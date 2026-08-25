/*
 * pmu_uops_rdpmc.c
 *
 * UOPS 瞬态窗口测量。
 * 优先使用 rdpmc，不可用时 fallback 到 read() syscall。
 *
 * 编译: gcc -c pmu_uops_rdpmc.c -o pmu_uops_rdpmc.o
 */

#define _GNU_SOURCE
#include "pmu_uops_rdpmc.h"

#include <linux/perf_event.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <signal.h>
#include <setjmp.h>

/* ---- perf_event_open 封装 ---- */

static int
perf_event_open_sys(struct perf_event_attr *hw_event, pid_t pid, int cpu,
                    int group_fd, unsigned long flags)
{
    return (int)syscall(__NR_perf_event_open, hw_event, pid, cpu, group_fd, flags);
}

/* ---- 配置 ---- */

/*
 * Intel Xeon Silver 4216 (Cascade Lake):
 *   UOPS_ISSUED.ANY:           Event=0x0E, UMask=0x01 => config=0x010E
 *   UOPS_RETIRED.RETIRE_SLOTS: Event=0xC2, UMask=0x02 => config=0x02C2
 */
#define RAW_UOPS_ISSUED   0x010EULL
#define RAW_UOPS_RETIRED  0x02C2ULL

/* ---- 状态 ---- */

static int fd_uops_issued  = -1;
static int fd_uops_retired = -1;

/* rdpmc 模式 */
static int      use_rdpmc       = 0;
static uint32_t pmc_idx_issued  = 0;
static uint32_t pmc_idx_retired = 0;

/* 快照值 */
static uint64_t snap_issued  = 0;
static uint64_t snap_retired = 0;

/* 数据存储 */
#define MAX_UOPS_SAMPLES 4096
static int32_t  transient_arr[MAX_UOPS_SAMPLES];
static uint32_t issued_delta_arr[MAX_UOPS_SAMPLES];
static uint32_t retired_delta_arr[MAX_UOPS_SAMPLES];
static int      uops_cnt = 0;

static int uops_available = 0;

/* ---- rdpmc 可用性探测 ---- */

static sigjmp_buf rdpmc_jmpbuf;
static volatile int rdpmc_faulted = 0;

static void rdpmc_sighandler(int sig)
{
    (void)sig;
    rdpmc_faulted = 1;
    siglongjmp(rdpmc_jmpbuf, 1);
}

static int test_rdpmc(uint32_t counter)
{
    /*
     * 尝试执行 rdpmc，如果 CR4.PCE 未设置会收到 SIGSEGV。
     * 用 signal handler + siglongjmp 捕获。
     */
    struct sigaction sa_new, sa_old;
    memset(&sa_new, 0, sizeof(sa_new));
    sa_new.sa_handler = rdpmc_sighandler;
    sa_new.sa_flags = 0;
    sigemptyset(&sa_new.sa_mask);

    if (sigaction(SIGSEGV, &sa_new, &sa_old) < 0) {
        return 0;
    }

    rdpmc_faulted = 0;
    if (sigsetjmp(rdpmc_jmpbuf, 1) == 0) {
        uint32_t lo, hi;
        __asm__ volatile("rdpmc" : "=a"(lo), "=d"(hi) : "c"(counter));
        (void)lo; (void)hi;
    }

    sigaction(SIGSEGV, &sa_old, NULL);
    return !rdpmc_faulted;
}

/* ---- 内部: 读取 PMC ---- */

static inline uint64_t read_pmc_rdpmc(uint32_t counter)
{
    uint32_t lo, hi;
    __asm__ volatile("rdpmc" : "=a"(lo), "=d"(hi) : "c"(counter));
    return ((uint64_t)hi << 32) | lo;
}

static inline uint64_t read_pmc_fd(int fd)
{
    uint64_t val = 0;
    if (read(fd, &val, sizeof(val)) != sizeof(val)) {
        return 0;
    }
    return val;
}

/* ---- 内部: 配置一个 PMC ---- */

static int setup_pmc(uint64_t raw_config)
{
    struct perf_event_attr pe;
    memset(&pe, 0, sizeof(pe));
    pe.type           = PERF_TYPE_RAW;
    pe.size           = sizeof(pe);
    pe.config         = raw_config;
    pe.disabled       = 0;
    pe.exclude_kernel = 1;
    pe.exclude_hv     = 1;

    int fd = perf_event_open_sys(&pe, 0, -1, -1, 0);
    if (fd < 0) {
        fprintf(stderr, "[pmu_uops] perf_event_open failed for config 0x%llx: %s\n",
                (unsigned long long)raw_config, strerror(errno));
    }
    return fd;
}

static int setup_and_try_mmap(int fd, uint32_t *out_pmc_idx)
{
    /*
     * 尝试 mmap 获取 PMC index。
     * 即使 mmap 成功，rdpmc 也可能不可用（需要 CR4.PCE）。
     */
    struct perf_event_mmap_page *pc =
        (struct perf_event_mmap_page *)mmap(NULL, 4096, PROT_READ,
                                            MAP_SHARED, fd, 0);
    if (pc == MAP_FAILED) {
        return 0;
    }

    if (pc->index == 0) {
        munmap((void *)pc, 4096);
        return 0;
    }

    *out_pmc_idx = pc->index - 1;
    /* 保持 mmap 存活 */
    return 1;
}

/* ---- 公开接口 ---- */

void pmu_uops_snap_before(void)
{
    if (!uops_available) return;

    if (use_rdpmc) {
        snap_issued  = read_pmc_rdpmc(pmc_idx_issued);
        snap_retired = read_pmc_rdpmc(pmc_idx_retired);
    } else {
        snap_issued  = read_pmc_fd(fd_uops_issued);
        snap_retired = read_pmc_fd(fd_uops_retired);
    }
}

void pmu_uops_snap_after(void)
{
    uint64_t now_issued, now_retired;

    if (!uops_available) return;

    if (use_rdpmc) {
        now_issued  = read_pmc_rdpmc(pmc_idx_issued);
        now_retired = read_pmc_rdpmc(pmc_idx_retired);
    } else {
        now_issued  = read_pmc_fd(fd_uops_issued);
        now_retired = read_pmc_fd(fd_uops_retired);
    }

    if (uops_cnt < MAX_UOPS_SAMPLES) {
        uint32_t d_i = (uint32_t)(now_issued  - snap_issued);
        uint32_t d_r = (uint32_t)(now_retired - snap_retired);
        int32_t  t   = (int32_t)d_i - (int32_t)d_r;

        transient_arr[uops_cnt]      = t;
        issued_delta_arr[uops_cnt]   = d_i;
        retired_delta_arr[uops_cnt]  = d_r;
        uops_cnt++;
    }
}

void pmu_uops_print_results(void)
{
    int i;
    for (i = 0; i < uops_cnt; i++) {
        printf("UOPS_TRANSIENT[%d]=%d\n",      i, transient_arr[i]);
        printf("UOPS_ISSUED_DELTA[%d]=%u\n",   i, issued_delta_arr[i]);
        printf("UOPS_RETIRED_DELTA[%d]=%u\n",  i, retired_delta_arr[i]);
    }
}

int pmu_uops_get_count(void)
{
    return uops_cnt;
}

int32_t pmu_uops_get_transient(int i)
{
    return (i >= 0 && i < uops_cnt) ? transient_arr[i] : 0;
}

uint32_t pmu_uops_get_issued_delta(int i)
{
    return (i >= 0 && i < uops_cnt) ? issued_delta_arr[i] : 0;
}

uint32_t pmu_uops_get_retired_delta(int i)
{
    return (i >= 0 && i < uops_cnt) ? retired_delta_arr[i] : 0;
}

/* ---- 自动初始化 / 清理 ---- */

__attribute__((constructor))
static void pmu_uops_auto_init(void)
{
    int mmap_ok_issued = 0, mmap_ok_retired = 0;

    fd_uops_issued  = setup_pmc(RAW_UOPS_ISSUED);
    fd_uops_retired = setup_pmc(RAW_UOPS_RETIRED);

    if (fd_uops_issued < 0 || fd_uops_retired < 0) {
        fprintf(stderr, "[pmu_uops] Cannot open UOPS events. "
                        "UOPS measurement disabled.\n");
        uops_available = 0;
        return;
    }

    /* 尝试 mmap + rdpmc */
    mmap_ok_issued  = setup_and_try_mmap(fd_uops_issued,  &pmc_idx_issued);
    mmap_ok_retired = setup_and_try_mmap(fd_uops_retired, &pmc_idx_retired);

    if (mmap_ok_issued && mmap_ok_retired) {
        /* mmap 成功，测试 rdpmc 指令是否可执行 */
        if (test_rdpmc(pmc_idx_issued)) {
            use_rdpmc = 1;
            fprintf(stderr, "[pmu_uops] Using rdpmc mode "
                            "(issued PMC=%u, retired PMC=%u)\n",
                    pmc_idx_issued, pmc_idx_retired);
        } else {
            use_rdpmc = 0;
            fprintf(stderr, "[pmu_uops] rdpmc not available (CR4.PCE not set), "
                            "using read() fallback.\n");
        }
    } else {
        use_rdpmc = 0;
        fprintf(stderr, "[pmu_uops] mmap failed, using read() fallback.\n");
    }

    uops_available = 1;
    fprintf(stderr, "[pmu_uops] Initialized (mode=%s)\n",
            use_rdpmc ? "rdpmc" : "read_syscall");
}

__attribute__((destructor))
static void pmu_uops_auto_fini(void)
{
    if (fd_uops_issued  >= 0) close(fd_uops_issued);
    if (fd_uops_retired >= 0) close(fd_uops_retired);
}