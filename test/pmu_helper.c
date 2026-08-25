// pmu_helper.c
#define _GNU_SOURCE
#include <linux/perf_event.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>

static int fd_stage1 = -1;
static int fd_stage2 = -1;
static uint64_t stage1_before = 0;
static uint64_t stage2_before = 0;

#define MAX_STAGE1_SAMPLES  1024 

static uint64_t stage1_deltas[MAX_STAGE1_SAMPLES];
static int      stage1_count = 0;

// 对应 Cascade Lake 上的 BR_MISP_RETIRED.CONDITIONAL
#define RAW_BR_MISP_COND  0x0CC5

static int
perf_event_open(struct perf_event_attr *hw_event, pid_t pid, int cpu,
                int group_fd, unsigned long flags)
{
    return syscall(__NR_perf_event_open, hw_event, pid, cpu, group_fd, flags);
}

// 配置一个 PMU 事件，这里先用硬件 raw encoding 或者简单先用分支 miss
// 简化起见，先用 hardware event BRANCH_MISSES（generic event）
static int setup_branch_miss_event_allretire(void)
{
    struct perf_event_attr pe;
    memset(&pe, 0, sizeof(struct perf_event_attr));

    pe.type = PERF_TYPE_HARDWARE;
    pe.size = sizeof(struct perf_event_attr);
    pe.config = PERF_COUNT_HW_BRANCH_MISSES;  // generic branch misses
    pe.disabled = 0;      // 一打开就启用
    pe.exclude_kernel = 0;
    pe.exclude_hv     = 0;

    int fd = perf_event_open(&pe, 0, -1, -1, 0);
    if (fd == -1) {
        fprintf(stderr, "Error opening perf event: %s\n", strerror(errno));
    }
    return fd;
}

static int setup_branch_miss_event(void)
{
    struct perf_event_attr pe;
    memset(&pe, 0, sizeof(struct perf_event_attr));

    pe.type   = PERF_TYPE_RAW;
    pe.size   = sizeof(struct perf_event_attr);
    pe.config = RAW_BR_MISP_COND;       // 条件分支误预测

    pe.disabled       = 0;   // 一打开就启用
    pe.exclude_kernel = 1;   // 只测用户态，降噪
    pe.exclude_hv     = 1;

    int fd = perf_event_open(&pe, 0, -1, -1, 0);
    if (fd == -1) {
        fprintf(stderr, "Error opening br_misp_retired.conditional: %s\n",
                strerror(errno));
    }
    return fd;
}

int pmu_stage1_get_count(void) {
    return stage1_count;
}

uint64_t pmu_stage1_get_delta(int i) {
    return (i >= 0 && i < stage1_count) ? stage1_deltas[i] : 0;
}


// 在程序初始化时调用一次
__attribute__((constructor))
static void pmu_init(void)
{
    fd_stage1 = setup_branch_miss_event();
    fd_stage2 = setup_branch_miss_event();
}

// 在程序结束时关闭 fd
__attribute__((destructor))
static void pmu_fini(void)
{
    if (fd_stage1 != -1) close(fd_stage1);
    if (fd_stage2 != -1) close(fd_stage2);
}

// 汇编将调用这些函数（阶段1）
void pmu_stage1_before(void)
{
    /*
    if (fd_stage1 == -1) return;
    uint64_t val = 0;
    if (read(fd_stage1, &val, sizeof(val)) == sizeof(val)) {
        stage1_before = val;
    }
    */
    read(fd_stage1, &stage1_before, sizeof(stage1_before));
}

void pmu_stage1_after(void)
{
    /*
    if (fd_stage1 == -1) return;
    uint64_t val = 0;
    if (read(fd_stage1, &val, sizeof(val)) == sizeof(val)) {
        uint64_t delta = val - stage1_before;
        // 简化做法：先直接打印，后续框架可以解析 stdout
        printf("STAGE1_DELTA_BR_MISP_COND=%llu\n",
               (unsigned long long)delta);
        fflush(stdout);
    }
    */
    uint64_t val = 0;
    read(fd_stage1, &val, sizeof(val));
    uint64_t delta = val - stage1_before;
    stage1_deltas[stage1_count++] = delta;
    
}

// 同理对阶段2预留接口（暂时可以不调用，后续阶段2插桩时用）
void pmu_stage2_before(void)
{
    if (fd_stage2 == -1) return;
    uint64_t val = 0;
    if (read(fd_stage2, &val, sizeof(val)) == sizeof(val)) {
        stage2_before = val;
    }
}

void pmu_stage2_after(void)
{
    if (fd_stage2 == -1) return;
    uint64_t val = 0;
    if (read(fd_stage2, &val, sizeof(val)) == sizeof(val)) {
        uint64_t delta = val - stage2_before;
        printf("STAGE2_DELTA_BRANCH_MISSES=%llu\n",
               (unsigned long long)delta);
        fflush(stdout);
    }
}