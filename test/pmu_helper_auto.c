// pmu_helper_auto.c
// 统一 PMU Helper：Stage1 (BR_MISP) + Stage2 (L1D miss)
#define _GNU_SOURCE
#include <linux/perf_event.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>

/* ----------------- 通用 perf_event_open 包装 ----------------- */

static int
perf_event_open_sys(struct perf_event_attr *hw_event, pid_t pid, int cpu,
                    int group_fd, unsigned long flags)
{
    return syscall(__NR_perf_event_open, hw_event, pid, cpu, group_fd, flags);
}

/* =============================================================
 * Stage 1: BR_MISP_RETIRED.CONDITIONAL 计数
 * ============================================================= */

static int fd_stage1 = -1;
static uint64_t stage1_before = 0;

#define MAX_STAGE1_SAMPLES  1024
static uint64_t stage1_deltas[MAX_STAGE1_SAMPLES];
static int      stage1_count = 0;

/*
 * BR_MISP_RETIRED.CONDITIONAL
 *   Event=0xC5, UMask=0x01 => config=0x01C5
 *
 * 注: 旧版 pmu_helper_auto.c 使用 0x0CC5，
 *     对应 BR_MISP_RETIRED.ALL_BRANCHES(UMask=0x0C)
 *     0x01C5 (CONDITIONAL) 更精确，推荐使用
 *     如果 0x01C5 在你的平台上不可用，可改回 0x0CC5
 */
#define RAW_BR_MISP_COND  0x01C5

static int setup_branch_miss_event(void)
{
    struct perf_event_attr pe;
    memset(&pe, 0, sizeof(struct perf_event_attr));

    pe.type   = PERF_TYPE_RAW;
    pe.size   = sizeof(struct perf_event_attr);
    pe.config = RAW_BR_MISP_COND;

    pe.disabled       = 0;
    pe.exclude_kernel = 1;
    pe.exclude_hv     = 1;

    int fd = perf_event_open_sys(&pe, 0, -1, -1, 0);
    if (fd == -1) {
        fprintf(stderr, "Error opening br_misp_retired.conditional (0x%x): %s\n",
                RAW_BR_MISP_COND, strerror(errno));
    }
    return fd;
}

/* Stage1 查询接口 */
int pmu_stage1_get_count(void)
{
    return stage1_count;
}

uint64_t pmu_stage1_get_delta(int i)
{
    return (i >= 0 && i < stage1_count) ? stage1_deltas[i] : 0;
}

/* Stage1: 被汇编在 STAGE1_BEGIN/END 调用 */
void pmu_stage1_before(void)
{
    (void)read(fd_stage1, &stage1_before, sizeof(stage1_before));
}

void pmu_stage1_after(void)
{
    uint64_t val = 0;
    read(fd_stage1, &val, sizeof(val));
    uint64_t delta = val - stage1_before;
    if (stage1_count < MAX_STAGE1_SAMPLES) {
        stage1_deltas[stage1_count++] = delta;
    }
}

/* =============================================================
 * Stage 2: L1D miss 计数（cache probe 用）
 * ============================================================= */

/*
 * MEM_LOAD_RETIRED.L1_MISS
 *   Event=0xD1, UMask=0x08 => config=0x08D1
 *
 * 被 auto_stage1_2_3_driver.c 中 probe_line_via_l1d_miss() 调用
 */
#define RAW_L1D_MISS  ((0x08ULL << 8) | 0xD1)

static int fd_l1d_miss = -1;

static int setup_l1d_miss_event(void)
{
    struct perf_event_attr pe;
    memset(&pe, 0, sizeof(pe));

    pe.type   = PERF_TYPE_RAW;
    pe.size   = sizeof(pe);
    pe.config = RAW_L1D_MISS;

    pe.disabled       = 0;
    pe.exclude_kernel = 1;
    pe.exclude_hv     = 1;

    int fd = perf_event_open_sys(&pe, 0, -1, -1, 0);
    if (fd == -1) {
        fprintf(stderr, "Error opening L1D miss event (0x%llx): %s\n",
                (unsigned long long)RAW_L1D_MISS, strerror(errno));
    }
    return fd;
}

/* 对外导出：读取当前 L1D miss 计数 */
uint64_t pmu_read_l1d_miss(void)
{
    if (fd_l1d_miss == -1) return 0;
    uint64_t val = 0;
    if (read(fd_l1d_miss, &val, sizeof(val)) != sizeof(val)) {
        return 0;
    }
    return val;
}

/* =============================================================
 * 初始化 / 清理
 * ============================================================= */

__attribute__((constructor))
static void pmu_init(void)
{
    fd_stage1   = setup_branch_miss_event();
    fd_l1d_miss = setup_l1d_miss_event();
}

__attribute__((destructor))
static void pmu_fini(void)
{
    if (fd_stage1   != -1) close(fd_stage1);
    if (fd_l1d_miss != -1) close(fd_l1d_miss);
}