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
 * Stage 1: selectable branch-misprediction events
 *
 * The assembly rewriter chooses one event-specific before/after pair.  There
 * is therefore no event-selection branch in the measured execution path.
 * ============================================================= */

static int fd_stage1 = -1;
static int fd_stage1_indirect = -1;
static int fd_stage1_disambiguation = -1;
static int fd_stage1_return = -1;
static uint64_t stage1_before = 0;
static uint64_t stage1_indirect_before = 0;
static uint64_t stage1_disambiguation_before = 0;
static uint64_t stage1_return_before = 0;

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
#define RAW_BR_MISP_INDIRECT  0xE489
#define RAW_MACHINE_CLEARS_DISAMBIGUATION  0x08C3
#define RAW_BR_MISP_RETIRED_RETURN  0xF7C5

/* Emitted only by preprocessing configured for the indirect event. */
extern const unsigned char pmu_stage1_event_indirect_selected
    __attribute__((weak));
extern const unsigned char pmu_stage1_event_disambiguation_selected
    __attribute__((weak));
extern const unsigned char pmu_stage1_event_return_selected
    __attribute__((weak));

static int setup_stage1_event(uint64_t raw_config, const char *event_name)
{
    struct perf_event_attr pe;
    memset(&pe, 0, sizeof(struct perf_event_attr));

    pe.type   = PERF_TYPE_RAW;
    pe.size   = sizeof(struct perf_event_attr);
    pe.config = raw_config;

    pe.disabled       = 0;
    pe.exclude_kernel = 1;
    pe.exclude_hv     = 1;

    int fd = perf_event_open_sys(&pe, 0, -1, -1, 0);
    if (fd == -1) {
        fprintf(stderr, "Error opening %s (0x%llx): %s\n",
                event_name, (unsigned long long)raw_config, strerror(errno));
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

/*
 * BR_MISP_EXEC.INDIRECT
 *   EventSel=0x89, UMask=0xE4 => config=0xE489
 *
 * These entry points are selected directly by the assembly rewriter.  They
 * contain no runtime dispatch on the configured event.
 */
void pmu_stage1_indirect_before(void)
{
    (void)read(fd_stage1_indirect, &stage1_indirect_before,
               sizeof(stage1_indirect_before));
}

void pmu_stage1_indirect_after(void)
{
    uint64_t val = 0;
    read(fd_stage1_indirect, &val, sizeof(val));
    if (stage1_count < MAX_STAGE1_SAMPLES) {
        stage1_deltas[stage1_count++] = val - stage1_indirect_before;
    }
}

/*
 * MACHINE_CLEARS.DISAMBIGUATION
 *   EventSel=0xC3, UMask=0x08 => config=0x08C3
 *
 * Used to count machine clears caused by memory-disambiguation failures.
 * Selection remains outside the measured execution path.
 */
void pmu_stage1_disambiguation_before(void)
{
    (void)read(fd_stage1_disambiguation, &stage1_disambiguation_before,
               sizeof(stage1_disambiguation_before));
}

void pmu_stage1_disambiguation_after(void)
{
    uint64_t val = 0;
    read(fd_stage1_disambiguation, &val, sizeof(val));
    if (stage1_count < MAX_STAGE1_SAMPLES) {
        stage1_deltas[stage1_count++] = val - stage1_disambiguation_before;
    }
}

/*
 * BR_MISP_RETIRED.RETURN
 *   EventSel=0xC5, UMask=0xF7 => config=0xF7C5
 *
 * Counts retired mispredicted return branches on supported processors.  The
 * rewriter calls this event-specific pair directly, without in-window event
 * dispatch.
 */
void pmu_stage1_return_before(void)
{
    (void)read(fd_stage1_return, &stage1_return_before,
               sizeof(stage1_return_before));
}

void pmu_stage1_return_after(void)
{
    uint64_t val = 0;
    read(fd_stage1_return, &val, sizeof(val));
    if (stage1_count < MAX_STAGE1_SAMPLES) {
        stage1_deltas[stage1_count++] = val - stage1_return_before;
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
    /* Selection happens once before main(), outside every measured window. */
    if (&pmu_stage1_event_return_selected != NULL) {
        fd_stage1_return = setup_stage1_event(
            RAW_BR_MISP_RETIRED_RETURN, "BR_MISP_RETIRED.RETURN");
    } else if (&pmu_stage1_event_disambiguation_selected != NULL) {
        fd_stage1_disambiguation = setup_stage1_event(
            RAW_MACHINE_CLEARS_DISAMBIGUATION,
            "MACHINE_CLEARS.DISAMBIGUATION");
    } else if (&pmu_stage1_event_indirect_selected != NULL) {
        fd_stage1_indirect = setup_stage1_event(
            RAW_BR_MISP_INDIRECT, "BR_MISP_EXEC.INDIRECT");
    } else {
        fd_stage1 = setup_stage1_event(
            RAW_BR_MISP_COND, "BR_MISP_RETIRED.CONDITIONAL");
    }
    fd_l1d_miss = setup_l1d_miss_event();
}

__attribute__((destructor))
static void pmu_fini(void)
{
    if (fd_stage1   != -1) close(fd_stage1);
    if (fd_stage1_indirect != -1) close(fd_stage1_indirect);
    if (fd_stage1_disambiguation != -1) close(fd_stage1_disambiguation);
    if (fd_stage1_return != -1) close(fd_stage1_return);
    if (fd_l1d_miss != -1) close(fd_l1d_miss);
}
