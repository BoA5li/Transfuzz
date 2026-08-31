#ifndef PMU_UOPS_RDPMC_H
#define PMU_UOPS_RDPMC_H

#include <stdint.h>

/*
 * UOPS 瞬态窗口测量模块
 *
 * 支持两种读取模式：
 *   1. rdpmc（需要 /sys/.../rdpmc >= 2 或 root）
 *   2. read() syscall fallback（更慢；仍需 perf_event_open 权限）
 *
 * 当前 raw event profile 仅适用于 Intel family 6 model 85
 * (Skylake-SP/Cascade Lake)，其他 CPU 必须提供单独 profile。
 *
 * 使用方式：
 *   每轮循环开始前:  pmu_uops_snap_before();
 *   每轮循环结束后:  pmu_uops_snap_after();
 *   程序结束前:      pmu_uops_print_results();
 */

void pmu_uops_snap_before(void);
void pmu_uops_snap_after(void);
void pmu_uops_print_results(void);

/*
 * Validate that both configured raw UOPS events can be read.  A successful
 * read whose value is zero is valid and returns 0; errors return -1.
 */
int pmu_uops_preflight(uint64_t *issued_value, uint64_t *retired_value);
int pmu_uops_get_status_code(void);
const char *pmu_uops_get_status_message(void);
const char *pmu_uops_get_mode(void);

int      pmu_uops_get_count(void);
int32_t  pmu_uops_get_transient(int i);
uint32_t pmu_uops_get_issued_delta(int i);
uint32_t pmu_uops_get_retired_delta(int i);

#endif /* PMU_UOPS_RDPMC_H */
