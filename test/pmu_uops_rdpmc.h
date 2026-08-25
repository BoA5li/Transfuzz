#ifndef PMU_UOPS_RDPMC_H
#define PMU_UOPS_RDPMC_H

#include <stdint.h>

/*
 * UOPS 瞬态窗口测量模块
 *
 * 支持两种读取模式：
 *   1. rdpmc（需要 /sys/.../rdpmc >= 2 或 root）
 *   2. read() syscall fallback（更慢但无权限要求）
 *
 * 使用方式：
 *   每轮循环开始前:  pmu_uops_snap_before();
 *   每轮循环结束后:  pmu_uops_snap_after();
 *   程序结束前:      pmu_uops_print_results();
 */

void pmu_uops_snap_before(void);
void pmu_uops_snap_after(void);
void pmu_uops_print_results(void);

int      pmu_uops_get_count(void);
int32_t  pmu_uops_get_transient(int i);
uint32_t pmu_uops_get_issued_delta(int i);
uint32_t pmu_uops_get_retired_delta(int i);

#endif /* PMU_UOPS_RDPMC_H */