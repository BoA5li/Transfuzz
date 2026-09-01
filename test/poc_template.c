/* ============================================================
 *  Transient Execution PoC — Framework Adaptation Template
 *  适配三阶段验证框架（Stage1 误预测 / Stage2 瞬态访问 / Stage3 F+R）
 * ============================================================ */

/* ------------------------------------------------------------
 *  [必需 1] 瞬态区标记宏 —— 名称固定
 *    框架靠这两个汇编注释定位"瞬态指令"，用于 Stage2 评分。
 * ------------------------------------------------------------ */
#define NOP_REGION_BEGIN  asm volatile("# NOP_REGION_BEGIN");
#define NOP_REGION_END    asm volatile("# NOP_REGION_END");

/* ------------------------------------------------------------
 *  [必需 2] 探针步长 probe_stride
 *    - 必须为 volatile size_t 全局变量
 *    - 取值任意（典型 256/512/1024/4096），框架自适应
 *    - Stage3 的 F+R 模块按此步长定位 256 个候选缓存行
 * ------------------------------------------------------------ */
volatile size_t probe_stride = /* 任意值 */;

/* ------------------------------------------------------------
 *  [必需 3] 探针数组 array2
 *    - 用于把 secret 编码到缓存行
 * ------------------------------------------------------------ */
uint8_t array2[candidate_count * PROBE_STRIDE_MAX];

/* ------------------------------------------------------------
 *  [必需 4] secret —— 必须是"单字节"可读取目标
 *    - 推荐字符串字面量形式，避免分析器误识别
 *    - 框架 Stage3  1 字节
 * ------------------------------------------------------------ */
char *secret = /* 单字节字面量，如 "Y" */;

/* ------------------------------------------------------------
 *  [必需 5] 框架 PMU 接口（由框架链接器提供实现，PoC 仅声明）
 *    - Stage1 评分：BR_MISP_RETIRED.* 等误预测事件
 *    - Stage2 评分：UOPS_ISSUED.ANY 等瞬态微操作事件
 * ------------------------------------------------------------ */
extern int      pmu_stage1_get_count(void);
extern uint64_t pmu_stage1_get_delta(int i);
extern int      pmu_stage2_get_count(void);
extern uint64_t pmu_stage2_get_delta(int i);
extern void     pmu_uops_snap_before(void);
extern void     pmu_uops_snap_after(void);
extern void     pmu_uops_print_results(void);
extern int      pmu_uops_get_count(void);
extern int32_t  pmu_uops_get_transient(int i);

/* Runtime phase contract; include this header in concrete inputs. */
#include "stage1_phase.h"

/*
 * Before EVERY call that produces one PMU sample, mark the semantic role
 * derived from the same runtime predicate/mask that selects the call input:
 *
 *   pmu_stage1_set_phase(is_detection
 *       ? PMU_STAGE1_PHASE_DETECT : PMU_STAGE1_PHASE_TRAIN);
 *   victim_function(selected_input);
 *
 * Do not infer the role from a variable name or a fixed loop period.  Keep
 * this marker outside STAGE1_BEGIN/END.  Zero training calls are representable
 * but cannot establish a within-run training baseline, so evaluation fails
 * closed with empty_group rather than inventing one.
 */

/* ------------------------------------------------------------
 *  [必需 6] Victim / Gadget 函数 —— PMU 插桩位置
 *
 *  插桩规则（强制）：
 *    ┌──────────────────────────────────────────────────┐
 *    │ pmu_uops_snap_before();                          │ ← UOPS 起点
 *    │ asm volatile(".globl STAGE1_BEGIN\n"             │
 *    │              "STAGE1_BEGIN:");                   │ ← Stage1 起点
 *    │ <触发瞬态执行的代码，如越界分支判断>             │
 *    │     NOP_REGION_BEGIN                             │ ← 瞬态区起点
 *    │     <瞬态指令：访问 secret 并编码到 array2>      │
 *    │     NOP_REGION_END                               │ ← 瞬态区终点
 *    │ asm volatile(".globl STAGE1_END\n"               │
 *    │              "STAGE1_END:");                     │ ← Stage1 终点
 *    │ pmu_uops_snap_after();                           │ ← UOPS 终点
 *    └──────────────────────────────────────────────────┘
 *
 *  说明：
 *    - STAGE1_BEGIN/END：框架在此区间统计 Stage1 PMU 事件
 *    - NOP_REGION_BEGIN/END：框架识别瞬态指令边界，用于 Stage2 评分
 *    - snap_before/after：框架统计瞬态窗口内 UOPS 数量
 *    - 函数必须加 __attribute__((noinline))，防止内联破坏标签位置
 * ------------------------------------------------------------ */
__attribute__((noinline))
void <victim_function_name>(...) {
    pmu_uops_snap_before();
    asm volatile(".globl STAGE1_BEGIN\nSTAGE1_BEGIN:");

    /* —— 攻击逻辑由测试人员自行实现 —— */
    /*     例如：边界检查 + 越界访问 / 类型混淆 / 间接跳转等 */
    {
        NOP_REGION_BEGIN
        /* 瞬态指令体：必须包含对 secret 的访问 + array2 编码 */
        NOP_REGION_END
    }

    asm volatile(".globl STAGE1_END\nSTAGE1_END:");
    pmu_uops_snap_after();
}

/* ------------------------------------------------------------
 *  [必需 7] 框架 API —— 名称/签名严格匹配
 * ------------------------------------------------------------ */

/* [API-1] 给定 secret 字节值 s，返回 array2 中对应的探测地址
 *         框架 Stage3 用此函数枚举 256 个候选地址做 F+R */
volatile uint8_t *vf_get_probe_addr_for_secret(uint8_t s) {
    return &array2[(size_t)s * probe_stride];
}

/* [API-2] 预填 candidate_count 个候选探针缓存行
 *         目的：把 array2 所有候选行写脏，避免 COW 零页干扰 */
void vf_prepare_probe_region(int candidate_count) {
    /* 写脏 candidate_count 个探针位置 */
}

/* [API-3] 执行一次完整攻击（mistrain + trigger，或等效流程）
 *         框架在 Stage1/2/3 调用此函数触发瞬态执行 */
void vf_run_attack_once(void) {
    /* 调用 victim_function 完成一次端到端攻击 */
}

/* ------------------------------------------------------------
 *  [必需 8] main —— 独立运行时入口
 *    - 用 #ifndef STAGE2_TEST_MAIN 包裹，允许框架替换
 *    - 必须打印 STAGE1_DELTA_BR_MISP_COND[i]=...（Stage1 评分输入）
 *    - 必须调用 pmu_uops_print_results()（Stage2 评分输入）
 * ------------------------------------------------------------ */
#ifndef STAGE2_TEST_MAIN
int main(int argc, const char **argv) {
    /* 初始化 array2 写脏（避免 COW） */

    /* 触发一次或多次攻击 */

    /* 打印 Stage1 PMU 增量 */
    {
        int n = pmu_stage1_get_count();
        for (int i = 0; i < n; i++) {
            printf("STAGE1_DELTA_BR_MISP_COND[%d]=%llu\n",
                   i, (unsigned long long)pmu_stage1_get_delta(i));
        }
    }

    /* 打印 Stage2 UOPS 测量 */
    pmu_uops_print_results();

    return 0;
}
#endif
