// auto_stage1_2_3_driver.c
#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <time.h>
#include <stdlib.h>
#include <string.h>
#include <x86intrin.h>
#include "stage3_observer.h"

void stage3_init_runtime_params_from_env(void);

// Victim PoC 接口
void vf_run_attack_once(void);
volatile uint8_t *vf_get_probe_addr_for_secret(uint8_t s);
void vf_prepare_probe_region(int candidate_count);

// pmu_helper 接口
int pmu_read_l1d_miss_checked(uint64_t *value, int *error_number);

static inline void flush_line(volatile uint8_t *addr) {
    _mm_clflush((void *)addr);
    _mm_mfence();
}

static int probe_line_via_l1d_miss(volatile uint8_t *addr) {
    int error_number = 0;
    _mm_lfence();
    uint64_t m0 = 0;
    if (pmu_read_l1d_miss_checked(&m0, &error_number) != 0) return -1;
    _mm_lfence();
    (void)*addr;
    _mm_lfence();
    uint64_t m1 = 0;
    if (pmu_read_l1d_miss_checked(&m1, &error_number) != 0) return -1;
    _mm_lfence();
    uint64_t delta = m1 - m0;
    return (delta == 0);  // 1 = hit, 0 = miss
}

static int stage3_enabled = 0;
static stage3_config_t g_stage3_cfg;


/* ✅ 新增：全局变量保存秘密值（从环境变量读取） */
static uint8_t g_expected_secret = 0;

/* ✅ 新增：从环境变量读取秘密值 */
static void init_expected_secret_from_env(void)
{
    const char *secret_env = getenv("VF_EXPECTED_SECRET");
    if (secret_env && secret_env[0] != '\0') {
        // 支持两种格式：
        // 1. 单字符：VF_EXPECTED_SECRET='Y'
        // 2. 数字：VF_EXPECTED_SECRET=89
        if (strlen(secret_env) == 1) {
            g_expected_secret = (uint8_t)secret_env[0];
        } else {
            g_expected_secret = (uint8_t)atoi(secret_env);
        }
    } else {
        // 默认值：'Y'
        g_expected_secret = (uint8_t)'Y';
    }
    
    fprintf(stderr, "Driver: Expected secret = 0x%02x ('%c')\n", 
            g_expected_secret, 
            (g_expected_secret >= 32 && g_expected_secret < 127) ? g_expected_secret : '?');
}

// 辅助宏：读取 int 型环境变量，失败时使用默认值
#define GET_ENV_INT(name, def) ({ \
    const char *_s = getenv(name); \
    int _v = (_s && _s[0]) ? atoi(_s) : (def); \
    _v; \
})


static void init_stage3_from_env(void)
{
    const char *enable = getenv("ENABLE_STAGE3");
    if (!enable || strcmp(enable, "1") != 0) {
        fprintf(stderr, "[driver] Stage3 DISABLED (ENABLE_STAGE3=%s)\n",
            enable ? enable : "(unset)");
        stage3_enabled = 0;
        return;
    }

    const char *mode_s = getenv("STAGE3_MODE");
    if (!mode_s) mode_s = "flush-reload";

    stage3_mode_t mode;
    if (stage3_parse_mode(mode_s, &mode) != 0) {
        fprintf(stderr, "Invalid STAGE3_MODE=%s\n", mode_s);
        stage3_enabled = 0;
        return;
    }

    g_stage3_cfg.mode = mode;
    // ✅ 关键修订：所有配置参数从 env 读取，缺省时回退到默认值
    g_stage3_cfg.rounds              = GET_ENV_INT("STAGE3_ROUNDS",          30);
    g_stage3_cfg.attack_repetitions  = GET_ENV_INT("STAGE3_ATTACK_REPS",      1);
    g_stage3_cfg.candidate_count     = GET_ENV_INT("STAGE3_CANDIDATE_COUNT", 256);
    g_stage3_cfg.noise_range_start   = GET_ENV_INT("STAGE3_NOISE_START",      1);
    g_stage3_cfg.noise_range_end     = GET_ENV_INT("STAGE3_NOISE_END",       16);
    g_stage3_cfg.verbose             = GET_ENV_INT("STAGE3_VERBOSE",          0);

    stage3_enabled = 1;
    fprintf(stderr,
        "[driver] Stage3 ENABLED, mode=%s, rounds=%d, reps=%d, "
        "candidates=%d, noise=[%d,%d]\n",
        mode_s,
        g_stage3_cfg.rounds, g_stage3_cfg.attack_repetitions,
        g_stage3_cfg.candidate_count,
        g_stage3_cfg.noise_range_start, g_stage3_cfg.noise_range_end);
    stage3_init_runtime_params_from_env();
}

static void print_stage3_round_result(int round_idx, const stage3_result_t *r)
{
    printf("STAGE3_ROUND%d_EXPECTED=%u\n", round_idx, (unsigned)r->expected_secret);
    printf("STAGE3_ROUND%d_TOP1=%u\n", round_idx, (unsigned)r->top1_value);
    printf("STAGE3_ROUND%d_TOP2=%u\n", round_idx, (unsigned)r->top2_value);
    printf("STAGE3_ROUND%d_TOP1_SCORE=%d\n", round_idx, r->top1_score);
    printf("STAGE3_ROUND%d_TOP2_SCORE=%d\n", round_idx, r->top2_score);
    printf("STAGE3_ROUND%d_MATCH=%d\n", round_idx, r->match);
}

static void maybe_run_stage3_after_stage2_round(int round_idx, uint8_t expected_secret)
{
    if (!stage3_enabled) return;

    stage3_result_t r;
    if (stage3_run_single_reuse_secret(&g_stage3_cfg, expected_secret, &r) != 0) {
        fprintf(stderr, "Stage3 failed for round %d\n", round_idx);
        return;
    }
    print_stage3_round_result(round_idx, &r);
}

static inline void stage2_probe_wait(void)
{
    for (volatile int z = 0; z < 100; z++) {}
}

static int stage2_target_trial(volatile uint8_t *probe_target)
{
    flush_line(probe_target);
    stage2_probe_wait();
    vf_run_attack_once();
    stage2_probe_wait();
    return probe_line_via_l1d_miss(probe_target);
}

static int stage2_control_trial(volatile uint8_t *probe_target)
{
    flush_line(probe_target);
    stage2_probe_wait();
    /* Match the second fixed wait without invoking the victim. */
    stage2_probe_wait();
    return probe_line_via_l1d_miss(probe_target);
}

/**
 * 在 secret = s 的条件下，对 target_s 做多次试验
 */
static int stage2_round_dual(uint8_t secret,
                              uint8_t target_s,
                              int trials,
                              int *out_hits_target,  int *out_total_target,
                              int *out_hits_control, int *out_total_control)
{  
    (void)secret;

    volatile uint8_t *probe_target  = vf_get_probe_addr_for_secret(target_s);

    int hits_t = 0, total_t = 0;
    int hits_c = 0, total_c = 0;

    /*
     * Keep trials in one process to avoid startup/page-fault/PMU-open noise,
     * but collect target and control as adjacent pairs.  Alternate pair order
     * so slow temporal drift cannot systematically favor the first group.
     * This is a steady-state repeated measurement, not a claim that predictor,
     * TLB, or prefetcher state is independently reset between samples.
     */
    for (int i = 0; i < trials; i++) {
        int hit_t;
        int hit_c;
        if ((i & 1) == 0) {
            hit_t = stage2_target_trial(probe_target);
            if (hit_t < 0) return -1;
            hit_c = stage2_control_trial(probe_target);
            if (hit_c < 0) return -1;
        } else {
            hit_c = stage2_control_trial(probe_target);
            if (hit_c < 0) return -1;
            hit_t = stage2_target_trial(probe_target);
            if (hit_t < 0) return -1;
        }

        total_t++;
        hits_t += hit_t;
        total_c++;
        hits_c += hit_c;
    }

    *out_hits_target   = hits_t;
    *out_total_target  = total_t;
    *out_hits_control  = hits_c;
    *out_total_control = total_c;
    return 0;
}

int main(int argc, char **argv)
{
    (void)argc; (void)argv;

    init_expected_secret_from_env();
    init_stage3_from_env();

    int trials = 1000;

    uint8_t s0 = g_expected_secret;
    int hits_t0, tot_t0, hits_c0, tot_c0;
    if (stage2_round_dual(s0, s0, trials,
                          &hits_t0, &tot_t0,
                          &hits_c0, &tot_c0) != 0) {
        printf("STAGE2_PMU_STATUS=ERROR detail=l1d_miss_read_failed\n");
        return 2;
    }
    printf("STAGE2_PMU_STATUS=OK event=MEM_LOAD_RETIRED.L1_MISS\n");
    printf("STAGE2_TRIAL_SCHEDULE=PAIRED_ALTERNATING trials_per_group=%d\n",
           trials);

    // 直接复用 Stage2 刚刚设置过的 secret=s0
    maybe_run_stage3_after_stage2_round(0, s0);

    printf("STAGE2_ROUND0_SECRET=%u\n", (unsigned)s0);
    printf("STAGE2_ROUND0_TARGET_VALUE=%u\n", (unsigned)s0);
    printf("STAGE2_ROUND0_TARGET_HITS=%d\n", hits_t0);
    printf("STAGE2_ROUND0_TARGET_TOTAL=%d\n", tot_t0);

    /* 这里 control 的语义仍然是“同一 target line 在无攻击条件下的背景命中率” */
    printf("STAGE2_ROUND0_CONTROL_VALUE=%u\n", (unsigned)s0);
    printf("STAGE2_ROUND0_CONTROL_HITS=%d\n", hits_c0);
    printf("STAGE2_ROUND0_CONTROL_TOTAL=%d\n", tot_c0);

    double r0_t = (tot_t0 > 0) ? (double)hits_t0 / tot_t0 : 0.0;
    double r0_c = (tot_c0 > 0) ? (double)hits_c0 / tot_c0 : 0.0;

    printf("Round0: secret=%u, target=%u, control=%u, "
           "target_rate=%.3f, control_rate=%.3f\n",
           (unsigned)s0, (unsigned)s0, (unsigned)s0, r0_t, r0_c);

    return 0;
}
