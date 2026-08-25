// test_l1d_miss.c
#include <stdio.h>
#include <stdint.h>
#include <x86intrin.h>

extern uint64_t pmu_read_l1d_miss(void);

volatile uint8_t probe_array[256 * 512];

int main(void) {
    // 1. 清空 cache
    for (int i = 0; i < 256; i++) {
        _mm_clflush((void*)&probe_array[i * 512]);
    }
    _mm_mfence();

    // 2. 读取初始 L1D miss 计数
    uint64_t m0 = pmu_read_l1d_miss();
    printf("Initial L1D miss: %llu\n", (unsigned long long)m0);

    // 3. 访问一个 cache line（应该 miss）
    volatile uint8_t x = probe_array[42 * 512];
    (void)x;

    uint64_t m1 = pmu_read_l1d_miss();
    printf("After 1st access: %llu (delta=%llu)\n",
           (unsigned long long)m1, (unsigned long long)(m1 - m0));

    // 4. 再次访问同一个 cache line（应该 hit，delta=0）
    x = probe_array[42 * 512];
    (void)x;

    uint64_t m2 = pmu_read_l1d_miss();
    printf("After 2nd access: %llu (delta=%llu)\n",
           (unsigned long long)m2, (unsigned long long)(m2 - m1));

    return 0;
}