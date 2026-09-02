#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

int pmu_l1d_miss_preflight(uint64_t *value, int *error_number);

int main(void)
{
    uint64_t value = 0;
    int error_number = 0;
    if (pmu_l1d_miss_preflight(&value, &error_number) != 0) {
        if (error_number == 0) error_number = EIO;
        fprintf(stderr,
                "L1D_PMU_PREFLIGHT_STATUS=ERROR code=%d detail=%s\n",
                error_number, strerror(error_number));
        return 2;
    }
    printf("L1D_PMU_PREFLIGHT_STATUS=OK value=%llu\n",
           (unsigned long long)value);
    return 0;
}
