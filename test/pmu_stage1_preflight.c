#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#if defined(STAGE1_PMU_EVENT_INDIRECT)
const unsigned char pmu_stage1_event_indirect_selected = 1;
#elif defined(STAGE1_PMU_EVENT_DISAMBIGUATION)
const unsigned char pmu_stage1_event_disambiguation_selected = 1;
#elif defined(STAGE1_PMU_EVENT_RETURN)
const unsigned char pmu_stage1_event_return_selected = 1;
#endif

extern int pmu_stage1_preflight(uint64_t *value, int *error_number);

int main(void)
{
    uint64_t value = 0;
    int error_number = 0;

    if (pmu_stage1_preflight(&value, &error_number) != 0) {
        fprintf(stderr,
                "STAGE1_PMU_PREFLIGHT_STATUS=ERROR code=%d detail=%s\n",
                error_number, strerror(error_number));
        return 2;
    }
    printf("STAGE1_PMU_PREFLIGHT_STATUS=OK value=%llu\n",
           (unsigned long long)value);
    return 0;
}
