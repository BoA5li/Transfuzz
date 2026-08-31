#include "pmu_uops_rdpmc.h"

#include <inttypes.h>
#include <stdio.h>

int main(void)
{
    uint64_t issued = 0;
    uint64_t retired = 0;

    if (pmu_uops_preflight(&issued, &retired) != 0) {
        fprintf(stderr,
                "UOPS_PREFLIGHT_STATUS=ERROR code=%d detail=%s\n",
                pmu_uops_get_status_code(),
                pmu_uops_get_status_message());
        return 2;
    }

    printf("UOPS_PREFLIGHT_STATUS=OK mode=%s "
           "profile=intel_family6_model85 issued=%" PRIu64
           " retired=%" PRIu64 "\n",
           pmu_uops_get_mode(), issued, retired);
    return 0;
}
