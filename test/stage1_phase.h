#ifndef STAGE1_PHASE_H
#define STAGE1_PHASE_H

/*
 * Runtime sample-classification contract.
 *
 * Call exactly one marker immediately before every invocation that produces
 * one Stage 1 PMU sample.  The call must remain outside STAGE1_BEGIN/END.
 * Loop counts and selection logic may vary at runtime; no period is assumed.
 */
enum pmu_stage1_phase {
    PMU_STAGE1_PHASE_TRAIN = 1,
    PMU_STAGE1_PHASE_DETECT = 2,
};

void pmu_stage1_set_phase(int phase);

#define STAGE1_MARK_TRAIN() \
    pmu_stage1_set_phase(PMU_STAGE1_PHASE_TRAIN)
#define STAGE1_MARK_DETECT() \
    pmu_stage1_set_phase(PMU_STAGE1_PHASE_DETECT)

#endif
