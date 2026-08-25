// auto_stage3_driver_safe.c
#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <time.h>
#include "stage3_observer.h"

#ifndef STAGE3_DEFAULT_SECRET_COUNT
#define STAGE3_DEFAULT_SECRET_COUNT 4
#endif

#ifndef STAGE3_DEFAULT_ROUNDS
#define STAGE3_DEFAULT_ROUNDS 20
#endif

#ifndef STAGE3_DEFAULT_ATTACK_REPETITIONS
#define STAGE3_DEFAULT_ATTACK_REPETITIONS 1
#endif

#ifndef STAGE3_MODE_STR
#define STAGE3_MODE_STR "flush-reload"
#endif

/*
static void build_test_secrets(uint8_t *buf, int n)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    unsigned int seed = (unsigned int)(ts.tv_nsec ^ ts.tv_sec);

    for (int i = 0; i < n; i++) {
        uint8_t v;
        int unique;
        do {
            v = (uint8_t)(rand_r(&seed) & 0xFF);
            unique = 1;
            for (int j = 0; j < i; j++) {
                if (buf[j] == v) {
                    unique = 0;
                    break;
                }
            }
        } while (!unique);
        buf[i] = v;
    }
}
*/

int main(void)
{
    stage3_mode_t mode;
    if (stage3_parse_mode(STAGE3_MODE_STR, &mode) != 0) {
        fprintf(stderr, "Invalid STAGE3_MODE_STR: %s\n", STAGE3_MODE_STR);
        return 1;
    }

    stage3_config_t cfg;
    cfg.mode = mode;
    cfg.rounds = STAGE3_DEFAULT_ROUNDS;
    cfg.attack_repetitions = STAGE3_DEFAULT_ATTACK_REPETITIONS;
    cfg.candidate_count = 256;
    cfg.verbose = 0;

    uint8_t secrets[STAGE3_DEFAULT_SECRET_COUNT];
    //build_test_secrets(secrets, STAGE3_DEFAULT_SECRET_COUNT);
    //secrets = stage2_secrets_from_pipeline;

    for (int i = 0; i < STAGE3_DEFAULT_SECRET_COUNT; i++) {
        printf("STAGE3_INPUT_SECRET[%d]=%u\n", i, (unsigned)secrets[i]);
    }

    if (stage3_run_batch(&cfg, secrets, STAGE3_DEFAULT_SECRET_COUNT) != 0) {
        return 1;
    }

    return 0;
}