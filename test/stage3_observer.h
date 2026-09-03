// stage3_observer.h
#ifndef STAGE3_OBSERVER_H
#define STAGE3_OBSERVER_H

#include <stdint.h>

/* Fixed per-candidate Stage 3 observation budget. */
#define STAGE3_DETECTION_ROUNDS 20

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    STAGE3_MODE_NONE = 0,
    STAGE3_MODE_FLUSH_RELOAD = 1,
    STAGE3_MODE_PRIME_PROBE = 2,
    STAGE3_MODE_CUSTOM = 100
} stage3_mode_t;

typedef struct {
    stage3_mode_t mode;
    int rounds;              // 兼容字段；observer 强制使用 STAGE3_DETECTION_ROUNDS
    int attack_repetitions;  // 每轮前触发多少次 vf_run_attack_once()
    int candidate_count;     // 默认 256
    int verbose;
    int noise_range_start;   // 需要排除的噪声项起始索引
    int noise_range_end;     // 需要排除的噪声项结束索引

    // Stage3 不持有 secret，而是外部传入
    const uint8_t *secrets;
    int secret_count;
} stage3_config_t;

typedef struct {
    int expected_secret;  // 建议使用 int，便于使用 -1 表示无效
    int top1_value;
    int top2_value;
    int top1_score;       // 阈值命中累计次数
    int top2_score;       // 阈值命中累计次数
    int match;            // top1==expected 或 top2==expected
} stage3_result_t;

/* victim PoC 侧最小接口 */
void vf_run_attack_once(void);
volatile uint8_t *vf_get_probe_addr_for_secret(uint8_t s);
void vf_prepare_probe_region(int candidate_count);

/* observer 统一接口 */
const char *stage3_mode_to_string(stage3_mode_t mode);
int stage3_parse_mode(const char *s, stage3_mode_t *out_mode);

/* 执行单个 secret 的 Stage3 验证 */
int stage3_run_single_reuse_secret(const stage3_config_t *cfg,
                                   uint8_t secret,
                                   stage3_result_t *out_result);

/* 执行一组 secret 的 Stage3 验证 */
int stage3_run_batch(const stage3_config_t *cfg,
                     const uint8_t *secrets,
                     int secret_count,
                     stage3_result_t *results);

#ifdef __cplusplus
}
#endif

#endif
