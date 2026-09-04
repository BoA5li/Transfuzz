#!/usr/bin/env python3
"""
stage3_config.py - 完整版（每参数 50% 独立变异 + 强制有效）

修订点（相对旧版）：
1. mutate_stage3_config():
   - 旧: 每轮只随机挑 1 个参数变异
   - 新: 每个参数独立以 PER_PARAM_MUTATE_PROB (默认 0.5) 概率被尝试变异
   - 新: 对每个被选中的参数, 只在"真正能改变当前值"的候选集中采样,
        从根本上避免空 diff
   - 新: 若一轮伯努利采样后无任何参数发生改变, 兜底强制挑 1 个
        能变的参数变异它, 保证调用者拿到的 new_cfg 与 current_config 不同
2. 严格约束:
   - choices 模式: 从 choices 中随机挑, 排除当前值
   - step_choices + range 模式: new = current + step, 再 clip 到 range,
     且排除 clip 后等于 current 的 step
3. 函数签名保持不变, 不影响 stage3_controller.py 的调用方式
"""

import os
import json
import random
import logging

logger = logging.getLogger("stage3_config")

# Detection-sample size is an experimental constant, not a mutation axis.
STAGE3_DETECTION_ROUNDS = 20
STAGE3_DETECTION_CANDIDATES = 256


# ====================================================================
# 可变异参数规格定义
# ====================================================================

STAGE3_PARAM_SPECS = {
    "cache_hit_threshold": {
        "env_var": "STAGE3_CACHE_HIT_THRESHOLD",
        "c_define": "STAGE3_CACHE_HIT_THRESHOLD",
        "default": 80,
        "range": [40, 200],
        "step_choices": [-20, -10, -5, 5, 10, 20, 40],
        "description": "cache hit 判定阈值 (CPU cycles)，不同 CPU 微架构差异大",
        "platform_notes": {
            "Intel_Skylake": "通常 60-100",
            "Intel_CoffeeLake": "通常 60-100",
            "AMD_Zen2": "通常 80-150",
            "AMD_Zen3": "通常 70-120",
            "Apple_M1": "通常 40-80",
        },
    },
    "attack_repetitions": {
        "env_var": "STAGE3_ATTACK_REPS",
        "default": 1,
        "choices": [1, 2, 3, 5, 10],
        "description": "每轮 flush 后攻击重复次数，增加可提高信号但可能引入噪声",
    },
    "noise_range_start": {
        "env_var": "STAGE3_NOISE_START",
        "default": 1,
        "choices": [0, 1, 2],
        "description": "噪声过滤起始候选值（排除 kernel/prefetch 干扰的低值区）",
    },
    "noise_range_end": {
        "env_var": "STAGE3_NOISE_END",
        "default": 16,
        "choices": [8, 16, 32, 48],
        "description": "噪声过滤结束候选值",
    },
    "use_poc_permutation": {
        "env_var": "STAGE3_USE_PERMUTATION",
        "default": 1,
        "choices": [0, 1],
        "description": "是否使用 PoC 风格乱序扫描（mix_i = (i*167+13)&255）",
    },
    "flush_wait_cycles": {
        "env_var": "STAGE3_FLUSH_WAIT",
        "default": 100,
        "choices": [0, 50, 100, 200, 500],
        "description": "flush 后到 attack 前的等待空转次数",
    },
    "reload_wait_cycles": {
        "env_var": "STAGE3_RELOAD_WAIT",
        "default": 100,
        "choices": [0, 50, 100, 200, 500],
        "description": "attack 后到 reload 前的等待空转次数",
    },
}


# ====================================================================
# 变异概率: 每个参数独立被尝试变异的概率
# ====================================================================
PER_PARAM_MUTATE_PROB = 0.5


# ====================================================================
# 内部工具: 针对单个参数, 返回一个"真正能改变当前值"的新值
# 如果该参数无法发生有效变异 (例如 choices 长度=1, 或 step 全部被 clip
# 回原值), 返回 None, 由上层决定是否跳过.
# ====================================================================

def _mutate_one_param(param_name, current_value):
    """
    针对单个参数, 在其规格约束下产生一个 != current_value 的新值.

    返回:
      new_value: 合法的新值 (与 current_value 不同)
      None:      该参数当前条件下无法产生有效变异
    """
    spec = STAGE3_PARAM_SPECS.get(param_name)
    if spec is None:
        return None

    # ----------------------------------------------------------------
    # 情形 A: 数值步长 + range
    # ----------------------------------------------------------------
    if "step_choices" in spec:
        rng = spec.get("range")
        candidate_new_values = []
        for step in spec["step_choices"]:
            v = current_value + step
            if rng is not None:
                v = max(rng[0], min(rng[1], v))
            if v != current_value:
                candidate_new_values.append(v)
        if not candidate_new_values:
            return None
        return random.choice(candidate_new_values)

    # ----------------------------------------------------------------
    # 情形 B: 枚举候选
    # ----------------------------------------------------------------
    if "choices" in spec:
        alt = [c for c in spec["choices"] if c != current_value]
        if not alt:
            return None
        return random.choice(alt)

    # ----------------------------------------------------------------
    # 情形 C: 无变异规则
    # ----------------------------------------------------------------
    return None


# ====================================================================
# 主变异函数: 每个参数独立 50% 概率被尝试变异
# ====================================================================

def mutate_stage3_config(current_config, per_param_prob=PER_PARAM_MUTATE_PROB):
    """
    变异 Stage 3 配置参数 (每参数独立采样模式).

    策略:
      1) 遍历 STAGE3_PARAM_SPECS 中每一个参数;
      2) 每个参数以 per_param_prob (默认 0.5) 的概率独立被"尝试变异";
      3) 被选中的参数, 调用 _mutate_one_param 生成一个 != 当前值 的新值
         (从候选 / 步长中采样, 严格遵守 range 上下限);
      4) 若该参数在当前值下无法发生有效变异, 跳过;
      5) 若整轮采样后没有任何参数发生改变 (例如所有伯努利都骰失败),
         兜底: 在"可变异参数集合"中随机挑 1 个强制变异一次,
         以保证返回值与 current_config 一定不同
         (这样 controller 的 _config_diff 不会把它判成无效变异).

    参数:
      current_config: dict, 当前配置
      per_param_prob: float, 每参数被尝试变异的概率 (默认 0.5)

    返回:
      dict, 变异后的新配置 (与 current_config 至少 1 个 key 不同;
            若所有参数都不存在有效替代值, 则原样返回)
    """
    mutated_config = dict(current_config)  # 浅拷贝, 值都是基本类型, 安全
    changed_keys = []

    # ---- 第一遍: 伯努利采样, 每个参数独立 50% 概率被尝试变异 ----
    for param_name, spec in STAGE3_PARAM_SPECS.items():
        if random.random() >= per_param_prob:
            continue

        current_value = mutated_config.get(param_name, spec["default"])
        new_value = _mutate_one_param(param_name, current_value)
        if new_value is None:
            # 该参数当前条件下不能有效变异, 跳过
            continue

        mutated_config[param_name] = new_value
        changed_keys.append((param_name, current_value, new_value))

    # ---- 兜底: 若没有任何参数改变, 强制挑 1 个能变的参数变异它 ----
    if not changed_keys:
        mutable_params = []
        for param_name, spec in STAGE3_PARAM_SPECS.items():
            current_value = mutated_config.get(param_name, spec["default"])
            # 探测一次, 仅用于判断"能否变异"
            probe = _mutate_one_param(param_name, current_value)
            if probe is not None:
                mutable_params.append((param_name, current_value, probe))

        if mutable_params:
            pname, old_v, new_v = random.choice(mutable_params)
            mutated_config[pname] = new_v
            changed_keys.append((pname, old_v, new_v))
            logger.debug(
                "Config mutation fallback: forced mutate {} "
                "{} -> {}".format(pname, old_v, new_v))
        else:
            logger.debug(
                "Config mutation: no parameter is mutable in current "
                "config (returning identical)")

    # ---- 日志 ----
    if changed_keys:
        diff_str = ", ".join(
            "{}:{}->{}".format(k, ov, nv) for k, ov, nv in changed_keys)
        logger.info(
            "Config mutation: {} param(s) changed [{}]".format(
                len(changed_keys), diff_str))

    return mutated_config


# ====================================================================
# 配置 I/O / 默认值 / 环境变量 / 打印 (保持原行为)
# ====================================================================

def save_stage3_config(config, path):
    """保存 Stage 3 配置到 JSON 文件。"""
    os.makedirs(
        os.path.dirname(path) if os.path.dirname(path) else ".",
        exist_ok=True)
    persisted_config = {
        key: value for key, value in config.items()
        if key in STAGE3_PARAM_SPECS
    }
    with open(path, 'w') as f:
        json.dump(persisted_config, f, indent=2)
    logger.debug("Saved Stage 3 config to {}".format(path))


def load_stage3_config(config_path):
    """从文件加载 Stage 3 配置。"""
    if not os.path.exists(config_path):
        logger.warning(
            "Config file not found: {}, using defaults".format(config_path))
        return get_stage3_defaults()
    with open(config_path, 'r') as f:
        loaded_config = json.load(f)
    # Drop retired/unknown keys (notably the formerly mutable ``rounds``)
    # so old work directories cannot reintroduce an experimental variable.
    config = get_stage3_defaults()
    config.update({
        key: value for key, value in loaded_config.items()
        if key in STAGE3_PARAM_SPECS
    })
    logger.info("Loaded Stage 3 config from {}".format(config_path))
    return config


def get_stage3_defaults():
    """获取 Stage 3 默认配置"""
    return {key: spec["default"] for key, spec in STAGE3_PARAM_SPECS.items()}


def generate_stage3_env(config):
    """将 Stage 3 配置转换为环境变量字典。"""
    env = {
        "STAGE3_ROUNDS": str(STAGE3_DETECTION_ROUNDS),
        "STAGE3_CANDIDATE_COUNT": str(STAGE3_DETECTION_CANDIDATES),
    }
    for key, spec in STAGE3_PARAM_SPECS.items():
        env_var = spec.get("env_var")
        if env_var and key in config:
            env[env_var] = str(config[key])
    return env


def print_stage3_config(config):
    """打印 Stage 3 配置（用于调试）"""
    print("=" * 60)
    print("Stage 3 Configuration:")
    print("=" * 60)
    for key, value in config.items():
        spec = STAGE3_PARAM_SPECS.get(key, {})
        desc = spec.get("description", "")
        print("  {}: {}".format(key, value))
        if desc:
            print("    ({})".format(desc))
    print("=" * 60)
