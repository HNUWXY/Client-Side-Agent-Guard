from typing import Sequence

from .models import Rule


_EN_RULES: tuple[Rule, ...] = (
    Rule(
        "instruction_override",
        "instruction_override",
        r"(ignore|disregard|forget|override)\s+(all\s+)?previous\s+instructions?",
        0.36,
    ),
    Rule(
        "system_prompt_extraction",
        "system_prompt_extraction",
        r"(show|reveal|print|display|repeat)\s+(the\s+)?(system\s+prompt|hidden\s+instructions?)",
        0.34,
    ),
    Rule(
        "role_hijack",
        "role_hijack",
        r"(you\s+are\s+now|act\s+as|pretend\s+to\s+be|roleplay\s+as)",
        0.30,
    ),
    Rule(
        "delimiter_injection",
        "delimiter_injection",
        r"(```\s*system|\[system\]|<\|im_start\|>system|<system>)",
        0.28,
    ),
    Rule(
        "policy_bypass",
        "policy_bypass",
        r"(bypass|circumvent)\s+(safety|content|policy|guardrails?)",
        0.30,
    ),
    Rule(
        "data_exfiltration",
        "data_exfiltration",
        r"(dump|export|leak)\s+(all\s+)?(memory|context|secrets?|credentials?)",
        0.33,
    ),
)

# 中文提示注入常见表述（与英文规则并列，权重同级略保守以降低误报）
_ZH_RULES: tuple[Rule, ...] = (
    Rule(
        "instruction_override_zh",
        "instruction_override",
        r"(忽略|无视|忘掉|忘记)(.{0,14})?(上述|上面|前面|先前|之前|上文)(的)?(指令|规则|要求|设定)",
        0.34,
    ),
    Rule(
        "instruction_override_zh2",
        "instruction_override",
        r"(覆盖|取代)(.{0,10})?(系统|原先|默认)?(指令|规则|设定)",
        0.30,
    ),
    Rule(
        "system_prompt_extraction_zh",
        "system_prompt_extraction",
        r"(输出|显示|打印|重复|泄露)(.{0,10})(系统|开发者|隐藏)(提示词|提示|指令|消息)",
        0.33,
    ),
    Rule(
        "system_prompt_extraction_zh2",
        "system_prompt_extraction",
        r"(说出|告诉我|给我)(.{0,8})(完整)?(的)?(系统|开发者)(提示词|提示|指令)",
        0.32,
    ),
    Rule(
        "role_hijack_zh",
        "role_hijack",
        r"(你现在|接下来你)(是|要|请)?(扮演|作为|身份是)(.{0,16})?(不受限|无限制|无道德|无审查|越狱|开发者模式)",
        0.32,
    ),
    Rule(
        "role_hijack_zh2",
        "role_hijack",
        r"(进入|开启|切换)(到)?(越狱|开发者|无限制|无审查)(模式)?",
        0.31,
    ),
    Rule(
        "delimiter_injection_zh",
        "delimiter_injection",
        r"(【\s*系统\s*】|「系统」|＜\s*系统\s*＞|【\s*开发者\s*】|\[系统\])",
        0.27,
    ),
    # 伪造系统/开发者抬头 + 明确绕过安全语境（单独 delimiter_zh + policy_bypass_zh2 往往仅到 alert）
    Rule(
        "fake_system_unrestricted_zh",
        "delimiter_injection",
        r"(【\s*系统\s*】|「系统」|＜\s*系统\s*＞|【\s*开发者\s*】).{0,48}?"
        r"(不受任何安全限制|不受.{0,10}安全.{0,8}限制|无任何安全限制|完全不受审查|"
        r"解除.{0,8}(安全|审查|限制)|无视.{0,8}(安全|审查|限制))",
        0.40,
    ),
    Rule(
        "fenced_system_instruction_zh",
        "delimiter_injection",
        r"```\s*system[\s\S]{0,400}?(新的系统指令|系统指令\s*[:：]|删除所有日志|删除所有|清空日志)",
        0.40,
    ),
    Rule(
        "policy_bypass_zh",
        "policy_bypass",
        r"(绕过|无视|解除|关闭|取消)(.{0,10})?(安全|审核|策略|内容审查|限制|约束|护栏)",
        0.30,
    ),
    Rule(
        "policy_bypass_zh2",
        "policy_bypass",
        r"(不受.{0,8}限制|无道德约束|无视审查|没有审查|进入无审查)",
        0.26,
    ),
    Rule(
        "data_exfiltration_zh",
        "data_exfiltration",
        r"(导出|泄露|外传|发送)(.{0,10})?(全部|完整)?(记忆|对话|上下文|密钥|凭据|令牌|密码)",
        0.32,
    ),
)

DEFAULT_RULES: Sequence[Rule] = _EN_RULES + _ZH_RULES
