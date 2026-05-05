from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, FrozenSet, Optional, Sequence, Set, Tuple


@dataclass
class GuardConfig:
    """
    统一配置项：检测、沙箱、DLP、审计。

    设计为与具体 Agent 框架解耦；由 :class:`AgentGuard` 读取。
    """

    # --- Prompt / 文本侧 ---
    enable_prompt_pattern_injection: bool = True
    injection_confidence_threshold: float = 0.72
    """与 agent-security 默认 0.8 相比略低，使单条强特征即可触发（答辩演示更稳定）"""

    enable_instruction_boundary: bool = True
    """第二条注入防线：分隔符 / 伪造 system 块识别与可选清洗"""

    strip_boundary_markers_from_user_text: bool = False
    """True 时将从用户片段中弱化明显伪造的结构化指令块（偏防御，可能影响合法内容）"""

    block_instruction_boundary: bool = True
    """边界检测命中时是否直接拦截用户消息"""

    redact_input_pii: bool = True
    redact_output_pii: bool = True

    # --- 工具权限清单（比照治理层 allowlist）---
    enforce_tool_allowlist: bool = True
    allowed_tools: Optional[Set[str]] = None
    """None 表示不做名称级拦截（仍可被敏感工具Consent与沙箱约束）"""

    sensitive_tools: FrozenSet[str] = field(
        default_factory=lambda: frozenset(
            {
                "read_file",
                "write_file",
                "fetch_url",
                "http_request",
                "run_terminal",
                "shell",
                "clipboard_write",
                "clipboard_read",
            }
        )
    )

    # --- 策略沙箱 ---
    enable_path_sandbox: bool = True
    path_allow_prefixes: Tuple[str, ...] = ("/tmp/agent_safe/",)

    enable_network_sandbox: bool = True
    url_allowed_hosts: Tuple[str, ...] = ("127.0.0.1", "localhost")

    argument_keys_for_paths: Tuple[str, ...] = ("path", "file_path", "filepath", "dest", "destination")
    argument_keys_for_urls: Tuple[str, ...] = ("url", "uri", "endpoint", "href")

    # --- DLP ---
    enable_dlp_on_tool_args: bool = True
    dlp_block_when_pii_in_exfil_tools: bool = True
    """对标注为高外泄风险的工具参数若检出 PII 则阻断"""

    exfil_sensitive_tools: FrozenSet[str] = field(
        default_factory=lambda: frozenset(
            {
                "write_file",
                "http_request",
                "fetch_url",
                "clipboard_write",
            }
        )
    )

    # --- 审计 ---
    audit_log_path: Optional[str] = None
    """JSONL 路径；None 则仅内存"""

    include_raw_user_text_in_audit: bool = False
    """合规默认 False，避免把用户原文写入磁盘"""
