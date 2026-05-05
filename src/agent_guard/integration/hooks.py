from __future__ import annotations

import copy
import functools
import inspect
from typing import Any, Callable, Dict, TypeVar

from ..core.exceptions import GuardError
from ..facade import AgentGuard

F = TypeVar("F", bound=Callable[..., Any])


def guarded_tool_call(guard: AgentGuard, tool_name: str, fn: F) -> F:
    """
    将任意「工具函数」包装为受 AgentGuard 保护的调用（AOP/装饰器风格）。

    与 agent-mesh ``govern()`` 一样：宿主只维护一个可调用原语，网关统一前置校验。
    入参由 ``inspect.signature`` 绑定为 dict 再送进 ``before_tool``。
    """

    @functools.wraps(fn)
    def wrapper(*args: Any, **kwargs: Any):
        sig = inspect.signature(fn)
        bound = sig.bind_partial(*args, **kwargs)
        bound.apply_defaults()
        merged = copy.deepcopy(dict(bound.arguments))
        verdict = guard.before_tool(tool_name, merged)
        if not verdict.allowed:
            raise GuardError(verdict.block_reason or "blocked_by_agent_guard")
        out = fn(*args, **kwargs)
        return guard.after_tool(tool_name, out)

    return wrapper  # type: ignore[return-value]


def guarded_executor(
    guard: AgentGuard,
    executor: Callable[[str, Dict[str, Any]], Any],
) -> Callable[[str, Dict[str, Any]], Any]:
    """适用于 ``executor(tool_name, arguments) -> result`` 的 MCP/LangChain 统一入口。"""

    def _run(name: str, arguments: Dict[str, Any]) -> Any:
        v = guard.before_tool(name, copy.deepcopy(arguments))
        if not v.allowed:
            raise GuardError(v.block_reason or "blocked_by_agent_guard")
        result = executor(name, v.sanitized_arguments)
        return guard.after_tool(name, result)

    return _run
