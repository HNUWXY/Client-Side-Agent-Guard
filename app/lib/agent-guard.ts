/**
 * NextChat ⇄ Agent Guard（Python HTTP 桥梁）前端客户端。
 *
 * 配置：在 `.env.local` 中设置
 *   NEXT_PUBLIC_AGENT_GUARD_URL=http://127.0.0.1:8765
 * 未设置时不会产生任何请求（相当于关闭检测）。
 */

export interface AgentGuardSlimMessage {
  role: string;
  content: unknown;
}

export type AgentGuardPrepareResult =
  | { skipped: true; allowed: true }
  | {
      skipped: false;
      allowed: boolean;
      block_reason?: string;
      threat_signals?: string[];
      messages?: AgentGuardSlimMessage[];
    };

function guardBaseUrl(): string {
  const u = process.env.NEXT_PUBLIC_AGENT_GUARD_URL?.trim();
  return u || "";
}

function failOpen(): boolean {
  return process.env.NEXT_PUBLIC_AGENT_GUARD_FAIL_OPEN !== "false";
}

/**
 * 在发往任意 LLM API 之前调用：`messages` 为 OpenAI 形态（仅 role/content 即可）。
 * 网关会重写 **最后一条 user** 的 content（注入拦截 / 脱敏等）。
 */
export async function runAgentGuardPrepareMessages(
  sessionId: string,
  messages: AgentGuardSlimMessage[],
  approveSensitiveTools = false,
): Promise<AgentGuardPrepareResult> {
  const base = guardBaseUrl();
  if (!base) {
    return { skipped: true, allowed: true };
  }

  const url = `${base.replace(/\/$/, "")}/guard/prepare_messages`;
  try {
    const res = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        session_id: sessionId,
        messages,
        approve_sensitive_tools: approveSensitiveTools,
      }),
    });
    const data = (await res.json()) as {
      allowed?: boolean;
      block_reason?: string;
      messages?: AgentGuardSlimMessage[];
      threat_signals?: string[];
    };
    if (!res.ok) {
      console.warn("[AgentGuard] HTTP", res.status, data);
      if (failOpen()) {
        return { skipped: false, allowed: true, messages };
      }
      return {
        skipped: false,
        allowed: false,
        block_reason: `guard_http_${res.status}`,
      };
    }
    return {
      skipped: false,
      allowed: !!data.allowed,
      block_reason: data.block_reason,
      threat_signals: data.threat_signals,
      messages: data.messages,
    };
  } catch (e) {
    console.warn("[AgentGuard] fetch failed:", e);
    if (failOpen()) {
      return { skipped: true, allowed: true };
    }
    return {
      skipped: false,
      allowed: false,
      block_reason: "guard_unreachable",
    };
  }
}

/** 与 stream() 内插件 tool 结构兼容，避免从 store 反向引用造成循环依赖 */
export type AgentGuardToolLike = {
  function?: { name?: string; arguments?: string };
};

/**
 * 在执行插件函数前走 `/guard/tool`（路径/域名沙箱、敏感工具授权、DLP 等）。
 * 未配置 `NEXT_PUBLIC_AGENT_GUARD_URL` 或未传 sessionId 时直接执行原插件。
 */
export async function invokePluginToolWithGuard(
  sessionId: string | undefined,
  tool: AgentGuardToolLike,
  funcs: Record<string, Function>,
): Promise<unknown> {
  const name = tool.function?.name;
  if (!name || typeof funcs[name] !== "function") {
    throw new Error(`[AgentGuard] 未找到插件工具: ${String(name)}`);
  }

  let rawArgs: Record<string, unknown> = {};
  try {
    rawArgs = tool.function?.arguments
      ? (JSON.parse(tool.function.arguments) as Record<string, unknown>)
      : {};
  } catch {
    rawArgs = {};
  }

  const base = guardBaseUrl();
  if (!base || !sessionId) {
    return funcs[name](rawArgs);
  }

  const autoApprove =
    process.env.NEXT_PUBLIC_AGENT_GUARD_AUTO_APPROVE_TOOLS === "true";
  const url = `${base.replace(/\/$/, "")}/guard/tool`;

  type GuardJson = {
    allowed?: boolean;
    block_reason?: string;
    sanitized_arguments?: Record<string, unknown>;
    consent_required?: boolean;
  };

  const postOnce = async (
    approve: boolean,
  ): Promise<GuardJson | { httpError: true; status: number }> => {
    const res = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        session_id: sessionId,
        tool: name,
        arguments: rawArgs,
        approve_sensitive_tools: approve,
      }),
    });
    if (!res.ok) {
      return { httpError: true, status: res.status };
    }
    return (await res.json()) as GuardJson;
  };

  try {
    let data = await postOnce(autoApprove);

    if ("httpError" in data && data.httpError) {
      if (failOpen()) {
        return funcs[name](rawArgs);
      }
      throw new Error(`[安全网关] HTTP ${data.status}`);
    }

    if (
      !data.allowed &&
      !autoApprove &&
      (data.block_reason === "user_rejected_sensitive_tool" ||
        data.consent_required)
    ) {
      if (
        typeof window !== "undefined" &&
        window.confirm(
          `[安全网关] 插件工具「${name}」需要授权（敏感操作），是否允许本次执行并本会话内记住？`,
        )
      ) {
        const second = await postOnce(true);
        if ("httpError" in second && second.httpError) {
          if (failOpen()) return funcs[name](rawArgs);
          throw new Error(`[安全网关] HTTP ${second.status}`);
        }
        data = second;
      }
    }

    if (!data.allowed) {
      throw new Error(`[安全网关] ${data.block_reason || "tool_blocked"}`);
    }

    const args = data.sanitized_arguments ?? rawArgs;
    return funcs[name](args);
  } catch (e) {
    if (failOpen() && e instanceof TypeError) {
      return funcs[name](rawArgs);
    }
    throw e;
  }
}
