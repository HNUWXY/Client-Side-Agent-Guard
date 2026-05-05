/**
 * Next.js 服务端（Server Actions / Route Handler）调用 Agent Guard。
 * MCP 的 `executeMcpAction` 跑在 Node 上，不能复用浏览器里的 `invokePluginToolWithGuard`。
 */

type GuardToolJson = {
  allowed?: boolean;
  block_reason?: string;
  sanitized_arguments?: Record<string, unknown>;
  consent_required?: boolean;
};

function guardBaseUrl(): string {
  return (
    process.env.AGENT_GUARD_URL?.trim() ||
    process.env.NEXT_PUBLIC_AGENT_GUARD_URL?.trim() ||
    ""
  );
}

function failOpen(): boolean {
  return process.env.NEXT_PUBLIC_AGENT_GUARD_FAIL_OPEN !== "false";
}

function autoApproveFromEnv(): boolean {
  return (
    process.env.NEXT_PUBLIC_AGENT_GUARD_AUTO_APPROVE_TOOLS === "true" ||
    process.env.AGENT_GUARD_MCP_AUTO_APPROVE === "true"
  );
}

/**
 * 在执行 MCP `tools/call` 前调用，与 Python `/guard/tool` 对齐。
 *
 * 服务端无法弹窗：若因敏感工具同意被拒，可设置
 * `NEXT_PUBLIC_AGENT_GUARD_AUTO_APPROVE_TOOLS=true` 或 `AGENT_GUARD_MCP_AUTO_APPROVE=true`
 * 使第二次请求带 `approve_sensitive_tools: true`（仅建议演示环境）。
 */
export async function guardToolCallServerSide(
  sessionId: string,
  toolName: string,
  rawArgs: Record<string, unknown>,
): Promise<{
  allowed: boolean;
  sanitized_arguments?: Record<string, unknown>;
  block_reason?: string;
}> {
  const base = guardBaseUrl();
  if (!base) {
    return { allowed: true, sanitized_arguments: rawArgs };
  }

  const url = `${base.replace(/\/$/, "")}/guard/tool`;
  const auto = autoApproveFromEnv();

  const postOnce = async (
    approve: boolean,
  ): Promise<GuardToolJson | { httpError: true; status: number }> => {
    const res = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        session_id: sessionId,
        tool: toolName,
        arguments: rawArgs,
        approve_sensitive_tools: approve,
      }),
      cache: "no-store",
    });
    if (!res.ok) {
      return { httpError: true, status: res.status };
    }
    return (await res.json()) as GuardToolJson;
  };

  try {
    let data = await postOnce(auto);

    if ("httpError" in data && data.httpError) {
      if (failOpen()) {
        return { allowed: true, sanitized_arguments: rawArgs };
      }
      return { allowed: false, block_reason: `guard_http_${data.status}` };
    }

    if (
      !data.allowed &&
      !auto &&
      (data.block_reason === "user_rejected_sensitive_tool" ||
        data.consent_required) &&
      process.env.AGENT_GUARD_MCP_AUTO_APPROVE === "true"
    ) {
      const second = await postOnce(true);
      if ("httpError" in second && second.httpError) {
        if (failOpen()) return { allowed: true, sanitized_arguments: rawArgs };
        return { allowed: false, block_reason: `guard_http_${second.status}` };
      }
      data = second;
    }

    if (!data.allowed) {
      return {
        allowed: false,
        block_reason:
          data.block_reason ||
          "tool_blocked (MCP 服务端无弹窗：可设 NEXT_PUBLIC_AGENT_GUARD_AUTO_APPROVE_TOOLS 或 AGENT_GUARD_MCP_AUTO_APPROVE)",
      };
    }

    return {
      allowed: true,
      sanitized_arguments: data.sanitized_arguments ?? rawArgs,
    };
  } catch (e) {
    if (failOpen() && e instanceof TypeError) {
      return { allowed: true, sanitized_arguments: rawArgs };
    }
    throw e;
  }
}
