# NextChat

轻量、快速的 AI 对话客户端（支持多种大模型 API）。

本文说明：**克隆本仓库后如何在本地安装依赖并运行**。

## 环境要求

### Node.js

- **版本**：**18.17 及以上**（推荐使用当前 **20.x LTS**）。
- 安装方式：从 [Node.js 官网](https://nodejs.org/) 下载安装，或使用 [nvm](https://github.com/nvm-sh/nvm) / fnm 等工具管理多版本。

在终端中确认：

```bash
node -v   # 应显示 v18.17.x 或 v20.x 等
```

### Yarn（Classic / Yarn 1）

本项目使用 **Yarn 1**。

若尚未安装，可用以下任一方式：

```bash
# 方式一：通过 Corepack（Node 16.10+ 自带，推荐）
corepack enable
corepack prepare yarn@1.22.19 --activate

# 方式二：全局安装指定版本
npm install -g yarn@1.22.19
```

确认：

```bash
yarn -v   # 建议为 1.22.x
```

## 克隆与安装

```bash
git clone <仓库地址>
cd NextChat
yarn install
```

## 配置环境变量

复制模板并按需填写（至少需要配置你要使用的模型对应的 API Key 等）：

```bash
cp .env.template .env.local
```

用编辑器打开 `.env.local`，按注释修改；例如使用 OpenAI 时需填写 `OPENAI_API_KEY`（详见 `.env.template` 内说明）。

## 运行

**开发模式**（热更新，默认 <http://localhost:3000>）：

```bash
yarn dev
```

**生产构建与启动**：

```bash
yarn build
yarn start
```

浏览器访问控制台输出的地址即可使用 NextChat。

## 可选：MCP 功能

若需启用 MCP，请在 `.env.local` 中设置 `ENABLE_MCP=true`，并在构建前配置好相关环境（详见仓库内关于 MCP 的说明）。

---

## Python：客户端 Agent Guard（赛题后端能力）

`src/agent_guard/` 为可与具体 LLM SDK 解耦的安全网关（**自带** `pii/` 扫描与脱敏，不依赖其他同学目录）；含 **HTTP 桥梁** 供 NextChat 等前端 `fetch` 联调。

```bash
export PYTHONPATH="$(pwd)/src:${PYTHONPATH}"
python -m unittest src.agent_guard.tests.test_agent_guard src.agent_guard.tests.test_gateway -v
PYTHONPATH=src python src/agent_guard/examples/minimal_demo.py
PYTHONPATH=src python -m agent_guard --port 8765
```
（亦可用 `python -m agent_guard.bridge.http_server`。）

完整用法、**NextChat 接入与 curl 测试步骤**见 [src/agent_guard/USAGE.md](src/agent_guard/USAGE.md)。

---


