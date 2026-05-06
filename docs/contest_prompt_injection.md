# contest_prompt_injection

赛题增强版提示注入检测（规则 + 启发式 + 边界 + 可选 ML）。

代码目录：`src/contest_prompt_injection/`

## 交叉验证（在 Client-Side-Agent-Guard 仓库根目录执行）

1. `python3 -m venv .venv`
2. `source .venv/bin/activate`
3. `pip install pydantic pyyaml`
4. `export PYTHONPATH="$(pwd)/src:$PYTHONPATH"`
5. `python scripts/crosscheck_injection_baseline.py`

预期：全部为 OK，进程退出码为 0。
