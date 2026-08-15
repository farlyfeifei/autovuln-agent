# AutoVulnAgent — 自动漏洞挖掘 AI Agent

面向 **百度 BSRC「Agent+」攻防能力挑战赛** 的自动化漏洞发现 Agent。核心是一个
**ReAct 决策循环**：由 LLM（或确定性本地策略）根据当前观察选择工具动作，工具
执行真实 HTTP/离线分析，观察回灌，从响应中提取 flag 并提交，直至解出或预算耗尽。
覆盖侦察、注入、越权、加密弱点、哈希破解等 13 类工具与 7 类漏洞靶标，既可在
纯离线 mock 靶场闭环演示，也可接真实大模型与真实靶标平台打分。

## 架构

```
┌───────────────────────────────────────────────────────────┐
│  main.py  CLI / webdemo 实时演示(SSE)                      │
├───────────────────────────────────────────────────────────┤
│  core/  ReAct 编排: solve_challenge / run_benchmark        │
│         budget 执行 · flag 提取 · 上下文压缩 · JSONL 轨迹    │
├───────────────┬───────────────────────────────────────────┤
│  llm/          │  adapters/                                │
│  providers     │  mock(离线靶标) · tsecbench/http(真实平台) │
│  local_policy  │  提供 list_challenges / tools / submit     │
├───────────────┴───────────────────────────────────────────┤
│  tools/  13 个真实工具: http_probe/port_scan/dir_enum/     │
│         fingerprint/param_probe/fuzz/sqli/xss/lfi/ssrf/    │
│         idor/decode/hash_crack (全部真实 HTTP/本地计算)     │
├───────────────────────────────────────────────────────────┤
│  bench/ 题库与评分 · reports/ markdown 报告 · core/net  HTTP│
└───────────────────────────────────────────────────────────┘
```

分层解耦：**决策层(LLM) / 编排层(core) / 工具层(tools) / 适配层(adapters) /
评分报告层(bench/reports)**。同一套 ReAct 编排既可以驱动离线 mock 工具，也可以
驱动真实工具打真实靶标——只是 `adapter.tool_registry()` 不同。

## 快速开始

### 0) 安装依赖

```bash
pip install -r requirements.txt   # requests + PyYAML（仅联网/配置用，也可零依赖运行）
```

### 1) 纯离线 Mock 跑分（零网络、零 key，演示全链路）

```bash
python main.py --mode mock --report --trace
python main.py --mode mock --json          # 机器可读 JSON 摘要
```

输出 7 题 80 分的成绩单、每步 ReAct 轨迹，并生成 `reports/*.md` 报告。

### 2) 接入真实大模型（决策质量跑分）

```bash
export LLM_API_KEY="你的key"              # Windows PowerShell: $env:LLM_API_KEY="..."
python main.py --mode mock --llm glm --report     # 智谱(glm-4-flash)
python main.py --mode mock --llm deepseek         # DeepSeek(deepseek-chat)
```

provider 支持 `local | openai | glm | deepseek | comate | opencode`。缺 key 时自动
回退到确定性本地策略，跑分不会中断。

**opencode（OpenCode Go）**：无需 `LLM_API_KEY`——自动从 opencode 的凭据存储
（`~/.local/share/opencode/auth.json`，`opencode-go.api.key`）读取，也可用
`LLM_API_KEY` 覆盖。默认模型 `deepseek-v4-flash`（推理模型，已自动提高输出 token 预算）：

```bash
python main.py --mode mock --llm opencode --report    # OpenCode Go · deepseek-v4-flash
LLM_MODEL=deepseek-v4-pro python main.py --mode mock --llm opencode   # 换模型
```

真实模型实测（opencode / DeepSeek V4 flash，Mock 靶场）：**6/7 解出、75% 得分**；真实
token 69.9k、端到端 325s（含 1 道故意不可解的 SSRF 题烧满预算），报告与 JSONL 轨迹自动生成。

### 3) 打真实靶标平台

**TSecBench（官方跑分平台）**：适配器实现官方的 Challenges API（`docs/CHALLENGES_API.md`），
每道题先 `start` 拉取容器地址 → 工具攻击 → `submit` 提交 flag → `close` 释放容器。
认证走 `BENCHMARK_TOKEN` 请求头；凭证优先读平台下发的环境变量 `BENCHMARK_BASE_URL` /
`BENCHMARK_TOKEN`（`AV_BASE_URL` / `AV_SUBMIT_TOKEN` 为兼容别名）：

```bash
export BENCHMARK_BASE_URL="https://tsecbench.zc.tencent.com"
export BENCHMARK_TOKEN="<跑分任务下发的 token>"
# 连接靶场 VPN 后再运行；未带 --challenges-file 时自动从 API 拉取题目清单
python main.py --mode tsecbench --llm opencode --max-steps 30 --report
```

`tsecbench` / `http` 两种适配器负责容器生命周期、清单加载与 flag 提交，对接官方或自建
评分平台；`--trace` 可实时观察每一步的 ReAct 过程与容器 start/close。

多 flag 支持：列表接口归一化 `flag_count`，提交接口回传 `correct_flag_count` /
`total_flag_count`；**已接受的 flag 若仍有剩余会继续狩猎**，`points_awarded` 按平台
实发 `awarded` 累计（部分 flag 也计分）。已通关题目（`is_completed`）自动跳过；运行
中若传了 `--challenges-file`，仍以 live API 清单为准，seed 仅在 API 不可达时回退。
全 run 有墙钟上限 `budget.run_max_elapsed`（默认 5.5h，`AV_RUN_MAX_ELAPSED` 覆盖），
避免把 6h 平台时限烧穿后所有接口返回 `invalid_state`。

### 4) 实时演示 Web UI

```bash
python webdemo/app.py      # → http://127.0.0.1:8080/  (stdlib SSE 实时步骤)
```

演示使用 Mock 靶场驱动**当前配置的决策大脑**：无 key 时自动回落本地策略，配置了
真实 LLM（如 `LLM_PROVIDER=glm LLM_API_KEY=... python webdemo/app.py`）时实时展示
真模型逐步推理与工具调用。

### 5) 运行测试（151 个单测 + 真实工具冒烟 + 真模型链路）

```bash
python -m unittest discover -s tests -p "test_*.py"
```

- `tests/test_live_target.py` 起本地真实 HTTP 靶标，逐一验证全部 13 个工具
  与完整 ReAct 循环（非 mock）。
- `tests/test_provider.py` 用本地 mock OpenAI 服务验证真模型链路：请求结构、
  JSON 解析、markdown 围栏容错、429 重试、纠错二次调用、usage 统计。
- `tests/test_e2e_llm.py` 真模型链路驱动真实工具打真实靶标，端到端解出并提交 flag。

## 配置

`config.yaml` 集中配置，所有值可被同名环境变量覆盖（见 `config.py`）：

| 配置块 | 关键项 | 环境变量覆盖 |
|---|---|---|
| `llm` | provider / model / api_key_env | `LLM_API_KEY` |
| `budget` | max_steps / max_elapsed / max_tokens / run_max_elapsed | `AV_MAX_STEPS` 等 |
| `net` | timeout / verify_ssl / proxies | `AV_VERIFY_SSL` |
| `adapter` | mode / challenges_file / base_url | `AV_ADAPTER` / `AV_BASE_URL` |
| `report` | out_dir / trace_dir | — |

## 目录结构

```
autovuln-agent/
├── main.py               # CLI 入口（mock / tsecbench / http 三种模式）
├── config.py / config.yaml
├── core/                 # ReAct 编排、budget、flag 提取、net、trace、context
├── llm/                  # providers(OpenAI 兼容) / local_policy(确定性策略)
├── tools/                # 13 个真实工具 + registry
├── adapters/             # mock / tsecbench / http
├── bench/                # 题库(challenges.py) + 评分(scoreboard.py)
├── reports/              # markdown 报告生成 + traces 输出
├── webdemo/              # stdlib SSE 实时演示
├── tests/                # 158 个测试（含 tsecbench API 契约、多 flag 循环、真实靶标冒烟、provider 链路、webdemo）
├── docs/技术方案文档.md   # 参赛技术方案（≤5000 字）
├── run_benchmark.py      # 早期原型（自包含单文件版），见下
└── bench_mock/           # 早期原型的模块化组件
```

## 早期原型说明

`run_benchmark.py` 与 `bench_mock/` 是项目起步阶段的**原型**：单文件自包含的
mock 跑分闭环，仅用标准库，用于快速验证「题库→决策→工具→评分」可行性。
正式实现为 `main.py` + 上方分层包，二者不冲突；原型保留作最小可运行对照与
离线演示兜底。

## 作品包 / 交付材料

BSRC「Agent+」挑战赛提交材料清单（对照官网要求，截止 2026-08-15 23:59）：

| 材料 | 对应文件 | 状态 |
|---|---|---|
| 技术方案文档（必交，≤5000 字） | `docs/技术方案文档.md`（可转 PDF） | 已定稿 |
| 可运行 Demo / 原型（≤100MB） | 本仓库 `main.py`（mock 零依赖离线跑分）+ `webdemo/` 实时演示 | 可运行 |
| 源码仓库（带 README） | 本仓库 | 已整理 |
| 演示视频（≤5min MP4，加分项） | 待录制（mock 跑分 + webdemo 实时流） | 待完成 |

快速录制素材建议：`python main.py --mode mock` 展示 6/7 全自动解出，再
`python webdemo/app.py` 展示 SSE 实时步骤流。

## 合规声明

- 仅用于**官方授权的靶场 / 本地故意构造的含漏洞靶标**；绝不触碰未授权目标。
- 工具在无授权目标白名单时可全程离线运行（mock 模式），不发起任何真实网络请求。
- 真模型模式要求自行配置授权目标，用户对目标授权与合规负全责。

## 环境

- Python 3.10+（已在 3.12.10 验证）
- 运行时仅 `requests`（core.net 自带 urllib 兜底，可完全零依赖）
- Windows / Linux 均可
