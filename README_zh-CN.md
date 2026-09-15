# MIDAS

[English](README.md) | 简体中文

**多源智能诊断智能体系统（Multi-source Intelligent Diagnostic Agent System）**

MIDAS 是面向大连先进光源（DALS）多源故障诊断的大语言模型运维助手。系统通过模型上下文协议（MCP）连接 EPICS 过程变量、Loki 日志、Prometheus 监控指标和 PostgreSQL 配置记录，使智能体能够综合原本分散在不同运行系统中的证据。

本仓库是以下论文的配套材料：

> *MIDAS: An LLM-Based Agent for Fault Diagnosis Using Multi-Source
> Operational Data at the Dalian Advanced Light Source*

## 研究范围

MIDAS 被设计为诊断辅助系统。在论文报告的评估中，系统负责收集运行证据、识别可能的故障原因，并生成由操作人员审核的处置建议。已评估流程不会自主执行故障修复操作。

论文所报告的实验统一使用 Azure OpenAI 提供的 GPT-5.2，`temperature=1`。本研究尚未测试其他大语言模型，因此不声称结果与模型无关，也不声称 GPT-5.2 优于其他模型。

## 系统概览

```text
操作人员请求
      |
      v
MIDAS 诊断智能体
      |
      +-- 中间件：调用限制、重试、上下文管理和审计
      |
      +-- EPICS MCP -------- 过程变量和 IOC 状态
      +-- Loki MCP --------- 机器及服务日志
      +-- Prometheus MCP --- 监控指标和监控目标
      +-- PostgreSQL MCP --- PV、设备、IOC 和主机配置
      |
      v
包含证据链的诊断结论和由操作人员审核的处置建议
```

MCP 统一了工具访问方式，但不会自动合并四类数据。MIDAS 在查询过程中使用 PV 名称、IOC 名称、设备名称、服务标签、主机名和 IP 地址等设施标识符关联不同数据源。

## 仓库结构

```text
MIDAS/
├── MCP Servers/                      # 各运行数据源的 MCP 适配器
├── MIDAS_Fault_Diagnosis_Raw_Data/   # 保留的故障案例记录和相关材料
├── evaluated-version/                # 与论文研究对应的评估版本
├── hardened-version/                 # 研究完成后的安全与审计加固版本
├── LICENSE
├── README.md
└── README_zh-CN.md
```

### 评估版本

`evaluated-version/` 保存与论文诊断案例研究对应的实现，用于研究追溯，不应被视为可直接部署到生产控制系统的智能体。该版本提供的通用 SSH 接口和基于正则表达式的命令过滤只能构成有限的防护措施。

### 加固版本

`hardened-version/` 包含研究完成后的工程加固，包括：

- 基于可信应用身份的默认拒绝授权；
- 按工具、主机、服务和操作配置的允许列表；
- 使用固定的只读 SSH 诊断操作替代模型生成的任意 shell 命令；
- SSH 主机密钥验证、输出大小限制和执行超时；
- 对参数进行脱敏的 PostgreSQL 工具调用审计；
- 记录提出、执行、拒绝、失败和取消的调用；
- 审计存储失败后采用失败关闭策略。

这些改进是在论文所报告的诊断会话之后加入的，不能被解释为已经由原十个案例验证的安全机制。

## 安装

创建虚拟环境，并安装所选版本需要的 Python 依赖。典型安装需要以下软件包：

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install \
  deepagents \
  langchain \
  langgraph \
  langchain-openai \
  langchain-mcp-adapters \
  langgraph-checkpoint-postgres \
  'psycopg[binary]' \
  paramiko \
  python-dotenv
```

为保证可复现性，应使用目标部署实际记录的依赖版本，而不是直接采用最新版本。

## 配置

请勿将凭据提交到代码仓库。应通过环境变量或密钥管理服务进行配置。

加固版本使用的环境变量示例如下：

```dotenv
# Azure OpenAI
AZURE_OPENAI_ENDPOINT=https://<resource>.openai.azure.com/
AZURE_OPENAI_API_KEY=<secret>
AZURE_OPENAI_DEPLOYMENT=gpt-5.2
AZURE_OPENAI_API_VERSION=2024-12-01-preview

# 智能体记忆和审计存储
MIDAS_MEMORY_DATABASE_URL=postgresql://<user>:<password>@<host>:5432/<database>
MIDAS_AUDIT_DATABASE_URL=postgresql://<audit_user>:<password>@<host>:5432/<database>
MIDAS_SETUP_MEMORY_STORE=0

# 授权策略
MIDAS_AUTHORIZATION_POLICY=/absolute/path/to/policy.json

# MCP 端点
MIDAS_MCP_EPICS_URL=http://<host>:<port>/sse
MIDAS_MCP_LOKI_URL=http://<host>:<port>/sse
MIDAS_MCP_PROMETHEUS_URL=http://<host>:<port>/sse
MIDAS_MCP_POSTGRES_URL=http://<host>:<port>/sse

# 本地代码工具的工作目录
MIDAS_PROJECT_ROOT=/app
```

编辑授权策略前，复制示例文件：

```bash
cp hardened-version/policy_example.json policy.local.json
```

应使用非 root SSH 账户，并且只授予诊断所需的主机、服务、操作和工具权限。应用程序必须提供经过身份验证的主体标识，不能接受模型生成的身份信息。

## PostgreSQL 审计日志

启动加固版智能体前，应用审计表结构：

```bash
psql "$MIDAS_AUDIT_DATABASE_URL" -f hardened-version/audit_schema.sql
```

可以使用以下 SQL 检查审计事件：

```sql
SELECT occurred_at,
       run_id,
       thread_id,
       tool_name,
       phase,
       duration_ms,
       arguments,
       result,
       error
FROM midas_audit.tool_events
ORDER BY occurred_at DESC;
```

这些记录可用于运行检查，但当前数据库表结构本身并不能证明记录具有防篡改能力。生产部署还应根据实际要求配置受限数据库权限、数据保留策略、完整性保护以及异机备份或复制。

## 运行 MIDAS

1. 启动所需的 EPICS、Loki、Prometheus 和 PostgreSQL MCP 服务器。
2. 配置模型、记忆数据库、审计数据库、MCP 端点和授权策略。
3. 根据需要初始化 PostgreSQL 记忆和审计表结构。
4. 启动所选的 MIDAS 智能体实现。

运行加固版本：

```bash
cd hardened-version
python midas_agent.py
```

智能体图应由经过身份验证的应用程序调用，并提供与授权策略匹配的主体标识。示例策略仅用于说明，必须根据本地设施环境进行调整。

## 评估材料

`MIDAS_Fault_Diagnosis_Raw_Data/` 包含与故障诊断案例相关的保留材料。解释这些文件时请注意：

- 每个案例仅包含一次保留的诊断会话；
- 同一案例中的多个 `run` 可能是同一会话中的多轮对话，而不是独立重复试验；
- 案例级结论一致性属于描述性结果，不能作为总体准确率或泛化能力的估计；
- 本仓库未提供受控的人工性能基线；
- 在将不同案例视为相互独立的冷启动试验前，应核实持久记忆的初始化状态。

公开更多记录前，应对运行标识符和敏感设施信息进行脱敏。

## 安全注意事项

MIDAS 会与运行基础设施交互，部署时必须谨慎。至少应遵循以下要求：

- 尽可能为 MCP 和数据库使用只读账户；
- 不向模型提供原始 shell 访问能力；
- 使用最小权限的非 root SSH 账户；
- 不在提示、源码、日志或 Git 历史中保存凭据；
- 在实际执行边界再次验证授权；
- 改变系统状态的操作必须经过操作人员明确批准；
- 将生成代码与控制网络及敏感文件隔离；
- 生产部署前测试提示注入和跨工具绕过路径。

加固版本降低了部分风险，但仍不是完整的安全边界。特别是任意代码执行和通用数据库查询工具，还需要额外的沙箱隔离以及由后端强制实施的只读权限。

## 数据主权

论文所使用的商业模型仅用于概念验证。面向生产部署，可以在设施自主管控的基础设施中运行本地开源权重大模型，使提示信息、运行数据和工具返回结果保留在本地网络内。模型本地部署还应结合访问控制、数据最小化、保留规则和审计策略。

## 引用

论文正式发表后将补充完整引用信息。在此之前，请使用仓库发布版本标签和 commit hash 进行引用。可以将 GitHub Release 与 Zenodo 关联，为代码归档生成永久 DOI。

## 许可证

本项目采用 [MIT License](LICENSE)。

## 联系方式

欢迎通过 GitHub Issues 提交问题、复现结果和缺陷报告。
