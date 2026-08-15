"""AutoVulnAgent: BSRC「Agent+」攻防能力挑战赛自动漏洞挖掘 Agent。

分层架构:
    llm/       决策大脑(可插拔:本地策略 / OpenAI 兼容大模型)
    core/      数据模型、flag 提取、HTTP、轨迹、ReAct 主循环
    tools/     真实安全工具(纯 Python 实现,可替换为外部二进制)
    adapters/  靶场适配(本地 Mock / 任意 HTTP / tsecbench)
    bench/     题库与积分聚合
    reports/   量化报告生成
    webdemo/   (可选)Web 实时演示
"""
__version__ = "0.2.0"
