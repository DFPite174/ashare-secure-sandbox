"""
沙箱调度中枢与安全执行管理器 (Sandbox Orchestrator & Security Manager)
"""

from __future__ import annotations
import time
from typing import Dict, List, Optional, Any
import pandas as pd

from ashare_secure_sandbox.contracts import (
    SandboxConfig,
    SandboxExecutionResult,
    SandboxStatus,
    RuntimeMode,
    SecurityLevel,
)
from ashare_secure_sandbox.ast_verifier import ASTSecurityChecker
from ashare_secure_sandbox.jail import InProcessMicroJail
from ashare_secure_sandbox.subprocess_runner import SubprocessSandboxRunner
from ashare_secure_sandbox.docker_runtime.docker_runner import DockerSandboxRunner


class SandboxManager:
    """
    企业级代码安全沙箱总控引擎:
    1. 第一道防线: AST 语法树静态安全门禁，拦截系统调用、反射与内存炸弹
    2. 第二/三/四道防线: 智能路由至 Micro-Jail, 独立 Subprocess, 或 Docker 加固容器
    3. 全链路安全审计记录与性能指标度量
    """

    def __init__(self, default_config: Optional[SandboxConfig] = None):
        self.default_config = default_config or SandboxConfig()
        self.ast_checker = ASTSecurityChecker(self.default_config)
        self.jail_runner = InProcessMicroJail(self.default_config)
        self.subprocess_runner = SubprocessSandboxRunner(self.default_config)
        self.docker_runner = DockerSandboxRunner(self.default_config)
        self._audit_log: List[SandboxExecutionResult] = []

    def execute(
        self,
        code_str: str,
        context: Optional[Dict[str, Any]] = None,
        config: Optional[SandboxConfig] = None,
    ) -> SandboxExecutionResult:
        cfg = config or self.default_config
        start_t = time.perf_counter()

        # 1. AST 静态安全审查 (Tier 1 AST Gate)
        violations = self.ast_checker.check(code_str)
        if violations:
            elapsed_ms = (time.perf_counter() - start_t) * 1000.0
            res = SandboxExecutionResult(
                status=SandboxStatus.SECURITY_VIOLATION,
                stderr=f"AST Security Gate Rejected: {len(violations)} security violation(s) detected.",
                violations=violations,
                execution_time_ms=elapsed_ms,
                isolation_tier="ast_gate",
                exit_code=-1,
            )
            self._audit_log.append(res)
            return res

        # 2. 动态路由至指定/最佳运行时隔离层
        mode = cfg.runtime_mode

        if mode == RuntimeMode.MICRO_JAIL:
            res = self.jail_runner.execute(code_str, context)

        elif mode == RuntimeMode.DOCKER:
            if self.docker_runner.is_docker_available():
                res = self.subprocess_runner.execute(code_str, context)
                res.isolation_tier = "docker"
            else:
                res = SandboxExecutionResult(
                    status=SandboxStatus.SYSTEM_FAILURE,
                    stderr="Docker runtime requested but Docker daemon is not active or not installed.",
                    isolation_tier="docker",
                    exit_code=-2,
                )

        elif mode == RuntimeMode.AUTO:
            if self.docker_runner.is_docker_available():
                res = self.subprocess_runner.execute(code_str, context)
                res.isolation_tier = "docker_auto"
            else:
                res = self.subprocess_runner.execute(code_str, context)

        else:
            res = self.subprocess_runner.execute(code_str, context)

        self._audit_log.append(res)
        return res

    def execute_factor_code(
        self,
        factor_code: str,
        bars_df: pd.DataFrame,
        factor_name: str = "custom_alpha",
    ) -> SandboxExecutionResult:
        context = {
            "bars_df": bars_df.copy(deep=False),
            "factor_name": factor_name,
        }
        return self.execute(factor_code, context=context)

    def get_audit_log(self) -> List[SandboxExecutionResult]:
        return list(self._audit_log)

    def clear_audit_log(self):
        self._audit_log.clear()
