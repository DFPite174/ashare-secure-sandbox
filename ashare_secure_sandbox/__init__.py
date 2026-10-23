"""
ashare-secure-sandbox: 企业级代码安全沙箱与容器隔离中枢
"""

from ashare_secure_sandbox.contracts import (
    SecurityLevel,
    RuntimeMode,
    SandboxStatus,
    SecurityViolation,
    SandboxConfig,
    SandboxExecutionResult,
)
from ashare_secure_sandbox.ast_verifier import ASTSecurityChecker
from ashare_secure_sandbox.jail import InProcessMicroJail
from ashare_secure_sandbox.subprocess_runner import SubprocessSandboxRunner
from ashare_secure_sandbox.docker_runtime.container_spec import DockerContainerSpec
from ashare_secure_sandbox.docker_runtime.docker_runner import DockerSandboxRunner
from ashare_secure_sandbox.manager.sandbox_manager import SandboxManager

__version__ = "1.0.0"

__all__ = [
    "SecurityLevel",
    "RuntimeMode",
    "SandboxStatus",
    "SecurityViolation",
    "SandboxConfig",
    "SandboxExecutionResult",
    "ASTSecurityChecker",
    "InProcessMicroJail",
    "SubprocessSandboxRunner",
    "DockerContainerSpec",
    "DockerSandboxRunner",
    "SandboxManager",
]
