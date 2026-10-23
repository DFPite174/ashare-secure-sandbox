"""
代码安全沙箱契约层 (Secure Sandbox Contracts & Specifications)
参考:
- Agache et al., "Firecracker: Lightweight Virtualization for Serverless Applications" (NSDI 2020)
- Google gVisor Container Security Architecture
- E2B AI Agent Code Sandboxing Benchmark
"""

from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Set, Any, Union
from datetime import datetime
import uuid


class SecurityLevel(str, Enum):
    """代码安全沙箱防护等级"""
    STRICT = "STRICT"        # 极度严苛：禁用所有 I/O、文件读写与网络，仅允许纯数学与内存中 Pandas/NumPy 向量化运算
    STANDARD = "STANDARD"    # 标准量化：允许读入沙箱传入的只读行情数据，允许常见数据科学库，禁止任何外部网络与系统调用
    PERMISSIVE = "PERMISSIVE"# 宽松测试：允许指定白名单内模块，仍严格禁止危险系统调用与私有属性反射


class RuntimeMode(str, Enum):
    """沙箱底层隔离运行时模式"""
    AUTO = "AUTO"            # 智能探测：优先使用 Docker/MicroVM，不可用时安全降级至 Subprocess 进程级隔离
    DOCKER = "DOCKER"        # 强制 OCI / Docker 容器隔离 (--read-only, --network=none, --cap-drop=ALL)
    SUBPROCESS = "SUBPROCESS"# 独立无特权 Subprocess 进程隔离 (环境剥离, 内存与 CPU 监视, 临时目录擦除)
    MICRO_JAIL = "MICRO_JAIL"# 极速轻量进程内受限受限命名空间 (__builtins__ 深度净化)


class SandboxStatus(str, Enum):
    """沙箱执行终态"""
    SUCCESS = "SUCCESS"
    SECURITY_VIOLATION = "SECURITY_VIOLATION"  # 触发 AST 静态或动态安全拦截
    TIMEOUT = "TIMEOUT"                        # 超出最大 CPU/运行时间熔断
    OOM_KILLED = "OOM_KILLED"                  # 超过内存上限被操作系统/看门狗杀死
    RUNTIME_ERROR = "RUNTIME_ERROR"            # 正常的 Python 运行时语法或逻辑错误
    SYSTEM_FAILURE = "SYSTEM_FAILURE"          # 沙箱底层运行环境异常


@dataclass(frozen=True)
class SecurityViolation:
    """安全违规拦截明细"""
    violation_type: str       # 例如: FORBIDDEN_IMPORT, DUNDER_ACCESS, DANGEROUS_BUILTIN, SYSTEM_CALL, RESOURCE_ABUSE
    message: str              # 拦截人类可读原因
    line_number: Optional[int] = None
    node_repr: Optional[str] = None
    severity: str = "CRITICAL" # CRITICAL, WARNING


@dataclass
class SandboxConfig:
    """沙箱运行时安全配置"""
    timeout_sec: float = 5.0                   # 最大单次执行硬超时时间 (秒)
    memory_limit_mb: float = 512.0             # 最大物理内存限制 (MB)
    allow_network: bool = False                # 是否开放网络访问 (量化策略生成严格 False)
    read_only_fs: bool = True                  # 是否挂载只读文件系统
    max_output_bytes: int = 65536              # 标准输出/标准错误截断上限 (64 KB)
    security_level: SecurityLevel = SecurityLevel.STRICT
    runtime_mode: RuntimeMode = RuntimeMode.AUTO
    allowed_modules: Set[str] = field(default_factory=lambda: {
        "math", "numpy", "np", "pandas", "pd", "scipy", "statsmodels",
        "datetime", "collections", "itertools", "functools", "typing"
    })
    banned_modules: Set[str] = field(default_factory=lambda: {
        "os", "sys", "subprocess", "socket", "ctypes", "shutil", "pickle",
        "urllib", "requests", "http", "ftplib", "importlib", "builtins",
        "pty", "platform", "multiprocessing", "threading", "signal",
        "inspect", "posix", "nt", "_posixsubprocess", "winreg"
    })
    banned_builtins: Set[str] = field(default_factory=lambda: {
        "eval", "exec", "compile", "open", "breakpoint", "exit", "quit",
        "__import__", "memoryview", "globals", "locals", "input"
    })
    banned_attributes: Set[str] = field(default_factory=lambda: {
        "__class__", "__base__", "__bases__", "__subclasses__", "__mro__",
        "__globals__", "__code__", "__builtins__", "__import__", "__dict__",
        "__qualname__", "__module__", "func_globals", "func_code"
    })


@dataclass
class SandboxExecutionResult:
    """沙箱执行产出结构体"""
    execution_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    status: SandboxStatus = SandboxStatus.SUCCESS
    return_value: Any = None
    stdout: str = ""
    stderr: str = ""
    execution_time_ms: float = 0.0
    memory_peak_mb: float = 0.0
    violations: List[SecurityViolation] = field(default_factory=list)
    isolation_tier: str = "none"               # "ast_gate", "micro_jail", "subprocess", "docker"
    exit_code: int = 0
    executed_at: datetime = field(default_factory=datetime.now)

    @property
    def is_success(self) -> bool:
        return self.status == SandboxStatus.SUCCESS
