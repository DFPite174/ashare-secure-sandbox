"""
第二道防线：进程内受限微沙箱 (Tier 2: In-Process Micro-Jail)
"""

from __future__ import annotations
import sys
import io
import time
import threading
from typing import Dict, Any, Optional
import numpy as np
import pandas as pd

from ashare_secure_sandbox.contracts import SandboxConfig, SandboxExecutionResult, SandboxStatus


def create_safe_builtins(config: Optional[SandboxConfig] = None) -> Dict[str, Any]:
    """构造净化的安全内建符号表 (Safe Builtins Dictionary)"""
    safe_names = [
        "range", "len", "sum", "min", "max", "abs", "round", "enumerate",
        "zip", "isinstance", "issubclass", "int", "float", "str", "list",
        "dict", "set", "tuple", "bool", "sorted", "reversed", "filter",
        "map", "all", "any", "slice", "print", "Exception", "ValueError",
        "TypeError", "KeyError", "IndexError", "ZeroDivisionError"
    ]
    builtins_dict = {}
    py_builtins = __builtins__ if isinstance(__builtins__, dict) else __builtins__.__dict__

    for name in safe_names:
        if name in py_builtins:
            builtins_dict[name] = py_builtins[name]

    return builtins_dict


class InProcessMicroJail:
    """
    轻量级进程内受限微沙箱，适用于超高频（亚毫秒级）因子公式或数学运算。
    通过剥离全部危险 Builtins 并注入受限环境实现隔离。
    """

    def __init__(self, config: Optional[SandboxConfig] = None):
        self.config = config or SandboxConfig()

    def execute(
        self,
        code_str: str,
        context: Optional[Dict[str, Any]] = None,
    ) -> SandboxExecutionResult:
        start_t = time.perf_counter()
        stdout_capture = io.StringIO()
        stderr_capture = io.StringIO()

        sandbox_globals: Dict[str, Any] = {
            "__builtins__": create_safe_builtins(self.config),
            "np": np,
            "numpy": np,
            "pd": pd,
            "pandas": pd,
        }
        if context:
            sandbox_globals.update(context)

        result_container: Dict[str, Any] = {}
        error_container: Dict[str, Any] = {}

        def _target():
            old_stdout = sys.stdout
            old_stderr = sys.stderr
            sys.stdout = stdout_capture
            sys.stderr = stderr_capture
            try:
                compiled = compile(code_str, filename="<sandbox_jail>", mode="exec")
                exec(compiled, sandbox_globals)

                if "result" in sandbox_globals:
                    result_container["val"] = sandbox_globals["result"]
                elif "output" in sandbox_globals:
                    result_container["val"] = sandbox_globals["output"]
                else:
                    result_container["val"] = None
            except Exception as e:
                error_container["err"] = e
            finally:
                sys.stdout = old_stdout
                sys.stderr = old_stderr

        worker = threading.Thread(target=_target, daemon=True)
        worker.start()
        worker.join(timeout=self.config.timeout_sec)
        elapsed_ms = (time.perf_counter() - start_t) * 1000.0

        if worker.is_alive():
            return SandboxExecutionResult(
                status=SandboxStatus.TIMEOUT,
                stdout=stdout_capture.getvalue()[:self.config.max_output_bytes],
                stderr=f"Execution exceeded strict timeout of {self.config.timeout_sec}s",
                execution_time_ms=elapsed_ms,
                isolation_tier="micro_jail",
            )

        if "err" in error_container:
            err = error_container["err"]
            return SandboxExecutionResult(
                status=SandboxStatus.RUNTIME_ERROR,
                stdout=stdout_capture.getvalue()[:self.config.max_output_bytes],
                stderr=f"{type(err).__name__}: {str(err)}",
                execution_time_ms=elapsed_ms,
                isolation_tier="micro_jail",
            )

        return SandboxExecutionResult(
            status=SandboxStatus.SUCCESS,
            return_value=result_container.get("val"),
            stdout=stdout_capture.getvalue()[:self.config.max_output_bytes],
            stderr=stderr_capture.getvalue()[:self.config.max_output_bytes],
            execution_time_ms=elapsed_ms,
            isolation_tier="micro_jail",
        )
