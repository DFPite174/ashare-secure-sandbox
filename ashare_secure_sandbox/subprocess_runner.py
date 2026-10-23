"""
第三道防线：独立无特权子进程沙箱 (Tier 3: Isolated Subprocess Sandbox)
"""

from __future__ import annotations
import os
import sys
import json
import time
import shutil
import tempfile
import subprocess
from pathlib import Path
from typing import Dict, Any, Optional
import psutil
import pandas as pd

from ashare_secure_sandbox.contracts import SandboxConfig, SandboxExecutionResult, SandboxStatus


class SubprocessSandboxRunner:
    """
    负责在完全独立、环境脱敏的 OS 子进程中运行不可信代码。
    具备环境变数剥离、临时空间自动粉碎、内存峰值监控与超时强杀能力。
    """

    def __init__(self, config: Optional[SandboxConfig] = None):
        self.config = config or SandboxConfig()

    def _build_sanitized_env(self) -> Dict[str, str]:
        """构建剥离所有敏感凭据与 API Key 的极简环境变量"""
        safe_env = {
            "PYTHONIOENCODING": "utf-8",
            "PYTHONUTF8": "1",
            "PYTHONUNBUFFERED": "1",
        }
        for key in ("SYSTEMROOT", "WINDIR", "PATH", "TEMP", "TMP"):
            if key in os.environ:
                safe_env[key] = os.environ[key]

        return safe_env

    def execute(
        self,
        code_str: str,
        context: Optional[Dict[str, Any]] = None,
    ) -> SandboxExecutionResult:
        start_t = time.perf_counter()

        with tempfile.TemporaryDirectory(prefix="ashare_sandbox_") as tmp_dir_str:
            tmp_dir = Path(tmp_dir_str)
            script_path = tmp_dir / "user_script.py"
            input_data_path = tmp_dir / "input_context.json"
            output_data_path = tmp_dir / "output_result.json"

            # 序列化输入数据 (支持基础标量、字典、列表、Pandas DataFrame 与 Series)
            clean_context = context or {}
            serializable_context = {}
            for k, v in clean_context.items():
                if isinstance(v, pd.DataFrame):
                    serializable_context[k] = {
                        "__dtype__": "dataframe",
                        "data": v.to_dict(orient="list"),
                    }
                elif isinstance(v, pd.Series):
                    serializable_context[k] = {
                        "__dtype__": "series",
                        "data": v.to_list(),
                        "name": str(v.name) if v.name else None,
                    }
                else:
                    try:
                        json.dumps(v)
                        serializable_context[k] = v
                    except Exception:
                        serializable_context[k] = str(v)

            input_data_path.write_text(json.dumps(serializable_context, ensure_ascii=False), encoding="utf-8")

            # 构造隔离引导执行器代码
            wrapper_code = f"""# -*- coding: utf-8 -*-
import json
import sys
from pathlib import Path
import numpy as np
import pandas as pd

# 读取输入
with open(r"{input_data_path}", "r", encoding="utf-8") as f:
    context_data = json.load(f)

# 注入全局作用域并反序列化 Pandas 结构
for k, v in context_data.items():
    if isinstance(v, dict) and v.get("__dtype__") == "dataframe":
        globals()[k] = pd.DataFrame(v["data"])
    elif isinstance(v, dict) and v.get("__dtype__") == "series":
        globals()[k] = pd.Series(v["data"], name=v.get("name"))
    else:
        globals()[k] = v

# 执行用户代码
result = None
output = None

{code_str}

# 搜集返回值
final_val = result if result is not None else output
if final_val is not None:
    try:
        with open(r"{output_data_path}", "w", encoding="utf-8") as f:
            json.dump({{"return_value": final_val}}, f, ensure_ascii=False)
    except Exception as e:
        with open(r"{output_data_path}", "w", encoding="utf-8") as f:
            json.dump({{"return_value": str(final_val)}}, f, ensure_ascii=False)
"""
            script_path.write_text(wrapper_code, encoding="utf-8")

            sanitized_env = self._build_sanitized_env()
            python_exe = sys.executable

            cmd = [python_exe, "-I", str(script_path)]

            proc = subprocess.Popen(
                cmd,
                cwd=str(tmp_dir),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=sanitized_env,
                text=True,
                encoding="utf-8",
                errors="replace",
            )

            peak_memory_mb = 0.0
            is_timeout = False
            is_oom = False

            try:
                poll_interval = 0.05
                deadline = time.time() + self.config.timeout_sec

                while True:
                    if proc.poll() is not None:
                        break

                    now = time.time()
                    if now > deadline:
                        is_timeout = True
                        break

                    try:
                        p = psutil.Process(proc.pid)
                        mem_info = p.memory_info()
                        mem_mb = mem_info.rss / 1024.0 / 1024.0
                        if mem_mb > peak_memory_mb:
                            peak_memory_mb = mem_mb

                        if mem_mb > self.config.memory_limit_mb:
                            is_oom = True
                            break
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass

                    time.sleep(poll_interval)

            except Exception:
                pass

            if is_timeout or is_oom:
                try:
                    parent = psutil.Process(proc.pid)
                    for child in parent.children(recursive=True):
                        child.kill()
                    parent.kill()
                except Exception:
                    proc.kill()

                proc.wait()
                elapsed_ms = (time.perf_counter() - start_t) * 1000.0

                if is_timeout:
                    return SandboxExecutionResult(
                        status=SandboxStatus.TIMEOUT,
                        stderr=f"Subprocess exceeded hard timeout limit of {self.config.timeout_sec:.2f}s",
                        execution_time_ms=elapsed_ms,
                        memory_peak_mb=peak_memory_mb,
                        isolation_tier="subprocess",
                        exit_code=-9,
                    )
                else:
                    return SandboxExecutionResult(
                        status=SandboxStatus.OOM_KILLED,
                        stderr=f"Subprocess exceeded hard memory limit of {self.config.memory_limit_mb:.1f}MB (Peak: {peak_memory_mb:.1f}MB)",
                        execution_time_ms=elapsed_ms,
                        memory_peak_mb=peak_memory_mb,
                        isolation_tier="subprocess",
                        exit_code=-9,
                    )

            stdout, stderr = proc.communicate()
            elapsed_ms = (time.perf_counter() - start_t) * 1000.0

            return_val = None
            if output_data_path.exists():
                try:
                    out_json = json.loads(output_data_path.read_text(encoding="utf-8"))
                    return_val = out_json.get("return_value")
                except Exception:
                    pass

            if proc.returncode != 0:
                return SandboxExecutionResult(
                    status=SandboxStatus.RUNTIME_ERROR,
                    stdout=stdout[:self.config.max_output_bytes],
                    stderr=stderr[:self.config.max_output_bytes],
                    return_value=return_val,
                    execution_time_ms=elapsed_ms,
                    memory_peak_mb=peak_memory_mb,
                    isolation_tier="subprocess",
                    exit_code=proc.returncode,
                )

            return SandboxExecutionResult(
                status=SandboxStatus.SUCCESS,
                stdout=stdout[:self.config.max_output_bytes],
                stderr=stderr[:self.config.max_output_bytes],
                return_value=return_val,
                execution_time_ms=elapsed_ms,
                memory_peak_mb=peak_memory_mb,
                isolation_tier="subprocess",
                exit_code=0,
            )
