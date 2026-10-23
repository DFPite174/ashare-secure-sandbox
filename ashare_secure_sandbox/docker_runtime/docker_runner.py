"""
Docker 容器沙箱运行桥接器 (Docker Sandbox Runner Bridge)
"""

from __future__ import annotations
import subprocess
import shutil
import time
from pathlib import Path
from typing import Dict, Any, Optional

from ashare_secure_sandbox.contracts import SandboxConfig, SandboxExecutionResult, SandboxStatus
from ashare_secure_sandbox.docker_runtime.container_spec import DockerContainerSpec


class DockerSandboxRunner:
    """
    负责探测并调度 Docker 容器进行硬件级/内核级隔离执行。
    若 Docker 守护进程未启动，则主动感知并支持平滑降级。
    """

    def __init__(self, config: Optional[SandboxConfig] = None):
        self.config = config or SandboxConfig()
        self.spec = DockerContainerSpec()

    @staticmethod
    def is_docker_available() -> bool:
        if not shutil.which("docker"):
            return False
        try:
            res = subprocess.run(
                ["docker", "info", "--format", "{{.ServerVersion}}"],
                capture_output=True,
                text=True,
                timeout=2.0,
            )
            return res.returncode == 0
        except Exception:
            return False

    def execute(
        self,
        script_path: Path,
    ) -> SandboxExecutionResult:
        if not self.is_docker_available():
            raise RuntimeError("Docker daemon is not responsive or not installed.")

        cmd = self.spec.build_docker_run_args(script_path, self.config)
        start_t = time.perf_counter()

        try:
            res = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.config.timeout_sec,
                encoding="utf-8",
                errors="replace",
            )
            elapsed_ms = (time.perf_counter() - start_t) * 1000.0

            if res.returncode != 0:
                return SandboxExecutionResult(
                    status=SandboxStatus.RUNTIME_ERROR,
                    stdout=res.stdout[:self.config.max_output_bytes],
                    stderr=res.stderr[:self.config.max_output_bytes],
                    execution_time_ms=elapsed_ms,
                    isolation_tier="docker",
                    exit_code=res.returncode,
                )

            return SandboxExecutionResult(
                status=SandboxStatus.SUCCESS,
                stdout=res.stdout[:self.config.max_output_bytes],
                stderr=res.stderr[:self.config.max_output_bytes],
                execution_time_ms=elapsed_ms,
                isolation_tier="docker",
                exit_code=0,
            )

        except subprocess.TimeoutExpired:
            elapsed_ms = (time.perf_counter() - start_t) * 1000.0
            return SandboxExecutionResult(
                status=SandboxStatus.TIMEOUT,
                stderr=f"Docker container exceeded timeout limit of {self.config.timeout_sec}s",
                execution_time_ms=elapsed_ms,
                isolation_tier="docker",
                exit_code=-9,
            )
