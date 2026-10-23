"""
第四道防线：OCI / Docker 容器强化规范生成器 (Tier 4: OCI Container Spec)
"""

from __future__ import annotations
from dataclasses import dataclass
from typing import List, Dict, Optional
from pathlib import Path

from ashare_secure_sandbox.contracts import SandboxConfig


@dataclass
class DockerContainerSpec:
    """Docker 强化容器规格生成器"""

    image_name: str = "ashare-quant-sandbox:latest"
    base_image: str = "python:3.12-slim"

    @staticmethod
    def generate_dockerfile_content() -> str:
        """生成生产级无特权极简量化沙箱基础镜像 Dockerfile"""
        return """# CIS Hardened Minimal Quant Sandbox Image
FROM python:3.12-slim

RUN groupadd -g 10001 sandboxgroup && \\
    useradd -u 10001 -g sandboxgroup -m -s /sbin/nologin sandboxuser

RUN pip install --no-cache-dir numpy pandas scipy

USER sandboxuser
WORKDIR /home/sandboxuser/workspace

ENTRYPOINT ["python", "-I"]
"""

    def build_docker_run_args(
        self,
        script_host_path: Path,
        config: SandboxConfig,
        container_mount_dir: str = "/home/sandboxuser/workspace",
    ) -> List[str]:
        script_dir = script_host_path.parent
        script_name = script_host_path.name

        args = [
            "docker", "run", "--rm",
            "--network=none",
            "--read-only",
            "--tmpfs", f"{container_mount_dir}/tmp:rw,noexec,nosuid,size=64m",
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges",
            f"--memory={int(config.memory_limit_mb)}m",
            f"--cpus=1.0",
            "--pids-limit=64",
            "-v", f"{script_dir}:{container_mount_dir}:ro",
            "-w", container_mount_dir,
            self.image_name,
            f"{container_mount_dir}/{script_name}"
        ]
        return args
