"""
Docker 加固容器规格与 SandboxManager 总控端到端测试
"""

import pytest
from pathlib import Path
import pandas as pd
from ashare_secure_sandbox.contracts import SandboxConfig, SandboxStatus, RuntimeMode
from ashare_secure_sandbox.docker_runtime.container_spec import DockerContainerSpec
from ashare_secure_sandbox.manager.sandbox_manager import SandboxManager


def test_docker_container_spec_generation():
    spec = DockerContainerSpec()
    cfg = SandboxConfig(memory_limit_mb=256.0)
    fake_script = Path("C:/dummy/run.py")

    args = spec.build_docker_run_args(fake_script, cfg)

    assert "docker" in args
    assert "--network=none" in args
    assert "--read-only" in args
    assert "--cap-drop=ALL" in args
    assert "--security-opt=no-new-privileges" in args
    assert "--pids-limit=64" in args
    assert "--memory=256m" in args

    df_content = spec.generate_dockerfile_content()
    assert "FROM python:3.12-slim" in df_content
    assert "sandboxuser" in df_content


def test_sandbox_manager_end_to_end_benign_quant_code():
    manager = SandboxManager(SandboxConfig(timeout_sec=3.0))

    code = """
import numpy as np
import pandas as pd

closes = [10.0, 10.5, 11.0, 10.8, 11.2]
ret = (closes[-1] - closes[0]) / closes[0]
result = round(ret, 4)
"""
    res = manager.execute(code)
    assert res.is_success
    assert abs(res.return_value - 0.12) < 1e-4

    logs = manager.get_audit_log()
    assert len(logs) >= 1
    assert logs[-1].status == SandboxStatus.SUCCESS


def test_sandbox_manager_intercepts_prompt_injection_attack():
    manager = SandboxManager()

    malicious_injection = """
import os
import shutil
os.system("rm -rf /")
shutil.rmtree("data/storage")
"""
    res = manager.execute(malicious_injection)

    assert not res.is_success
    assert res.status == SandboxStatus.SECURITY_VIOLATION
    assert len(res.violations) >= 2
    assert res.isolation_tier == "ast_gate"
    assert any("os" in v.message for v in res.violations)
    assert any("shutil" in v.message for v in res.violations)

    logs = manager.get_audit_log()
    assert logs[-1].status == SandboxStatus.SECURITY_VIOLATION


def test_sandbox_manager_factor_evaluation_helper():
    manager = SandboxManager()
    df = pd.DataFrame({
        "trade_date": ["2025-01-02", "2025-01-03", "2025-01-06"],
        "close": [10.0, 11.0, 12.0],
    })

    factor_code = """
closes = bars_df['close']
diff = closes.iloc[-1] - closes.iloc[0]
result = float(diff)
"""
    res = manager.execute_factor_code(factor_code, df, factor_name="test_diff")
    assert res.is_success
    assert res.return_value == 2.0
