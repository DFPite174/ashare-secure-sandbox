"""
Micro-Jail 与独立 Subprocess 沙箱运行时单元测试
"""

import pytest
import os
import time
from ashare_secure_sandbox.contracts import SandboxConfig, SandboxStatus
from ashare_secure_sandbox.jail import InProcessMicroJail
from ashare_secure_sandbox.subprocess_runner import SubprocessSandboxRunner


def test_micro_jail_basic_execution():
    jail = InProcessMicroJail(SandboxConfig(timeout_sec=2.0))
    code = """
a = 10
b = 20
result = a + b
"""
    res = jail.execute(code)
    assert res.is_success
    assert res.return_value == 30
    assert res.isolation_tier == "micro_jail"


def test_micro_jail_runtime_error_trapping():
    jail = InProcessMicroJail()
    code = "x = 1 / 0"
    res = jail.execute(code)
    assert res.status == SandboxStatus.RUNTIME_ERROR
    assert "ZeroDivisionError" in res.stderr


def test_micro_jail_timeout_kill():
    jail = InProcessMicroJail(SandboxConfig(timeout_sec=0.2))
    code = """
x = 0
while True:
    x += 1
"""
    res = jail.execute(code)
    assert res.status == SandboxStatus.TIMEOUT
    assert "timeout" in res.stderr.lower()


def test_subprocess_runner_basic_execution():
    runner = SubprocessSandboxRunner(SandboxConfig(timeout_sec=3.0))
    code = """
import numpy as np
arr = [1, 2, 3, 4]
result = sum(arr)
print("computed sum successfully")
"""
    res = runner.execute(code)
    assert res.is_success
    assert res.return_value == 10
    assert "computed sum successfully" in res.stdout
    assert res.isolation_tier == "subprocess"


def test_subprocess_runner_timeout_kill():
    runner = SubprocessSandboxRunner(SandboxConfig(timeout_sec=0.3))
    code = """
import time
while True:
    time.sleep(0.05)
"""
    res = runner.execute(code)
    assert res.status == SandboxStatus.TIMEOUT
    assert "timeout limit" in res.stderr


def test_subprocess_runner_env_sanitization():
    os.environ["MOCK_TUSHARE_TOKEN_SECRET"] = "secret_key_12345"
    runner = SubprocessSandboxRunner()

    code = """
import os
token = os.environ.get("MOCK_TUSHARE_TOKEN_SECRET")
result = token is None
"""
    res = runner.execute(code)
    assert res.is_success
    assert res.return_value is True
