"""
AST 语法树静态安全门禁单元测试
"""

import pytest
from ashare_secure_sandbox.contracts import SandboxConfig
from ashare_secure_sandbox.ast_verifier import ASTSecurityChecker


def test_valid_quant_code_passes():
    checker = ASTSecurityChecker()
    valid_code = """
import numpy as np
import pandas as pd

def calculate_factor(close_series, window=20):
    ma = close_series.rolling(window).mean()
    std = close_series.rolling(window).std()
    z_score = (close_series - ma) / (std + 1e-8)
    return z_score

result = calculate_factor(pd.Series([10.0, 11.0, 12.0]))
"""
    violations = checker.check(valid_code)
    assert len(violations) == 0


def test_forbidden_system_imports_intercepted():
    checker = ASTSecurityChecker()

    malicious_scripts = [
        "import os\nos.system('echo hacked')",
        "import sys\nsys.exit(1)",
        "import subprocess\nsubprocess.run(['ls'])",
        "import socket\ns = socket.socket()",
        "import ctypes\nctypes.CDLL(None)",
        "from os import popen\npopen('whoami')",
        "from subprocess import Popen",
    ]

    for script in malicious_scripts:
        violations = checker.check(script)
        assert len(violations) >= 1
        assert any(v.violation_type == "FORBIDDEN_IMPORT" for v in violations)


def test_dunder_reflection_escapes_intercepted():
    checker = ASTSecurityChecker()

    escape_scripts = [
        "x = ().__class__.__base__.__subclasses__()",
        "g = f.__globals__['os']",
        "c = func.__code__",
        "b = obj.__builtins__",
    ]

    for script in escape_scripts:
        violations = checker.check(script)
        assert len(violations) >= 1
        assert any(v.violation_type == "DUNDER_ACCESS" for v in violations)


def test_dangerous_builtins_intercepted():
    checker = ASTSecurityChecker()

    dangerous_calls = [
        "eval('1 + 1')",
        "exec('a = 1')",
        "open('/etc/passwd', 'r')",
        "compile('x = 1', '<string>', 'exec')",
    ]

    for script in dangerous_calls:
        violations = checker.check(script)
        assert len(violations) >= 1
        assert any(v.violation_type == "DANGEROUS_BUILTIN" for v in violations)


def test_obfuscated_getattr_intercepted():
    checker = ASTSecurityChecker()
    obfuscated_code = "getattr(object, '__subclasses__')()"
    violations = checker.check(obfuscated_code)
    assert len(violations) >= 1
    assert any(v.violation_type in ("OBFUSCATED_REFLECTION", "DUNDER_ACCESS") for v in violations)


def test_memory_bomb_multiplier_intercepted():
    checker = ASTSecurityChecker()
    bomb_code = "bomb = [0] * 100000000"
    violations = checker.check(bomb_code)
    assert len(violations) >= 1
    assert any(v.violation_type == "RESOURCE_ABUSE" for v in violations)
