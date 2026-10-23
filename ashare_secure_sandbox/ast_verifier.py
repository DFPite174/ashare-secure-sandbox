"""
第一道防线：AST 语法树静态安全门禁 (Tier 1: AST Static Security Gate)
"""

from __future__ import annotations
import ast
from typing import List, Optional, Set
from ashare_secure_sandbox.contracts import SandboxConfig, SecurityViolation


class ASTSecurityChecker(ast.NodeVisitor):
    """
    负责在代码运行前静态扫描抽象语法树 (AST)，
    无死角拦截非法导入、私有反射逃逸、动态执行与内存炸弹代码。
    """

    def __init__(self, config: Optional[SandboxConfig] = None):
        self.config = config or SandboxConfig()
        self.violations: List[SecurityViolation] = []

    def check(self, code_str: str) -> List[SecurityViolation]:
        """全量扫描 Python 代码，返回违规行为列表"""
        self.violations = []
        try:
            tree = ast.parse(code_str)
        except SyntaxError as e:
            self.violations.append(SecurityViolation(
                violation_type="SYNTAX_ERROR",
                message=f"代码包含无法解析的语法错误: {e.msg}",
                line_number=e.lineno,
                severity="CRITICAL",
            ))
            return self.violations

        self.visit(tree)
        return self.violations

    def visit_Import(self, node: ast.Import):
        for alias in node.names:
            base_mod = alias.name.split(".")[0]
            if base_mod in self.config.banned_modules:
                self.violations.append(SecurityViolation(
                    violation_type="FORBIDDEN_IMPORT",
                    message=f"严禁导入受限的高危系统模块: '{alias.name}'",
                    line_number=node.lineno,
                    node_repr=f"import {alias.name}",
                ))
            elif self.config.allowed_modules and base_mod not in self.config.allowed_modules:
                self.violations.append(SecurityViolation(
                    violation_type="UNAUTHORIZED_MODULE",
                    message=f"未授权导入模块: '{alias.name}' (仅允许标准量化白名单)",
                    line_number=node.lineno,
                    node_repr=f"import {alias.name}",
                ))
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom):
        if node.module:
            base_mod = node.module.split(".")[0]
            if base_mod in self.config.banned_modules:
                self.violations.append(SecurityViolation(
                    violation_type="FORBIDDEN_IMPORT",
                    message=f"严禁从受限系统模块中提取符号: from '{node.module}'",
                    line_number=node.lineno,
                    node_repr=f"from {node.module} import ...",
                ))
            elif self.config.allowed_modules and base_mod not in self.config.allowed_modules:
                self.violations.append(SecurityViolation(
                    violation_type="UNAUTHORIZED_MODULE",
                    message=f"未授权导入模块: from '{node.module}'",
                    line_number=node.lineno,
                    node_repr=f"from {node.module} import ...",
                ))
        self.generic_visit(node)

    def visit_Attribute(self, node: ast.Attribute):
        attr_name = node.attr
        if attr_name in self.config.banned_attributes:
            self.violations.append(SecurityViolation(
                violation_type="DUNDER_ACCESS",
                message=f"严禁访问内省或元编程私有属性: '.{attr_name}' (可能尝试沙箱逃逸)",
                line_number=node.lineno,
                node_repr=f".{attr_name}",
            ))
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call):
        func_name = None
        if isinstance(node.func, ast.Name):
            func_name = node.func.id
        elif isinstance(node.func, ast.Attribute):
            func_name = node.func.attr

        if func_name and func_name in self.config.banned_builtins:
            self.violations.append(SecurityViolation(
                violation_type="DANGEROUS_BUILTIN",
                message=f"严禁调用危险内置函数: '{func_name}'",
                line_number=node.lineno,
                node_repr=f"{func_name}(...)",
            ))

        if func_name in ("getattr", "hasattr", "setattr", "delattr") and node.args:
            if len(node.args) >= 2 and isinstance(node.args[1], ast.Constant):
                target_attr = str(node.args[1].value)
                if target_attr in self.config.banned_attributes or target_attr in self.config.banned_builtins:
                    self.violations.append(SecurityViolation(
                        violation_type="OBFUSCATED_REFLECTION",
                        message=f"严禁利用反射函数动态调用受限属性: '{target_attr}'",
                        line_number=node.lineno,
                        node_repr=f"{func_name}(..., '{target_attr}')",
                    ))

        self.generic_visit(node)

    def visit_BinOp(self, node: ast.BinOp):
        if isinstance(node.op, ast.Mult):
            multiplier = None
            if isinstance(node.right, ast.Constant) and isinstance(node.right.value, (int, float)):
                multiplier = node.right.value
            elif isinstance(node.left, ast.Constant) and isinstance(node.left.value, (int, float)):
                multiplier = node.left.value

            if multiplier and multiplier > 5000000:
                self.violations.append(SecurityViolation(
                    violation_type="RESOURCE_ABUSE",
                    message=f"检测到潜在的巨额内存乘积炸弹 (乘数 {multiplier:,.0f} > 5,000,000)",
                    line_number=node.lineno,
                    node_repr="... * <huge multiplier>",
                ))

        self.generic_visit(node)
