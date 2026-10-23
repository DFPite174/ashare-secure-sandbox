# ashare-secure-sandbox (企业级 A 股代码安全沙箱与容器隔离中枢)

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Defense-in-Depth](https://img.shields.io/badge/Security-Multi--Tier--Defense-green.svg)]()

> 面向自主进化量化投研（RD-Agent / LLM 生成代码）的五层深度防御安全沙箱与轻量容器隔离引擎。

---

## 🌟 理论根基与工业参考

1. **Firecracker NSDI 2020** (*Agache et al.*): 极简轻量级微虚拟化、Jailer 进程隔离、严格 seccomp 系统调用过滤与 cgroups 资源限额。
2. **Google gVisor ATC 2019**: 系统调用虚拟化与无特权拦截架构，防范内核提权与容器逃逸。
3. **NIST SP 800-190 & CIS Docker Benchmark**: `--network=none`, `--read-only`, `--cap-drop=ALL`, `--security-opt=no-new-privileges`, `--pids-limit=64`。

---

## 🛡️ 五层深度防御架构 (5-Tier Defense-in-Depth)

1. **Tier 1: AST 语法树静态安全门禁 (`ast_verifier.py`)**：在代码运行前静态扫描抽象语法树，毫秒级阻断高危模块导入 (`os`, `sys`, `subprocess`, `socket`, `ctypes`)、双下划线私有反射逃逸 (`__subclasses__`, `__globals__`, `__mro__`)、危险内建函数调用 (`eval`, `exec`, `open`) 与内存乘积炸弹。
2. **Tier 2: 进程内受限微沙箱 (`jail.py`)**：剥离危险 Builtins，提供纯净数学计算上下文与线程级硬超时熔断。
3. **Tier 3: 独立无特权子进程沙箱 (`subprocess_runner.py`)**：使用 Python `-I` 隔离模式，全量剥离敏感凭据环境变量，动态监控物理内存峰值（RSS）与进程树强杀。
4. **Tier 4: OCI / Docker 加固容器运行时 (`docker_runtime/`)**：生成只读根文件系统、零网络、全能力剥离的生产容器规格，支持 Docker 守护进程活跃探测与平滑降级。
5. **Tier 5: 沙箱调度与安全总控 (`manager/sandbox_manager.py`)**：统一多层调度 API，提供完整的安全审计事件快照与违规拦截分析。

---

## 📦 安装与快速开始

```bash
pip install -e .
```

```python
from ashare_secure_sandbox import SandboxManager, SandboxConfig

manager = SandboxManager(SandboxConfig(timeout_sec=3.0))

# 安全运行正常量化策略/因子
result = manager.execute(\"\"\"
import numpy as np
ret = np.mean([0.01, -0.02, 0.03])
result = float(ret)
\"\"\")
print(result.status, result.return_value) # SUCCESS, 0.006666...

# 自动阻断 prompt injection 与恶意逃逸
malicious = manager.execute(\"\"\"
import os
os.system("rm -rf /")
\"\"\")
print(malicious.status) # SECURITY_VIOLATION
```
