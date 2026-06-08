"""dependency-jail — Supply-chain network sandbox for package installations."""

__version__ = "1.0.0"
__author__  = "dependency-jail contributors"
__license__ = "MIT"

from dep_jail.core     import JailRunner, JailResult, compile_interceptor
from dep_jail.resolver import RegistryResolver

__all__ = [
    "JailRunner",
    "JailResult",
    "compile_interceptor",
    "RegistryResolver",
]
