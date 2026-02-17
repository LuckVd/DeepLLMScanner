"""OWASP LLM Top 10 Plugin System."""

from .base import (
    AttackContext,
    AttackResult,
    BasePlugin,
    PluginConfig,
    PluginInfo,
    PluginPriority,
    PluginStatus,
    ScanResult,
)
from .registry import (
    PluginRegistry,
    get_plugin,
    get_registry,
    register_plugin,
)

__all__ = [
    # Base classes
    "BasePlugin",
    "PluginInfo",
    "PluginConfig",
    "PluginPriority",
    "PluginStatus",
    "AttackContext",
    "AttackResult",
    "ScanResult",
    # Registry
    "PluginRegistry",
    "get_registry",
    "get_plugin",
    "register_plugin",
]
