"""Plugin registry for automatic discovery and loading of plugins."""

import importlib
import inspect
from pathlib import Path
from typing import Any, Optional, Type

from rich.console import Console

from .base import BasePlugin, PluginInfo, PluginStatus, PluginConfig, AttackCategory

console = Console()


class PluginRegistry:
    """Registry for managing OWASP LLM risk plugins."""

    def __init__(self):
        """Initialize the plugin registry."""
        self._plugins: dict[str, BasePlugin] = {}
        self._plugin_classes: dict[str, Type[BasePlugin]] = {}
        self._categories: dict[AttackCategory, list[str]] = {
            cat: [] for cat in AttackCategory
        }

    def register(self, plugin_class: Type[BasePlugin], config: Optional[PluginConfig] = None) -> str:
        """Register a plugin class.

        Args:
            plugin_class: The plugin class to register.
            config: Optional configuration for the plugin.

        Returns:
            The registered plugin ID.

        Raises:
            ValueError: If plugin class is invalid or already registered.
        """
        if not inspect.isclass(plugin_class):
            raise ValueError(f"Expected a class, got {type(plugin_class)}")

        if not issubclass(plugin_class, BasePlugin):
            raise ValueError(f"{plugin_class.__name__} must be a subclass of BasePlugin")

        # Create instance to get metadata
        instance = plugin_class(config)
        plugin_id = instance.id

        if plugin_id in self._plugins:
            console.print(f"[yellow]Warning:[/yellow] Plugin {plugin_id} already registered, replacing")

        self._plugins[plugin_id] = instance
        self._plugin_classes[plugin_id] = plugin_class
        self._categories[instance.category].append(plugin_id)

        console.print(f"[green]✓[/green] Registered plugin: {plugin_id} ({instance.name})")
        return plugin_id

    def unregister(self, plugin_id: str) -> bool:
        """Unregister a plugin.

        Args:
            plugin_id: The plugin ID to unregister.

        Returns:
            True if plugin was unregistered, False if not found.
        """
        if plugin_id not in self._plugins:
            return False

        plugin = self._plugins[plugin_id]
        category = plugin.category
        self._categories[category].remove(plugin_id)

        del self._plugins[plugin_id]
        del self._plugin_classes[plugin_id]

        return True

    def get_plugin(self, plugin_id: str) -> Optional[BasePlugin]:
        """Get a plugin by ID.

        Args:
            plugin_id: The plugin ID.

        Returns:
            The plugin instance, or None if not found.
        """
        return self._plugins.get(plugin_id)

    def get_plugins_by_category(self, category: AttackCategory) -> list[BasePlugin]:
        """Get all plugins for a specific category.

        Args:
            category: The OWASP LLM category.

        Returns:
            List of plugins for the category.
        """
        plugin_ids = self._categories.get(category, [])
        return [self._plugins[pid] for pid in plugin_ids if pid in self._plugins]

    def get_all_plugins(self) -> list[BasePlugin]:
        """Get all registered plugins.

        Returns:
            List of all plugins.
        """
        return list(self._plugins.values())

    def get_enabled_plugins(self) -> list[BasePlugin]:
        """Get all enabled plugins.

        Returns:
            List of enabled plugins.
        """
        return [p for p in self._plugins.values() if p.status == PluginStatus.ENABLED]

    def get_plugin_info(self, plugin_id: str) -> Optional[PluginInfo]:
        """Get plugin metadata.

        Args:
            plugin_id: The plugin ID.

        Returns:
            Plugin info, or None if not found.
        """
        plugin = self.get_plugin(plugin_id)
        return plugin.info if plugin else None

    def list_plugins(self) -> list[dict[str, Any]]:
        """List all registered plugins with their metadata.

        Returns:
            List of plugin metadata dictionaries.
        """
        result = []
        for plugin in self._plugins.values():
            result.append({
                "id": plugin.id,
                "name": plugin.name,
                "category": plugin.category.value,
                "status": plugin.status.value,
                "description": plugin.info.description,
            })
        return result

    def auto_discover(self, package_path: Optional[str] = None) -> int:
        """Auto-discover and register plugins from a package.

        Scans the plugins directory for plugin classes and registers them.

        Args:
            package_path: Path to the plugins package. Defaults to src.plugins.

        Returns:
            Number of plugins discovered and registered.
        """
        if package_path is None:
            package_path = str(Path(__file__).parent)

        discovered = 0
        plugins_dir = Path(package_path)

        if not plugins_dir.exists():
            console.print(f"[yellow]Warning:[/yellow] Plugins directory not found: {plugins_dir}")
            return 0

        # Scan for plugin modules
        for module_path in plugins_dir.iterdir():
            if module_path.is_dir() and not module_path.name.startswith("_"):
                # Try to import plugin from subdirectory
                module_name = module_path.name
                try:
                    full_module_name = f"src.plugins.{module_name}.plugin"
                    module = importlib.import_module(full_module_name)

                    # Find plugin classes in the module
                    for name, obj in inspect.getmembers(module, inspect.isclass):
                        if (issubclass(obj, BasePlugin) and
                            obj is not BasePlugin and
                            obj.__module__ == full_module_name):
                            try:
                                self.register(obj)
                                discovered += 1
                            except Exception as e:
                                console.print(f"[red]Error registering {name}:[/red] {e}")

                except ImportError as e:
                    # Module doesn't exist or has import errors - skip
                    pass
                except Exception as e:
                    console.print(f"[red]Error scanning {module_name}:[/red] {e}")

        console.print(f"[green]✓[/green] Auto-discovered {discovered} plugins")
        return discovered

    def configure_plugin(self, plugin_id: str, config: PluginConfig) -> bool:
        """Configure a registered plugin.

        Args:
            plugin_id: The plugin ID.
            config: New configuration.

        Returns:
            True if configured, False if plugin not found.
        """
        if plugin_id not in self._plugin_classes:
            return False

        # Re-register with new config
        plugin_class = self._plugin_classes[plugin_id]
        self._plugins[plugin_id] = plugin_class(config)
        return True

    def enable_plugin(self, plugin_id: str) -> bool:
        """Enable a plugin.

        Args:
            plugin_id: The plugin ID.

        Returns:
            True if enabled, False if not found.
        """
        plugin = self.get_plugin(plugin_id)
        if plugin:
            plugin.enable()
            return True
        return False

    def disable_plugin(self, plugin_id: str) -> bool:
        """Disable a plugin.

        Args:
            plugin_id: The plugin ID.

        Returns:
            True if disabled, False if not found.
        """
        plugin = self.get_plugin(plugin_id)
        if plugin:
            plugin.disable()
            return True
        return False

    def clear(self) -> None:
        """Clear all registered plugins."""
        self._plugins.clear()
        self._plugin_classes.clear()
        for cat in self._categories:
            self._categories[cat] = []

    def __len__(self) -> int:
        """Return number of registered plugins."""
        return len(self._plugins)

    def __contains__(self, plugin_id: str) -> bool:
        """Check if plugin is registered."""
        return plugin_id in self._plugins

    def __iter__(self):
        """Iterate over registered plugins."""
        return iter(self._plugins.values())


# Global registry instance
_global_registry: Optional[PluginRegistry] = None


def get_registry() -> PluginRegistry:
    """Get the global plugin registry.

    Returns:
        The global PluginRegistry instance.
    """
    global _global_registry
    if _global_registry is None:
        _global_registry = PluginRegistry()
    return _global_registry


def register_plugin(plugin_class: Type[BasePlugin], config: Optional[PluginConfig] = None) -> str:
    """Register a plugin with the global registry.

    Args:
        plugin_class: The plugin class to register.
        config: Optional configuration.

    Returns:
        The registered plugin ID.
    """
    return get_registry().register(plugin_class, config)


def get_plugin(plugin_id: str) -> Optional[BasePlugin]:
    """Get a plugin from the global registry.

    Args:
        plugin_id: The plugin ID.

    Returns:
        The plugin instance, or None.
    """
    return get_registry().get_plugin(plugin_id)
