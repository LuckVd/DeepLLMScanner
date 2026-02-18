"""Template loader and attack generator."""

import re
import uuid
from pathlib import Path
from typing import Any, Iterator, Optional

import yaml
from rich.console import Console

from .models import (
    AttackCategory,
    AttackPayload,
    AttackSeverity,
    AttackTemplate,
    GeneratedAttack,
)

console = Console()

# Variable pattern: {{variable_name}}
VARIABLE_PATTERN = re.compile(r"\{\{(\w+)\}\}")


class TemplateLoader:
    """Loads attack templates from YAML files."""

    def __init__(self, templates_dir: Optional[Path] = None):
        """Initialize the template loader.

        Args:
            templates_dir: Directory containing YAML templates.
                          Defaults to built-in templates directory.
        """
        if templates_dir is None:
            templates_dir = Path(__file__).parent / "templates"
        self.templates_dir = Path(templates_dir)
        self._templates: dict[str, AttackTemplate] = {}
        self._loaded = False

    def load(self) -> dict[str, AttackTemplate]:
        """Load all templates from the templates directory.

        Returns:
            Dictionary of template ID to AttackTemplate.
        """
        if self._loaded:
            return self._templates

        if not self.templates_dir.exists():
            console.print(
                f"[yellow]Warning:[/yellow] Templates directory not found: {self.templates_dir}"
            )
            self._loaded = True
            return self._templates

        for yaml_file in self.templates_dir.glob("*.yaml"):
            try:
                self._load_yaml_file(yaml_file)
            except Exception as e:
                console.print(f"[red]Error loading {yaml_file}:[/red] {e}")

        self._loaded = True
        console.print(f"[green]+[/green] Loaded {len(self._templates)} attack templates")
        return self._templates

    def _load_yaml_file(self, filepath: Path) -> None:
        """Load a single YAML template file.

        Args:
            filepath: Path to the YAML file.
        """
        with open(filepath, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)

        if not data:
            return

        # Handle single template or list of templates
        templates_data = data if isinstance(data, list) else [data]

        for template_data in templates_data:
            template = self._parse_template(template_data, filepath)
            if template:
                self._templates[template.id] = template

    def _parse_template(
        self, data: dict[str, Any], filepath: Path
    ) -> Optional[AttackTemplate]:
        """Parse template data from YAML.

        Args:
            data: Raw template data from YAML.
            filepath: Source file path for reference.

        Returns:
            Parsed AttackTemplate or None if invalid.
        """
        if not data:
            return None

        # Parse category
        category_str = data.get("category", "LLM01")
        try:
            category = AttackCategory(category_str)
        except ValueError:
            category = AttackCategory.LLM01_PROMPT_INJECTION

        # Parse severity
        severity_str = data.get("severity", "medium").lower()
        try:
            severity = AttackSeverity(severity_str)
        except ValueError:
            severity = AttackSeverity.MEDIUM

        # Generate ID if not provided
        template_id = data.get("id") or data.get("name", "").lower().replace(" ", "_")

        return AttackTemplate(
            id=template_id,
            name=data.get("name", "Unnamed Template"),
            category=category,
            description=data.get("description", ""),
            severity=severity,
            tags=data.get("tags", []),
            templates=data.get("templates", []),
            variables=data.get("variables", {}),
            source=data.get("source"),
            references=data.get("references", []),
            author=data.get("author"),
            version=data.get("version", "1.0"),
        )

    def get_template(self, template_id: str) -> Optional[AttackTemplate]:
        """Get a specific template by ID.

        Args:
            template_id: Template identifier.

        Returns:
            AttackTemplate or None if not found.
        """
        if not self._loaded:
            self.load()
        return self._templates.get(template_id)

    def get_templates_by_category(
        self, category: AttackCategory
    ) -> list[AttackTemplate]:
        """Get all templates for a specific category.

        Args:
            category: OWASP LLM category.

        Returns:
            List of matching templates.
        """
        if not self._loaded:
            self.load()
        return [t for t in self._templates.values() if t.category == category]

    def get_all_templates(self) -> list[AttackTemplate]:
        """Get all loaded templates.

        Returns:
            List of all templates.
        """
        if not self._loaded:
            self.load()
        return list(self._templates.values())

    def reload(self) -> dict[str, AttackTemplate]:
        """Reload all templates from disk.

        Returns:
            Dictionary of reloaded templates.
        """
        self._templates.clear()
        self._loaded = False
        return self.load()


class AttackGenerator:
    """Generates attack payloads from templates."""

    def __init__(self, loader: Optional[TemplateLoader] = None):
        """Initialize the attack generator.

        Args:
            loader: Template loader instance. Creates default if not provided.
        """
        self.loader = loader or TemplateLoader()

    def generate(
        self,
        template_id: str,
        variables: Optional[dict[str, str]] = None,
    ) -> list[GeneratedAttack]:
        """Generate attacks from a specific template.

        Args:
            template_id: Template to use for generation.
            variables: Variable values to substitute.

        Returns:
            List of generated attacks.
        """
        template = self.loader.get_template(template_id)
        if not template:
            console.print(f"[red]Template not found:[/red] {template_id}")
            return []

        return self._generate_from_template(template, variables or {})

    def generate_category(
        self,
        category: AttackCategory,
        variables: Optional[dict[str, str]] = None,
    ) -> Iterator[GeneratedAttack]:
        """Generate attacks for all templates in a category.

        Args:
            category: OWASP LLM category.
            variables: Variable values to substitute.

        Yields:
            GeneratedAttack instances.
        """
        templates = self.loader.get_templates_by_category(category)
        for template in templates:
            yield from self._generate_from_template(template, variables or {})

    def generate_all(
        self,
        variables: Optional[dict[str, str]] = None,
    ) -> Iterator[GeneratedAttack]:
        """Generate attacks from all templates.

        Args:
            variables: Variable values to substitute.

        Yields:
            GeneratedAttack instances.
        """
        for template in self.loader.get_all_templates():
            yield from self._generate_from_template(template, variables or {})

    def _generate_from_template(
        self,
        template: AttackTemplate,
        variables: dict[str, str],
    ) -> list[GeneratedAttack]:
        """Generate attacks from a template.

        Args:
            template: Template to use.
            variables: Variable values to substitute.

        Returns:
            List of generated attacks.
        """
        attacks = []

        # Merge template defaults with provided variables
        final_vars = template.get_variable_defaults()
        final_vars.update(variables)

        # Generate variable combinations
        var_combinations = self._generate_variable_combinations(template.variables, final_vars)

        for template_str in template.templates:
            for var_combo in var_combinations:
                payload = self._substitute_variables(template_str, var_combo)

                attack = GeneratedAttack(
                    id=f"attack-{uuid.uuid4().hex[:8]}",
                    payload=payload,
                    template_id=template.id,
                    template_name=template.name,
                    category=template.category,
                    severity=template.severity,
                    tags=template.tags.copy(),
                    variables_used=var_combo,
                )
                attacks.append(attack)

        return attacks

    def _substitute_variables(
        self, template: str, variables: dict[str, str]
    ) -> str:
        """Substitute variables in a template string.

        Args:
            template: Template string with {{variable}} placeholders.
            variables: Variable values.

        Returns:
            String with variables substituted.
        """
        def replace(match: re.Match) -> str:
            var_name = match.group(1)
            return variables.get(var_name, match.group(0))

        return VARIABLE_PATTERN.sub(replace, template)

    def _generate_variable_combinations(
        self,
        template_vars: dict[str, list[str]],
        overrides: dict[str, str],
    ) -> list[dict[str, str]]:
        """Generate all combinations of variable values.

        Args:
            template_vars: Template variable definitions.
            overrides: Override values (take precedence).

        Returns:
            List of variable combination dictionaries.
        """
        if not template_vars:
            return [overrides.copy()] if overrides else [{}]

        # Filter out overridden variables
        remaining_vars = {
            k: v for k, v in template_vars.items()
            if k not in overrides
        }

        if not remaining_vars:
            return [overrides.copy()]

        # Generate combinations
        combinations = [{}]
        for var_name, values in remaining_vars.items():
            if not values:
                continue
            new_combinations = []
            for combo in combinations:
                for value in values:
                    new_combo = combo.copy()
                    new_combo[var_name] = value
                    new_combinations.append(new_combo)
            combinations = new_combinations

        # Add overrides to each combination
        if overrides:
            for combo in combinations:
                combo.update(overrides)

        return combinations if combinations else [overrides.copy()]

    def preview(self, template_id: str, limit: int = 5) -> list[str]:
        """Preview generated payloads from a template.

        Args:
            template_id: Template to preview.
            limit: Maximum number of payloads to show.

        Returns:
            List of preview payload strings.
        """
        attacks = self.generate(template_id)
        return [a.payload for a in attacks[:limit]]
