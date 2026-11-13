"""Terraform plan report formatting and output."""

import fnmatch
import json as _json
import logging
import re
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

from jinja2 import Environment, FileSystemLoader

from ..reporter import ReporterInterface
from ..reporters.base_reporter import BaseReporter


_MISSING = object()

# Keep ordinary resources at the configured depth, but allow the deeply
# nested AWS WAF statements to be expanded further.
_RESOURCE_DIFF_MAX_DEPTHS = {
    "aws_wafv2_web_acl": 20,
}

_ACTION_NAMES = {
    "allow": "ALLOW",
    "block": "BLOCK",
    "captcha": "CAPTCHA",
    "challenge": "CHALLENGE",
    "count": "COUNT",
}


class PlanReporter(BaseReporter, ReporterInterface):
    """Formats and displays Terraform plan results."""

    def __init__(self):
        """Initialize the plan reporter."""
        super().__init__()
        self.logger = logging.getLogger(__name__)

        template_dir = Path(__file__).parent.parent / "templates"
        self.env = Environment(
            autoescape=True,
            loader=FileSystemLoader(str(template_dir)),
            trim_blocks=True,
            lstrip_blocks=True,
        )
        self._provider_schema_cache = {}

    @property
    def category(self) -> str:
        """Return the reporter category."""
        return "plan"

    def get_report(self, data: Any, **kwargs) -> Dict:
        """Validate and return a plan report."""
        if not isinstance(data, dict) or "total_changes" not in data:
            self.logger.error("Invalid report format")
            raise ValueError("Invalid report format")
        return data

    def _process_resources(
        self,
        resources: List[Dict],
        show_changes: bool = False,
        show_details: bool = False,
    ) -> List[Dict]:
        """Prepare resources for Markdown or JSON output."""
        processed_resources = []

        for resource in resources:
            resource_data = {
                "resource_type": resource["resource_type"],
                "identifier": resource["identifier"],
                "action": resource["action"],
                "provider": resource.get("provider", "unknown"),
                "module": resource.get("module", "root"),
                "replacement": resource.get("replacement", False),
                "replacement_triggers": resource.get(
                    "replacement_triggers", []
                ),
            }

            if show_changes:
                before = resource.get("before", {}) or {}
                after = resource.get("after", {}) or {}
                changes = []

                for attr in sorted(set(before) | set(after)):
                    if attr in {"id", "tags_all"}:
                        continue

                    before_val = before.get(attr)
                    after_val = after.get(attr)
                    if before_val != after_val:
                        changes.append(
                            {
                                "attribute": attr,
                                "before": before_val,
                                "after": after_val,
                            }
                        )

                if changes:
                    resource_data["changes"] = changes

            if show_details:
                resource_data["details"] = {
                    "dependencies": resource.get("dependencies", []),
                    "tags": resource.get("tags", {}),
                    "raw": {
                        "before": resource.get("before", {}),
                        "after": resource.get("after", {}),
                    },
                    "replacement_triggers": resource.get(
                        "replacement_triggers", []
                    ),
                }

            processed_resources.append(resource_data)

        return processed_resources

    def print_report(self, data: Any, **kwargs) -> None:
        """Print the plan report.

        Structural diff is enabled by default and is printed when
        ``show_changes=True``.

        Options:
            show_changes: Print resource attribute changes.
            structural_diff: Use schema-aware recursive output.
            structural_diff_max_depth: Maximum recursion depth; defaults to 8.
                WAF resources use at least depth 20.
            structural_diff_ignore_paths: Glob patterns for paths to omit.
            provider_schema: Parsed output from ``tofu providers schema -json``.
            tofu_binary: Terraform/OpenTofu executable, default ``tofu``.
            tofu_working_dir: Initialized working directory for the plan.
            show_attribute_difference: Flat-mode option: bool or ``threshold``.
            structure_threshold: Flat-mode threshold.
            diff_method: Flat-mode library, ``deepdiff`` or ``jsondiff``.
        """
        report = self.get_report(data, **kwargs)
        show_details = kwargs.get("show_details", False)
        show_changes = kwargs.get("show_changes", False)

        self._print_header("Terraform Plan Analysis")
        self._print_summary(report)

        if not (show_details or show_changes):
            return

        if "resources" not in report:
            raise ValueError("Report missing resource details")

        structural_diff = kwargs.get("structural_diff", True)
        provider_schema = kwargs.get("provider_schema")

        if show_changes and structural_diff and provider_schema is None:
            provider_schema = self._load_provider_schema(
                tofu_binary=kwargs.get("tofu_binary", "tofu"),
                working_dir=kwargs.get("tofu_working_dir"),
            )

        self._print_resource_details(
            report["resources"],
            show_changes=show_changes,
            structural_diff=structural_diff,
            provider_schema=provider_schema,
            structural_diff_max_depth=kwargs.get(
                "structural_diff_max_depth", 8
            ),
            structural_diff_ignore_paths=kwargs.get(
                "structural_diff_ignore_paths", []
            ),
            show_attribute_difference=kwargs.get(
                "show_attribute_difference", "threshold"
            ),
            structure_threshold=kwargs.get("structure_threshold", 3),
            diff_method=kwargs.get("diff_method", "deepdiff"),
        )

    def _print_header(self, title: str) -> None:
        """Print a formatted header."""
        self._write(f"\n{self._colorize(title, 'bold')}\n")
        self._write("=" * 50 + "\n")

    def _print_summary(self, report: Dict) -> None:
        """Print the change summary."""
        self._write(
            f"\n{self._colorize('Total Changes: ' + str(report['total_changes']), 'bold')}\n"
        )

        for action in ("create", "update", "delete"):
            count = report["change_breakdown"].get(action, 0)
            self._write(f"{action.title()}: {count}\n")

    def _print_resource_details(
        self,
        resources: list,
        show_changes: bool = False,
        structural_diff: bool = True,
        provider_schema: Optional[Dict] = None,
        structural_diff_max_depth: int = 8,
        structural_diff_ignore_paths: Optional[List[str]] = None,
        show_attribute_difference: Any = "threshold",
        structure_threshold: int = 3,
        diff_method: str = "deepdiff",
    ) -> None:
        """Print resource details and optional attribute changes."""
        self._write(f"\n{self._colorize('Resources Changes:', 'bold')}\n")

        action_colors = {
            "CREATE": "green",
            "UPDATE": "blue",
            "DELETE": "red",
            "REPLACE": "yellow",
        }

        for resource in resources:
            action_str = resource["action"].upper()
            colored_action = self._colorize(
                action_str,
                action_colors.get(action_str, "bold"),
            )

            self._write(
                f"\n{colored_action} {resource['resource_type']}: "
                f"{resource['identifier']}\n"
            )

            if resource.get("replacement", False) and resource.get(
                "replacement_triggers"
            ):
                triggers = ", ".join(resource["replacement_triggers"])
                self._write(f"  Replacement triggered by: {triggers}\n")

            if show_changes:
                self._print_attribute_changes(
                    resource,
                    structural_diff=structural_diff,
                    provider_schema=provider_schema,
                    structural_diff_max_depth=structural_diff_max_depth,
                    structural_diff_ignore_paths=(
                        structural_diff_ignore_paths or []
                    ),
                    show_attribute_difference=show_attribute_difference,
                    structure_threshold=structure_threshold,
                    diff_method=diff_method,
                )

        self._write("\n")

    def _load_provider_schema(
        self,
        tofu_binary: str = "tofu",
        working_dir: Optional[str] = None,
    ) -> Optional[Dict]:
        """Run ``tofu providers schema -json`` and cache its output."""
        directory = str(Path(working_dir or Path.cwd()).resolve())
        cache_key = (tofu_binary, directory)

        if cache_key in self._provider_schema_cache:
            return self._provider_schema_cache[cache_key]

        command = [tofu_binary, "providers", "schema", "-json"]

        try:
            result = subprocess.run(
                command,
                cwd=directory,
                check=True,
                capture_output=True,
                text=True,
                encoding="utf-8",
                timeout=60,
            )
            schema = _json.loads(result.stdout)
        except (
            OSError,
            subprocess.SubprocessError,
            _json.JSONDecodeError,
        ) as exc:
            self.logger.warning(
                "Could not load provider schema by running %s in %s: %s",
                " ".join(command),
                directory,
                exc,
            )
            self._provider_schema_cache[cache_key] = None
            return None

        if not isinstance(schema, dict):
            self.logger.warning(
                "Provider schema command returned an unexpected JSON value"
            )
            self._provider_schema_cache[cache_key] = None
            return None

        self._provider_schema_cache[cache_key] = schema
        return schema

    @staticmethod
    def _provider_address(provider: Any) -> Optional[str]:
        """Normalize a provider identifier from resource analysis data."""
        if not isinstance(provider, str) or not provider:
            return None

        match = re.search(r"registry\.[^/]+/[^/]+/[^/]+", provider)
        if match:
            return match.group(0)

        return provider.strip()

    @staticmethod
    def _provider_source(address: str) -> str:
        """Return the namespace/provider suffix of a provider address."""
        parts = address.strip("/").split("/")
        if len(parts) >= 2:
            return "/".join(parts[-2:])
        return address

    def _resource_schema(
        self,
        resource: Dict,
        provider_schema: Optional[Dict],
    ) -> Optional[Dict]:
        """Find a resource schema, allowing registry-host aliases."""
        if not provider_schema:
            return None

        providers = provider_schema.get("provider_schemas", {})
        resource_type = resource.get("resource_type")
        provider_value = self._provider_address(resource.get("provider"))

        requested_source = (
            self._provider_source(provider_value)
            if provider_value
            else None
        )

        candidates = []
        for provider_address, provider_data in providers.items():
            if provider_value is None:
                candidates.append(provider_data)
            elif (
                provider_address == provider_value
                or self._provider_source(provider_address) == requested_source
            ):
                candidates.append(provider_data)

        found = []
        for provider_data in candidates:
            resource_schemas = provider_data.get("resource_schemas", {})
            schema = resource_schemas.get(resource_type)
            if schema:
                found.append(schema)

        if len(found) == 1:
            return found[0]

        if len(found) > 1:
            self.logger.warning(
                "Multiple provider schemas match provider %s and resource "
                "type %s",
                provider_value,
                resource_type,
            )
        else:
            self.logger.debug(
                "No provider schema found for provider %s and resource type %s",
                provider_value,
                resource_type,
            )

        return None

    @staticmethod
    def _block_node(block: Dict, nesting_mode: str = "object") -> Dict:
        """Wrap a provider block schema as a diff schema node."""
        return {"_block": block, "_mode": nesting_mode}

    @staticmethod
    def _type_node(type_spec: Any) -> Dict:
        """Wrap a provider attribute type as a diff schema node."""
        return {"_type": type_spec}

    @staticmethod
    def _node_kind(schema_node: Optional[Dict]) -> Optional[str]:
        """Return the collection or object kind described by a schema node."""
        if not schema_node:
            return None

        if "_mode" in schema_node:
            return schema_node["_mode"]

        type_spec = schema_node.get("_type")
        if isinstance(type_spec, (list, tuple)) and type_spec:
            return type_spec[0]

        if isinstance(type_spec, dict):
            return "object"

        return "scalar"

    @classmethod
    def _child_schema(
        cls,
        schema_node: Optional[Dict],
        key: Any,
    ) -> Optional[Dict]:
        """Return the schema node for a child field or map key."""
        if not schema_node:
            return None

        if "_block" in schema_node:
            block = schema_node["_block"]

            attribute = block.get("attributes", {}).get(str(key))
            if attribute:
                return cls._type_node(attribute.get("type"))

            nested_block = block.get("block_types", {}).get(str(key))
            if nested_block:
                return cls._block_node(
                    nested_block.get("block", {}),
                    nested_block.get("nesting_mode", "list"),
                )

            return None

        type_spec = schema_node.get("_type")

        if isinstance(type_spec, (list, tuple)) and type_spec:
            type_kind = type_spec[0]

            if type_kind == "object" and len(type_spec) > 1:
                child_type = type_spec[1].get(str(key))
                if child_type is not None:
                    return cls._type_node(child_type)

            if type_kind == "map" and len(type_spec) > 1:
                return cls._type_node(type_spec[1])

        return None

    @classmethod
    def _element_schema(
        cls,
        schema_node: Optional[Dict],
    ) -> Optional[Dict]:
        """Return the schema node for a list, set, or block element."""
        if not schema_node:
            return None

        if "_mode" in schema_node:
            return cls._block_node(schema_node["_block"], "object")

        type_spec = schema_node.get("_type")
        if (
            isinstance(type_spec, (list, tuple))
            and len(type_spec) > 1
            and type_spec[0] in {"list", "set"}
        ):
            return cls._type_node(type_spec[1])

        return None

    @staticmethod
    def _render_diff_value(value: Any, limit: int = 160) -> str:
        """Render a value compactly for console output."""
        rendered = _json.dumps(
            value,
            sort_keys=True,
            ensure_ascii=False,
            default=str,
        )

        if len(rendered) > limit:
            return rendered[: limit - 3] + "..."

        return rendered

    @staticmethod
    def _canonical_value(value: Any) -> str:
        """Return deterministic JSON for comparing set elements."""
        return _json.dumps(
            value,
            sort_keys=True,
            ensure_ascii=False,
            separators=(",", ":"),
            default=str,
        )

    @classmethod
    def _identity_index(
        cls,
        items: List[Any],
        identity_key: str,
    ) -> Optional[Dict[str, Tuple[Any, Any]]]:
        """Index object items by a unique scalar identity field."""
        result = {}

        for item in items:
            if not isinstance(item, dict) or identity_key not in item:
                return None

            identity = item[identity_key]
            if identity is None or isinstance(identity, (dict, list, set)):
                return None

            token = _json.dumps(
                identity,
                sort_keys=True,
                ensure_ascii=False,
                default=str,
            )

            if token in result:
                return None

            result[token] = (identity, item)

        return result

    @classmethod
    def _set_identity_indexes(
        cls,
        old_items: List[Any],
        new_items: List[Any],
    ) -> Optional[
        Tuple[
            str,
            Dict[str, Tuple[Any, Any]],
            Dict[str, Tuple[Any, Any]],
        ]
    ]:
        """Choose the unique identity that best matches two set values.

        Tries ``name``, ``arn``, and then ``priority``. The candidate with
        the most shared identity values wins; ties use that preference order.
        An identity field must be present and unique in both lists.
        """
        preference = {"name": 2, "arn": 1, "priority": 0}
        candidates = []

        for identity_key in ("name", "arn", "priority"):
            old_index = cls._identity_index(old_items, identity_key)
            new_index = cls._identity_index(new_items, identity_key)

            if old_index is None or new_index is None:
                continue

            shared_count = len(old_index.keys() & new_index.keys())
            candidates.append(
                (
                    shared_count,
                    preference[identity_key],
                    identity_key,
                    old_index,
                    new_index,
                )
            )

        if not candidates:
            return None

        _, _, identity_key, old_index, new_index = max(candidates)
        return identity_key, old_index, new_index

    @classmethod
    def _single_set_identity(
        cls,
        items: List[Any],
    ) -> Optional[Tuple[str, Dict[str, Tuple[Any, Any]]]]:
        """Find a unique identity field for displaying one-sided set items."""
        for identity_key in ("name", "arn", "priority"):
            index = cls._identity_index(items, identity_key)
            if index is not None:
                return identity_key, index
        return None

    @staticmethod
    def _identity_path(path: str, identity_key: str, identity: Any) -> str:
        """Append a readable identity selector to a path."""
        identity_text = _json.dumps(
            identity,
            ensure_ascii=False,
            default=str,
        )
        return f"{path}[{identity_key}={identity_text}]"

    @staticmethod
    def _action_label(value: Any) -> Optional[str]:
        """Return the active action name from a provider-expanded action."""
        if isinstance(value, dict):
            candidates = [value]
        elif isinstance(value, list):
            candidates = [item for item in value if isinstance(item, dict)]
        else:
            return None

        for candidate in candidates:
            for key, label in _ACTION_NAMES.items():
                action_value = candidate.get(key)
                if isinstance(action_value, list) and action_value:
                    return label
                if isinstance(action_value, dict) and action_value:
                    return label

        return None

    @staticmethod
    def _is_identity_leaf(path: str) -> bool:
        """Check whether a path repeats the identity already in its selector."""
        match = re.search(
            r'\[(name|arn|priority)=("(?:\\.|[^"\\])*"|[^\]]+)\]\.\1$',
            path,
        )
        return match is not None

    @staticmethod
    def _path_matches_pattern(path: str, pattern: str) -> bool:
        """Match a diff path against a glob pattern."""
        normalized_path = re.sub(r"\[[^\]]*\]", ".*", path)
        normalized_pattern = re.sub(r"\[[^\]]*\]", ".*", pattern)
        return fnmatch.fnmatchcase(normalized_path, normalized_pattern)

    @classmethod
    def _path_is_ignored(
        cls,
        path: str,
        ignore_paths: List[str],
    ) -> bool:
        """Return whether a diff path matches an ignore pattern."""
        return any(
            cls._path_matches_pattern(path, pattern)
            for pattern in ignore_paths
        )

    def _structural_diff(
        self,
        before: Any,
        after: Any,
        path: str,
        *,
        schema_node: Optional[Dict] = None,
        ignore_paths: Optional[List[str]] = None,
        max_depth: int = 8,
    ) -> Iterable[Tuple[str, str, Any, Any]]:
        """Yield recursive changes as operation, path, before, and after.

        Provider-schema sets are unordered. Their elements are matched
        exactly first, then by a unique shared ``name``, ``arn``, or
        ``priority``. Lists and collections without a set schema are
        compared by index.

        Empty lists are treated as absent placeholders. Empty dictionaries
        are retained because an empty object can represent a meaningful block.
        """
        if not isinstance(max_depth, int) or max_depth < 0:
            raise ValueError(
                "structural_diff_max_depth must be a non-negative integer"
            )

        ignore_paths = ignore_paths or []

        def walk(
            old: Any,
            new: Any,
            current_path: str,
            current_schema: Optional[Dict],
            depth: int,
        ) -> Iterable[Tuple[str, str, Any, Any]]:
            # Summarize active action alternatives instead of expanding
            # provider-expanded action placeholders.
            action_field = current_path.rsplit(".", 1)[-1]
            if action_field in {"action", "action_to_use"}:
                old_action = (
                    None if old is _MISSING else self._action_label(old)
                )
                new_action = (
                    None if new is _MISSING else self._action_label(new)
                )

                if old_action is not None or new_action is not None:
                    if old_action == new_action:
                        return
                    if old_action is None:
                        yield ("+", current_path, _MISSING, new_action)
                    elif new_action is None:
                        yield ("-", current_path, old_action, _MISSING)
                    else:
                        yield ("~", current_path, old_action, new_action)
                    return

            # Empty lists are commonly provider-expanded placeholders.
            # Preserve empty dictionaries: [{}] may be a real nested block.
            if isinstance(old, list) and not old:
                old = _MISSING
            if isinstance(new, list) and not new:
                new = _MISSING

            if old is _MISSING and new is _MISSING:
                return

            if old is not _MISSING and new is not _MISSING and old == new:
                return

            if self._path_is_ignored(current_path, ignore_paths):
                return

            if depth >= max_depth:
                if old is _MISSING:
                    yield ("+", current_path, old, new)
                elif new is _MISSING:
                    yield ("-", current_path, old, new)
                else:
                    yield ("~", current_path, old, new)
                return

            if old is _MISSING:
                if isinstance(new, dict) and new:
                    for key in sorted(new, key=str):
                        if self._is_identity_leaf(
                            f"{current_path}.{key}"
                        ):
                            continue

                        child_path = (
                            f"{current_path}.{key}"
                            if current_path
                            else str(key)
                        )
                        yield from walk(
                            _MISSING,
                            new[key],
                            child_path,
                            self._child_schema(current_schema, key),
                            depth + 1,
                        )
                    return

                if isinstance(new, list) and new:
                    kind = self._node_kind(current_schema)
                    element_schema = self._element_schema(current_schema)

                    if kind == "set":
                        identity_info = self._single_set_identity(new)
                        if identity_info is not None:
                            identity_key, new_index = identity_info
                            for token in sorted(new_index):
                                identity, item = new_index[token]
                                item_path = self._identity_path(
                                    current_path,
                                    identity_key,
                                    identity,
                                )
                                yield from walk(
                                    _MISSING,
                                    item,
                                    item_path,
                                    element_schema,
                                    depth + 1,
                                )
                            return

                    for index, item in enumerate(new):
                        item_path = (
                            f"{current_path}[set item]"
                            if kind == "set"
                            else f"{current_path}[{index}]"
                        )
                        yield from walk(
                            _MISSING,
                            item,
                            item_path,
                            element_schema,
                            depth + 1,
                        )
                    return

                yield ("+", current_path, old, new)
                return

            if new is _MISSING:
                if isinstance(old, dict) and old:
                    for key in sorted(old, key=str):
                        child_path = (
                            f"{current_path}.{key}"
                            if current_path
                            else str(key)
                        )
                        if self._is_identity_leaf(child_path):
                            continue

                        yield from walk(
                            old[key],
                            _MISSING,
                            child_path,
                            self._child_schema(current_schema, key),
                            depth + 1,
                        )
                    return

                if isinstance(old, list) and old:
                    kind = self._node_kind(current_schema)
                    element_schema = self._element_schema(current_schema)

                    if kind == "set":
                        identity_info = self._single_set_identity(old)
                        if identity_info is not None:
                            identity_key, old_index = identity_info
                            for token in sorted(old_index):
                                identity, item = old_index[token]
                                item_path = self._identity_path(
                                    current_path,
                                    identity_key,
                                    identity,
                                )
                                yield from walk(
                                    item,
                                    _MISSING,
                                    item_path,
                                    element_schema,
                                    depth + 1,
                                )
                            return

                    for index, item in enumerate(old):
                        item_path = (
                            f"{current_path}[set item]"
                            if kind == "set"
                            else f"{current_path}[{index}]"
                        )
                        yield from walk(
                            item,
                            _MISSING,
                            item_path,
                            element_schema,
                            depth + 1,
                        )
                    return

                yield ("-", current_path, old, new)
                return

            if isinstance(old, dict) and isinstance(new, dict):
                for key in sorted(old.keys() | new.keys(), key=str):
                    child_path = (
                        f"{current_path}.{key}"
                        if current_path
                        else str(key)
                    )
                    if self._is_identity_leaf(child_path):
                        continue

                    yield from walk(
                        old.get(key, _MISSING),
                        new.get(key, _MISSING),
                        child_path,
                        self._child_schema(current_schema, key),
                        depth + 1,
                    )
                return

            if isinstance(old, list) and isinstance(new, list):
                kind = self._node_kind(current_schema)
                element_schema = self._element_schema(current_schema)

                if kind == "set":
                    old_remaining = {
                        self._canonical_value(item): item for item in old
                    }
                    new_remaining = {
                        self._canonical_value(item): item for item in new
                    }

                    # Exact set members are unchanged, regardless of order.
                    unchanged = old_remaining.keys() & new_remaining.keys()
                    for token in unchanged:
                        del old_remaining[token]
                        del new_remaining[token]

                    old_items = list(old_remaining.values())
                    new_items = list(new_remaining.values())
                    identity_indexes = self._set_identity_indexes(
                        old_items,
                        new_items,
                    )

                    matched_old = set()
                    matched_new = set()

                    if identity_indexes is not None:
                        identity_key, old_index, new_index = identity_indexes

                        for token in sorted(old_index.keys() & new_index.keys()):
                            identity, old_item = old_index[token]
                            _, new_item = new_index[token]
                            item_path = self._identity_path(
                                current_path,
                                identity_key,
                                identity,
                            )
                            yield from walk(
                                old_item,
                                new_item,
                                item_path,
                                element_schema,
                                depth + 1,
                            )
                            matched_old.add(self._canonical_value(old_item))
                            matched_new.add(self._canonical_value(new_item))

                    for token, item in sorted(old_remaining.items()):
                        if token in matched_old:
                            continue

                        item_path = f"{current_path}[set item]"
                        if identity_indexes is not None:
                            identity_key = identity_indexes[0]
                            item_path = self._identity_path(
                                current_path,
                                identity_key,
                                item.get(identity_key),
                            )

                        yield from walk(
                            item,
                            _MISSING,
                            item_path,
                            element_schema,
                            depth + 1,
                        )

                    for token, item in sorted(new_remaining.items()):
                        if token in matched_new:
                            continue

                        item_path = f"{current_path}[set item]"
                        if identity_indexes is not None:
                            identity_key = identity_indexes[0]
                            item_path = self._identity_path(
                                current_path,
                                identity_key,
                                item.get(identity_key),
                            )

                        yield from walk(
                            _MISSING,
                            item,
                            item_path,
                            element_schema,
                            depth + 1,
                        )

                    return

                # Lists (and unknown collections) are ordered and compared
                # by position.
                common_length = min(len(old), len(new))

                for index in range(common_length):
                    yield from walk(
                        old[index],
                        new[index],
                        f"{current_path}[{index}]",
                        element_schema,
                        depth + 1,
                    )

                for index in range(common_length, len(old)):
                    yield from walk(
                        old[index],
                        _MISSING,
                        f"{current_path}[{index}]",
                        element_schema,
                        depth + 1,
                    )

                for index in range(common_length, len(new)):
                    yield from walk(
                        _MISSING,
                        new[index],
                        f"{current_path}[{index}]",
                        element_schema,
                        depth + 1,
                    )

                return

            yield ("~", current_path, old, new)

        yield from walk(before, after, path, schema_node, 0)

    def _print_structural_attribute_changes(
        self,
        resource: Dict,
        provider_schema: Optional[Dict],
        max_depth: int,
        ignore_paths: List[str],
    ) -> None:
        """Print structural changes using the provider schema."""
        before = resource.get("before", {}) or {}
        after = resource.get("after", {}) or {}
        action = resource["action"]

        resource_type = resource.get("resource_type")
        resource_max_depth = max(
            max_depth,
            _RESOURCE_DIFF_MAX_DEPTHS.get(resource_type, max_depth),
        )

        resource_schema = self._resource_schema(resource, provider_schema)
        root_schema = None

        if resource_schema and isinstance(resource_schema.get("block"), dict):
            root_schema = self._block_node(
                resource_schema["block"],
                "object",
            )

        all_attrs = set(before) | set(after)

        for attr in sorted(all_attrs - {"id", "tags_all"}):
            before_val = before.get(attr, _MISSING)
            after_val = after.get(attr, _MISSING)

            if before_val is not _MISSING and after_val is not _MISSING:
                if before_val == after_val:
                    continue

            if action == "create":
                old, new = _MISSING, after_val
            elif action == "delete":
                old, new = before_val, _MISSING
            else:
                old, new = before_val, after_val

            attr_schema = self._child_schema(root_schema, attr)

            for operation, path, old_value, new_value in self._structural_diff(
                old,
                new,
                attr,
                schema_node=attr_schema,
                ignore_paths=ignore_paths,
                max_depth=resource_max_depth,
            ):
                color = {
                    "+": "green",
                    "-": "red",
                    "~": "blue",
                }[operation]
                symbol = self._colorize(operation, color)

                if operation == "+":
                    line = (
                        f"  {symbol} {path} = "
                        f"{self._render_diff_value(new_value)}"
                    )
                elif operation == "-":
                    line = (
                        f"  {symbol} {path} = "
                        f"{self._render_diff_value(old_value)}"
                    )
                else:
                    line = (
                        f"  {symbol} {path}: "
                        f"{self._render_diff_value(old_value)} -> "
                        f"{self._render_diff_value(new_value)}"
                    )

                self._write(line + "\n")

    @staticmethod
    def _normalize_attribute_diff_mode(mode: Any) -> str:
        """Normalize and validate the flat diff option."""
        if isinstance(mode, bool):
            normalized = "true" if mode else "false"
        elif isinstance(mode, str):
            normalized = mode.lower()
        else:
            raise ValueError(
                "show_attribute_difference must be a bool or "
                "'threshold', 'true', or 'false'"
            )

        if normalized not in {"true", "false", "threshold"}:
            raise ValueError(
                "show_attribute_difference must be 'threshold', "
                "'true', or 'false'"
            )

        return normalized

    def _format_attribute_changes_difference(
        self,
        before_val: Any,
        after_val: Any,
        show_attribute_difference: Any,
        structure_threshold: int,
        diff_method: str,
    ) -> str:
        """Format a flat difference using DeepDiff or jsondiff."""
        if not isinstance(structure_threshold, int) or structure_threshold < 0:
            raise ValueError("structure_threshold must be non-negative")

        mode = self._normalize_attribute_diff_mode(
            show_attribute_difference
        )

        if mode == "true":
            use_custom_diff = True
        elif mode == "false":
            use_custom_diff = False
        else:
            use_custom_diff = (
                isinstance(before_val, (list, dict))
                and isinstance(after_val, (list, dict))
                and len(before_val) > structure_threshold
                and len(after_val) > structure_threshold
            )

        if not use_custom_diff:
            return (
                f"{self._render_diff_value(before_val)} -> "
                f"{self._render_diff_value(after_val)}"
            )

        method = diff_method.lower()

        if method == "deepdiff":
            try:
                from deepdiff import DeepDiff
            except ImportError as exc:
                raise ImportError(
                    "diff_method='deepdiff' requires the deepdiff package"
                ) from exc
            return str(DeepDiff(before_val, after_val))

        if method == "jsondiff":
            try:
                from jsondiff import diff
            except ImportError as exc:
                raise ImportError(
                    "diff_method='jsondiff' requires the jsondiff package"
                ) from exc
            return str(diff(before_val, after_val, syntax="symmetric"))

        raise ValueError("diff_method must be 'deepdiff' or 'jsondiff'")

    def _print_flat_attribute_changes(
        self,
        resource: Dict,
        show_attribute_difference: Any,
        structure_threshold: int,
        diff_method: str,
    ) -> None:
        """Print attribute changes using the flat formatter."""
        before = resource.get("before", {}) or {}
        after = resource.get("after", {}) or {}
        action = resource["action"]
        lines = []

        for attr in sorted((set(before) | set(after)) - {"id", "tags_all"}):
            before_val = before.get(attr)
            after_val = after.get(attr)

            if before_val == after_val:
                continue

            if action == "create":
                symbol = self._colorize("+", "green")
                lines.append(
                    f"  {symbol} {attr} = "
                    f"{self._render_diff_value(after_val)}"
                )
            elif action == "delete":
                symbol = self._colorize("-", "red")
                lines.append(
                    f"  {symbol} {attr} = "
                    f"{self._render_diff_value(before_val)}"
                )
            elif action in {"update", "replace"}:
                symbol_text = "~" if action == "update" else "-/+"
                color = "blue" if action == "update" else "yellow"
                symbol = self._colorize(symbol_text, color)
                difference = self._format_attribute_changes_difference(
                    before_val,
                    after_val,
                    show_attribute_difference,
                    structure_threshold,
                    diff_method,
                )
                lines.append(f"  {symbol} {attr} = {difference}")

        if lines:
            self._write("\n".join(lines) + "\n")

    def _print_attribute_changes(
        self,
        resource: Dict,
        structural_diff: bool = True,
        provider_schema: Optional[Dict] = None,
        structural_diff_max_depth: int = 8,
        structural_diff_ignore_paths: Optional[List[str]] = None,
        show_attribute_difference: Any = "threshold",
        structure_threshold: int = 3,
        diff_method: str = "deepdiff",
    ) -> None:
        """Print resource changes structurally or using the flat formatter."""
        if structural_diff:
            self._print_structural_attribute_changes(
                resource,
                provider_schema=provider_schema,
                max_depth=structural_diff_max_depth,
                ignore_paths=structural_diff_ignore_paths or [],
            )
            return

        self._print_flat_attribute_changes(
            resource,
            show_attribute_difference=show_attribute_difference,
            structure_threshold=structure_threshold,
            diff_method=diff_method,
        )

    def print_report_markdown(self, data: Any, **kwargs) -> None:
        """Print the plan report in Markdown format."""
        report = self.get_report(data, **kwargs)
        show_details = kwargs.get("show_details", False)
        show_changes = kwargs.get("show_changes", False)

        template_data = {
            "total_resources": report["total_changes"],
            "resources_to_add": report["change_breakdown"]["create"],
            "resources_to_change": report["change_breakdown"]["update"],
            "resources_to_destroy": report["change_breakdown"]["delete"],
            "resources": self._process_resources(
                report.get("resources", []),
                show_changes=show_changes,
                show_details=show_details,
            ),
            "show_changes": show_changes,
            "show_details": show_details,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "analysis": [],
        }

        template = self.env.get_template("plan_report.md")
        self._write(template.render(**template_data))

    def print_report_json(self, data: Any, **kwargs) -> None:
        """Print the plan report in JSON format."""
        report = self.get_report(data, **kwargs)
        show_details = kwargs.get("show_details", False)
        show_changes = kwargs.get("show_changes", False)

        json_output = {
            "metadata": {
                "timestamp": datetime.now().isoformat(),
                "version": "1.0",
                "format": "json",
            },
            "summary": {
                "total_resources": report["total_changes"],
                "resources_to_add": report["change_breakdown"]["create"],
                "resources_to_change": report["change_breakdown"]["update"],
                "resources_to_destroy": report["change_breakdown"]["delete"],
            },
            "resources": self._process_resources(
                report.get("resources", []),
                show_changes=show_changes,
                show_details=show_details,
            ),
        }

        if "analysis" in report:
            json_output["analysis"] = report["analysis"]

        self._write(_json.dumps(json_output, indent=2))
