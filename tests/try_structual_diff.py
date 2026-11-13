# try_structural_report.py
import json
import sys

from tfsumpy.plan.reporter import PlanReporter


def make_report(plan):
    """Adapt tofu show -json output to PlanReporter input."""
    resources = []
    breakdown = {
        "create": 0,
        "update": 0,
        "delete": 0,
        "replace": 0,
    }

    for item in plan.get("resource_changes", []):
        change = item.get("change", {})
        actions = change.get("actions", [])

        if actions == ["no-op"] or actions == ["read"]:
            continue

        if set(actions) == {"create", "delete"}:
            action = "replace"
        elif actions in (["create"], ["update"], ["delete"]):
            action = actions[0]
        else:
            # Skip actions this reporter does not summarize.
            continue

        breakdown[action] += 1

        resources.append(
            {
                "resource_type": item.get("type", "unknown"),
                "identifier": item.get("address", "unknown"),
                "action": action,
                "provider": item.get("provider_name", "unknown"),
                "module": item.get("module_address", "root"),
                "before": change.get("before") or {},
                "after": change.get("after") or {},
                "replacement": action == "replace",
                "replacement_triggers": change.get("replace_paths", []),
            }
        )

    return {
        "total_changes": len(resources),
        "change_breakdown": breakdown,
        "resources": resources,
    }


def main():
    if len(sys.argv) != 3:
        raise SystemExit(
            "Usage: python try_structural_report.py PLAN.json SCHEMA.json"
        )

    with open(sys.argv[1], encoding="utf-8") as plan_file:
        plan = json.load(plan_file)

    with open(sys.argv[2], encoding="utf-8") as schema_file:
        provider_schema = json.load(schema_file)

    report = make_report(plan)
    
    resource = next(
        r for r in report["resources"]
        if r["resource_type"] == "aws_wafv2_web_acl"
    )

    print("schema providers:", list(provider_schema.get("provider_schemas", {})))
    print("provider:", resource.get("provider"))
    schema = PlanReporter()._resource_schema(resource, provider_schema)
    print("schema found:", schema is not None)

    if schema:
        rule_schema = schema["block"]["block_types"].get("rule")
        print(
            "rule nesting mode:",
            rule_schema.get("nesting_mode") if rule_schema else "not found",
        )
    
    PlanReporter().print_report(
        report,
        show_changes=True,
        structural_diff=True,
        provider_schema=provider_schema,
    )


if __name__ == "__main__":
    main()
