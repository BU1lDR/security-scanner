import pytest

from scanner.core.fix import Fix, FixKind


def test_fix_stores_its_fields():
    fix = Fix(
        kind=FixKind.DEPENDENCY_BUMP,
        description="Upgrade requests to 2.32.0",
        apply_safe=True,
        details={"package": "requests", "to": "2.32.0"},
    )
    assert fix.kind is FixKind.DEPENDENCY_BUMP
    assert fix.description == "Upgrade requests to 2.32.0"
    assert fix.apply_safe is True
    assert fix.details == {"package": "requests", "to": "2.32.0"}


def test_details_default_to_empty_dict():
    fix = Fix(kind=FixKind.MANUAL, description="Review manually", apply_safe=False)
    assert fix.details == {}


def test_dependency_bump_may_be_apply_safe():
    fix = Fix(kind=FixKind.DEPENDENCY_BUMP, description="bump", apply_safe=True)
    assert fix.apply_safe is True


def test_config_snippet_may_be_apply_safe():
    fix = Fix(kind=FixKind.CONFIG_SNIPPET, description="add header", apply_safe=True)
    assert fix.apply_safe is True


def test_code_patch_cannot_be_apply_safe():
    with pytest.raises(ValueError):
        Fix(kind=FixKind.CODE_PATCH, description="rewrite", apply_safe=True)


def test_manual_cannot_be_apply_safe():
    with pytest.raises(ValueError):
        Fix(kind=FixKind.MANUAL, description="do it yourself", apply_safe=True)
