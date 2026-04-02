"""Tests for safe challenge update field application."""

from CTFd.models import Challenges
from CTFd.plugins.dynamic_challenges import DynamicChallenge
from CTFd.utils.challenge_update_payload import scalar_field_keys


def test_scalar_field_keys_excludes_relationships_and_id():
    keys = scalar_field_keys(Challenges)
    assert "id" not in keys
    assert "tags" not in keys
    assert "files" not in keys
    assert "hints" not in keys
    assert "name" in keys
    assert "requirements" in keys


def test_dynamic_challenge_scalar_keys_include_editable_fields():
    keys = scalar_field_keys(DynamicChallenge)
    assert "name" in keys
    # Admin forms use ``initial`` (synonym) or the underlying column may appear.
    assert ("initial" in keys) or ("dynamic_initial" in keys)
    assert "id" not in keys
