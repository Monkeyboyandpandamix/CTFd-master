"""
Apply admin/API challenge update payloads safely: only mapped scalar columns
and synonyms (no relationships, no primary key).
"""

from sqlalchemy.inspection import inspect
from sqlalchemy.orm import RelationshipProperty

from CTFd.exceptions.challenges import ChallengeUpdateException
from CTFd.models import db


def scalar_field_keys(model_cls):
    """
    ORM keys that correspond to scalar columns (and synonyms) on ``model_cls``,
    excluding the primary key and relationship collections.
    """
    keys = set()
    for prop in inspect(model_cls).mapper.iterate_properties:
        if isinstance(prop, RelationshipProperty):
            continue
        if prop.key == "id":
            continue
        keys.add(prop.key)
    return keys


def apply_challenge_scalar_updates(challenge, data):
    """
    Set attributes on ``challenge`` from mapping ``data`` (form or JSON).
    Unknown keys and relationship names are ignored. ``initial``, ``minimum``,
    and ``decay`` are coerced with the same float rules as legacy CTFd updates.
    """
    if not data:
        return

    allowed = scalar_field_keys(challenge.__class__)
    float_attrs = frozenset({"initial", "minimum", "decay"})

    for attr, value in data.items():
        if attr not in allowed:
            continue
        if attr in float_attrs:
            try:
                value = float(value)
            except (TypeError, ValueError):
                db.session.rollback()
                raise ChallengeUpdateException(f"Invalid input for '{attr}'")
        setattr(challenge, attr, value)
