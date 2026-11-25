"""Login page choice: SSO leads only once an account is managed by the identity provider (in-memory database)."""
from __future__ import annotations

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from orion_app.api.sso import _has_idp_accounts
from orion_app.database import Base
from orion_app.models import User
from orion_app.services.identity import PENDING

ISSUER = "https://login.microsoftonline.com/11111111-2222-3333-4444-555555555555/v2.0"


@pytest.fixture()
def db():
    engine = create_engine("sqlite://", poolclass=StaticPool, connect_args={"check_same_thread": False})
    Base.metadata.create_all(engine)
    with Session(engine) as session:
        yield session


def add(db, issuer: str, *, active: bool = True, subject: str = "s") -> None:
    db.add(User(issuer=issuer, subject=subject, email=f"{subject}@corp.example", display_name=subject, role="USER", active=active))
    db.flush()


def test_local_and_other_provider_accounts_do_not_make_sso_primary(db):
    add(db, "builtin:local", subject="admin")
    add(db, "ldap:corp", subject="ldap")
    add(db, "https://keycloak.example/realms/old", subject="old")
    assert _has_idp_accounts(db, ISSUER) is False


def test_a_disabled_idp_account_does_not_count(db):
    add(db, ISSUER, active=False)
    assert _has_idp_accounts(db, ISSUER) is False


@pytest.mark.parametrize("issuer", [ISSUER, f"{ISSUER}/", PENDING])
def test_an_active_idp_or_pre_provisioned_account_makes_sso_primary(db, issuer):
    add(db, issuer)
    assert _has_idp_accounts(db, ISSUER) is True
