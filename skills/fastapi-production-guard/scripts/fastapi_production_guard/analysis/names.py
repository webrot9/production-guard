"""Reading intent out of identifiers.

Static analysis of an arbitrary codebase cannot know that `CurrentUserDep`
yields the signed-in user or that `wallet.balance` is money. It can read the
words the author chose. Every heuristic in the rules goes through these few
functions, so the vocabulary is in one place and can be extended from
configuration rather than by editing a regex in three rules.
"""

from __future__ import annotations

import ast
import re

_TOKEN = re.compile(r"[A-Z]+(?=[A-Z][a-z])|[A-Z]?[a-z]+|[A-Z]+|\d+")


def tokens(name: str) -> list[str]:
    """`CurrentUserDep` → ["current", "user", "dep"]; `get_db` → ["get", "db"]."""
    return [t.lower() for t in _TOKEN.findall(name)]


def dotted(node: ast.AST | None) -> str | None:
    """`self.session.get` → "self.session.get"; anything else → None."""
    parts: list[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
        return ".".join(reversed(parts))
    return None


def last_name(node: ast.AST | None) -> str | None:
    """The rightmost identifier of a name, attribute or call: `a.b.c()` → "c"."""
    if isinstance(node, ast.Call):
        node = node.func
    if isinstance(node, ast.Attribute):
        return node.attr
    if isinstance(node, ast.Name):
        return node.id
    return None


def call_name(call: ast.Call) -> str | None:
    return last_name(call.func)


def names_in(node: ast.AST) -> set[str]:
    """Every bare `Name` loaded anywhere inside `node`."""
    return {n.id for n in ast.walk(node) if isinstance(n, ast.Name)}


def attribute_paths(node: ast.AST) -> set[str]:
    """Every dotted path inside `node`: `user.org.id` yields all of its prefixes."""
    found: set[str] = set()
    for n in ast.walk(node):
        path = dotted(n)
        if path is not None:
            found.add(path)
    return found


def string_constants(node: ast.AST) -> list[str]:
    return [
        n.value for n in ast.walk(node) if isinstance(n, ast.Constant) and isinstance(n.value, str)
    ]


class Vocabulary:
    """The word lists, overridable from `[tool.fastapi-production-guard]`."""

    # A dependency whose name carries one of these yields *who is asking*.
    principal: frozenset[str] = frozenset(
        {
            "user", "users", "account", "member", "principal", "identity", "owner",
            "tenant", "org", "orgs", "organization", "organisation", "team", "workspace",
            "customer", "claims", "token", "auth", "caller", "actor", "subject", "me",
            "viewer", "profile", "requester", "operator", "agent", "seller", "merchant",
        }
    )
    # ...unless it also carries one of these, in which case it is plumbing
    # that happens to mention users: `get_user_db`, `UserRepository`.
    infra: frozenset[str] = frozenset(
        {
            "db", "database", "session", "sess", "conn", "connection", "engine", "repo",
            "repository", "repositories", "settings", "config", "cache", "redis", "service",
            "services", "client", "http", "logger", "log", "storage", "queue", "background",
            "tasks", "uow", "request", "manager", "store", "crud", "dao", "mailer", "email",
        }
    )
    # A dependency or check with one of these grants access to everyone's rows.
    admin: frozenset[str] = frozenset(
        {"admin", "admins", "superuser", "superusers", "staff", "sudo", "root", "superadmin"}
    )
    # A dependency with one of these checks a permission. Whether it checks
    # *this row* is decided by reading it (see FPG001), not by its name.
    authz: frozenset[str] = frozenset(
        {
            "permission", "permissions", "perm", "perms", "authorize", "authorise",
            "authorization", "authorisation", "authz", "policy", "policies", "acl", "rbac",
            "abac", "guard", "access", "allowed", "can",
        }
    )
    # Columns that make a model user-owned. A foreign key on one of them
    # must point at a users-like table (`owner_id -> services.id` is a team
    # that runs something, not a person who owns it); without a foreign key
    # the name alone decides, except for a bare `owner`/`user`.
    owner_columns: frozenset[str] = frozenset(
        {
            "user_id", "owner_id", "account_id", "tenant_id", "org_id", "organization_id",
            "organisation_id", "team_id", "workspace_id", "customer_id", "member_id",
            "user", "owner", "clerk_user_id", "profile_id", "merchant_id", "seller_id",
            "company_id", "owner_user_id",
        }
    )
    # Columns that record who made a row without saying who may read it. A
    # draft is private to its author; a forum post is not. Findings that rest
    # on one of these are reported at medium confidence.
    author_columns: frozenset[str] = frozenset(
        {"created_by", "created_by_id", "author_id", "creator_id", "author", "creator", "created_by_user_id"}
    )
    # Tables a foreign key can point at to make a model user-owned.
    owner_tables: frozenset[str] = frozenset(
        {
            "user", "users", "account", "accounts", "tenant", "tenants", "org", "orgs",
            "organization", "organizations", "organisation", "organisations", "team",
            "teams", "workspace", "workspaces", "customer", "customers", "member",
            "members", "profile", "profiles", "company", "companies", "merchant",
            "merchants",
        }
    )
    # Fields that hold a balance someone spends.
    balance: frozenset[str] = frozenset(
        {
            "credit", "credits", "balance", "balances", "quota", "quotas", "allowance",
            "remaining", "points", "coins", "funds", "budget", "stock", "inventory",
            "tokens_left", "tokens_remaining",
        }
    )

    def __init__(
        self,
        *,
        extra_principal: frozenset[str] = frozenset(),
        extra_admin: frozenset[str] = frozenset(),
        extra_owner_columns: frozenset[str] = frozenset(),
        extra_balance: frozenset[str] = frozenset(),
    ) -> None:
        self.principal = self.principal | extra_principal
        self.admin = self.admin | extra_admin
        self.owner_columns = self.owner_columns | extra_owner_columns
        self.balance = self.balance | extra_balance

    def is_balance_field(self, name: str) -> bool:
        if name.lower() in self.balance:
            return True
        parts = tokens(name)
        # `credits_remaining`, `credit_balance`, `quota_used`: a balance word,
        # and the name ends in a quantity. Not `credit_card`, `stock_symbol` or
        # `create_balance_from_charge`, where the balance word only qualifies
        # some other noun.
        if not parts or not any(p in self.balance for p in parts):
            return False
        if any(p in _NON_QUANTITY for p in parts):
            return False
        return parts[-1] in self.balance or parts[-1] in _QUANTITY_SUFFIXES


_QUANTITY_SUFFIXES = frozenset({"remaining", "left", "used", "available", "total", "count"})

_NON_QUANTITY = frozenset(
    {
        "card", "cards", "symbol", "symbols", "id", "ids", "name", "names", "url", "type",
        "kind", "status", "note", "notes", "reason", "currency", "at", "date", "enabled",
        "label", "description", "key", "code", "history", "log", "logs", "transactions",
        "transaction", "ledger", "unit", "units", "table", "model",
    }
)
