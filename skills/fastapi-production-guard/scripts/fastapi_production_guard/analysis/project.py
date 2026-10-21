"""Loading a project: files, parse trees, and the indexes the rules resolve against.

Resolution is by name, not by type inference. `repo.get_for_user(...)` resolves
to every function in the project called `get_for_user`; a class resolves to
every class of that name. That is crude and it is enough: the rules only ever
ask "does some definition of this callee do X", and they say so in the
evidence when more than one definition was considered.
"""

from __future__ import annotations

import ast
import fnmatch
import os
import re
import sys
from collections import defaultdict
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path

DEFAULT_EXCLUDE_DIRS = frozenset(
    {
        ".git", ".hg", ".svn", ".venv", "venv", "env", ".env", "node_modules", "__pycache__",
        "build", "dist", ".tox", ".nox", ".mypy_cache", ".ruff_cache", ".pytest_cache",
        "site-packages", ".eggs", "migrations", "alembic", ".idea", ".vscode",
    }
)
TEST_DIRS = frozenset({"tests", "test", "testing"})


def is_test_path(rel: str) -> bool:
    parts = rel.split("/")
    name = parts[-1]
    if any(p in TEST_DIRS for p in parts[:-1]):
        return True
    return name.startswith("test_") or name.endswith("_test.py") or name == "conftest.py"


_SUPPRESS = re.compile(
    r"#\s*fpg:\s*ignore\[(?P<rules>[A-Z0-9,\s]+)\](?P<reason>[^#]*)", re.IGNORECASE
)


@dataclass
class Suppression:
    rules: frozenset[str]
    reason: str
    line: int


@dataclass
class Module:
    path: Path
    rel: str
    name: str
    tree: ast.Module
    lines: list[str]
    # alias -> (module dotted path, imported name or None for `import x`)
    imports: dict[str, tuple[str, str | None]] = field(default_factory=dict)
    suppressions: dict[int, Suppression] = field(default_factory=dict)
    # Every node of the tree, walked once. Several indexes need a full pass
    # and re-walking a 5,000-line module for each of them was most of the
    # runtime on large repositories.
    nodes: list[ast.AST] = field(default_factory=list)

    def suppression_for(self, line: int, rule: str) -> Suppression | None:
        """A marker on the finding's line, or on the comment line directly above it."""
        for candidate in (line, line - 1):
            s = self.suppressions.get(candidate)
            if s is None:
                continue
            if candidate == line - 1 and not self.lines[candidate - 1].lstrip().startswith("#"):
                continue
            if rule in s.rules or "ALL" in s.rules:
                return s
        return None


@dataclass
class FunctionInfo:
    module: Module
    node: ast.FunctionDef | ast.AsyncFunctionDef
    class_name: str | None

    @property
    def name(self) -> str:
        return self.node.name

    @property
    def qualname(self) -> str:
        return f"{self.class_name}.{self.name}" if self.class_name else self.name

    @property
    def params(self) -> list[ast.arg]:
        a = self.node.args
        return [*a.posonlyargs, *a.args, *a.kwonlyargs]

    def __hash__(self) -> int:
        return hash((self.module.rel, self.node.lineno, self.node.col_offset))

    def __eq__(self, other: object) -> bool:
        return (
            isinstance(other, FunctionInfo)
            and self.module.rel == other.module.rel
            and self.node.lineno == other.node.lineno
            and self.node.col_offset == other.node.col_offset
        )


@dataclass
class ClassInfo:
    module: Module
    node: ast.ClassDef

    @property
    def name(self) -> str:
        return self.node.name

    @property
    def base_names(self) -> list[str]:
        names: list[str] = []
        for b in self.node.bases:
            target = b.value if isinstance(b, ast.Subscript) else b
            if isinstance(target, ast.Attribute):
                names.append(target.attr)
            elif isinstance(target, ast.Name):
                names.append(target.id)
        return names


@dataclass
class ParseError:
    rel: str
    message: str


class Project:
    def __init__(self, root: Path, modules: list[Module], errors: list[ParseError]) -> None:
        self.root = root
        self.modules = modules
        self.errors = errors
        self.functions: dict[str, list[FunctionInfo]] = defaultdict(list)
        self.classes: dict[str, list[ClassInfo]] = defaultdict(list)
        # name -> [(module, value)] for module-level `X = ...` / `X: T = ...` / `type X = ...`
        self.assignments: dict[str, list[tuple[Module, ast.expr]]] = defaultdict(list)
        for m in modules:
            self._index(m)

    def _index(self, m: Module) -> None:
        for node in m.tree.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                self.functions[node.name].append(FunctionInfo(m, node, None))
            elif isinstance(node, ast.ClassDef):
                self._index_class(m, node)
            elif isinstance(node, ast.Assign):
                for t in node.targets:
                    if isinstance(t, ast.Name):
                        self.assignments[t.id].append((m, node.value))
            elif isinstance(node, ast.AnnAssign) and node.value is not None:
                if isinstance(node.target, ast.Name):
                    self.assignments[node.target.id].append((m, node.value))
            # `type X = ...` is 3.12 syntax, and ast.TypeAlias does not exist on
            # 3.11; checking the version first keeps the attribute unread there.
            elif sys.version_info >= (3, 12) and isinstance(node, ast.TypeAlias):
                self.assignments[node.name.id].append((m, node.value))
            elif isinstance(node, (ast.If, ast.Try)):
                # `if TYPE_CHECKING:` blocks and import fallbacks hold real definitions.
                for child in ast.iter_child_nodes(node):
                    if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        self.functions[child.name].append(FunctionInfo(m, child, None))
                    elif isinstance(child, ast.ClassDef):
                        self._index_class(m, child)

    def _index_class(self, m: Module, node: ast.ClassDef) -> None:
        self.classes[node.name].append(ClassInfo(m, node))
        for item in node.body:
            if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                self.functions[item.name].append(FunctionInfo(m, item, node.name))

    # -- resolution ---------------------------------------------------------

    def all_functions(self) -> Iterator[FunctionInfo]:
        for infos in self.functions.values():
            yield from infos

    def methods_of(self, class_name: str, method: str, _seen: set[str] | None = None) -> list[FunctionInfo]:
        """`method` as defined on `class_name` or the nearest base that defines it."""
        seen = _seen if _seen is not None else set()
        if class_name in seen:
            return []
        seen.add(class_name)
        found: list[FunctionInfo] = []
        for cls in self.classes.get(class_name, []):
            own = [
                FunctionInfo(cls.module, item, cls.name)
                for item in cls.node.body
                if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)) and item.name == method
            ]
            if own:
                found.extend(own)
                continue
            for base in cls.base_names:
                found.extend(self.methods_of(base, method, seen))
        return found

    def class_and_bases(self, class_name: str, _seen: set[str] | None = None) -> list[ClassInfo]:
        seen = _seen if _seen is not None else set()
        if class_name in seen:
            return []
        seen.add(class_name)
        out: list[ClassInfo] = []
        for cls in self.classes.get(class_name, []):
            out.append(cls)
            for base in cls.base_names:
                out.extend(self.class_and_bases(base, seen))
        return out

    def resolve_function(self, module: Module, ref: ast.expr, *, strict: bool = False) -> list[FunctionInfo]:
        """The definitions a call target in `module` can mean, most specific first.

        `name(...)` defined in the same module, or imported into it, resolves
        to that definition only; `alias.name(...)` with `alias` an imported
        module resolves inside that module. Anything else — a method on an
        object of unknown type — falls back to every function of that name,
        unless `strict`: then a bare name that is neither defined nor imported
        here (a local variable, a builtin) resolves to nothing.
        """
        if isinstance(ref, ast.Name):
            local = [f for f in self.functions.get(ref.id, []) if f.module is module and f.class_name is None]
            if local:
                return local
            imported = module.imports.get(ref.id)
            if imported and imported[1]:
                target = imported[1]
                found = [
                    f
                    for m in self.module_by_suffix(_absolute(module, imported[0]))
                    for f in self.functions.get(target, [])
                    if f.module is m and f.class_name is None
                ]
                if found:
                    return found
            if strict:
                return []
            return [f for f in self.functions.get(ref.id, []) if f.class_name is None] or list(
                self.functions.get(ref.id, [])
            )
        if isinstance(ref, ast.Attribute) and isinstance(ref.value, ast.Name):
            # `item_service.get(...)` where `item_service = ItemService()` at
            # module level, here or in the module it was imported from.
            instance_class = self.instance_class(module, ref.value.id)
            if instance_class is not None:
                methods = self.methods_of(instance_class, ref.attr)
                if methods:
                    return methods
            imported = module.imports.get(ref.value.id)
            if imported:
                mod = imported[0] if imported[1] is None else f"{imported[0]}.{imported[1]}"
                found = [
                    f
                    for m in self.module_by_suffix(_absolute(module, mod))
                    for f in self.functions.get(ref.attr, [])
                    if f.module is m and f.class_name is None
                ]
                if found:
                    return found
        if isinstance(ref, ast.Attribute):
            return list(self.functions.get(ref.attr, []))
        return []

    def instance_class(self, module: Module, name: str) -> str | None:
        """The class of a module-level singleton: `name = SomeService()`."""
        sources: list[Module] = [module]
        imported = module.imports.get(name)
        if imported and imported[1]:
            sources = self.module_by_suffix(_absolute(module, imported[0])) or sources
            name = imported[1]
        for m, value in self.assignments.get(name, []):
            if m not in sources or not isinstance(value, ast.Call):
                continue
            func = value.func
            cls = func.id if isinstance(func, ast.Name) else func.attr if isinstance(func, ast.Attribute) else None
            if cls and cls in self.classes:
                return cls
        return None

    def module_by_suffix(self, dotted_name: str) -> list[Module]:
        """Modules whose dotted name ends with `dotted_name` (imports are often relative)."""
        tail = dotted_name.split(".")
        out: list[Module] = []
        for m in self.modules:
            parts = m.name.split(".")
            if parts[-len(tail):] == tail:
                out.append(m)
        return out


def _absolute(module: Module, imported: str) -> str:
    """Resolve `..repository` against the importing module; absolute names pass through."""
    level = len(imported) - len(imported.lstrip("."))
    if level == 0:
        return imported
    base = module.name.split(".")
    is_package = module.rel.endswith("__init__.py")
    keep = len(base) - level + (1 if is_package else 0)
    rest = imported[level:]
    parts = [*base[: max(keep, 0)], *([rest] if rest else [])]
    return ".".join(p for p in parts if p)


def _module_name(rel: str) -> str:
    parts = rel[:-3].split("/")
    if parts[-1] == "__init__":
        parts = parts[:-1]
    return ".".join(parts)


def _imports(nodes: list[ast.AST]) -> dict[str, tuple[str, str | None]]:
    out: dict[str, tuple[str, str | None]] = {}
    for node in nodes:
        if isinstance(node, ast.Import):
            for alias in node.names:
                out[alias.asname or alias.name.split(".")[0]] = (alias.name, None)
        elif isinstance(node, ast.ImportFrom):
            base = ("." * node.level) + (node.module or "")
            for alias in node.names:
                out[alias.asname or alias.name] = (base, alias.name)
    return out


def _suppressions(lines: list[str]) -> dict[int, Suppression]:
    out: dict[int, Suppression] = {}
    for i, text in enumerate(lines, start=1):
        if "fpg" not in text.lower():
            continue
        m = _SUPPRESS.search(text)
        if m is None:
            continue
        rules = frozenset(r.strip().upper() for r in m.group("rules").split(",") if r.strip())
        reason = m.group("reason").strip().lstrip("-—:").strip()
        out[i] = Suppression(rules, reason, i)
    return out


def iter_python_files(
    root: Path, *, include_tests: bool, exclude: list[str]
) -> Iterator[tuple[Path, str]]:
    root = root.resolve()
    if root.is_file():
        yield root, root.name
        return
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in DEFAULT_EXCLUDE_DIRS and not d.startswith("."))
        for name in sorted(filenames):
            if not name.endswith(".py"):
                continue
            path = Path(dirpath) / name
            rel = path.relative_to(root).as_posix()
            if not include_tests and is_test_path(rel):
                continue
            if any(fnmatch.fnmatch(rel, pat) for pat in exclude):
                continue
            yield path, rel


def load_project(root: Path, *, include_tests: bool = False, exclude: list[str] | None = None) -> Project:
    modules: list[Module] = []
    errors: list[ParseError] = []
    for path, rel in iter_python_files(root, include_tests=include_tests, exclude=exclude or []):
        try:
            source = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            errors.append(ParseError(rel, f"unreadable: {exc}"))
            continue
        try:
            tree = ast.parse(source, filename=rel, type_comments=False)
        except SyntaxError as exc:
            errors.append(ParseError(rel, f"syntax error at line {exc.lineno}: {exc.msg}"))
            continue
        lines = source.splitlines()
        nodes = list(ast.walk(tree))
        modules.append(
            Module(
                path=path,
                rel=rel,
                name=_module_name(rel),
                tree=tree,
                lines=lines,
                imports=_imports(nodes),
                suppressions=_suppressions(lines),
                nodes=nodes,
            )
        )
    return Project(root.resolve(), modules, errors)
