"""Typed condition expressions used by graph workflows.

The previous implementation converted every placeholder to text before
comparing it. That made ``True`` differ from the template literal ``true``
and silently routed malformed expressions down the default branch.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any

from .variables import _lookup


class ConditionSyntaxError(ValueError):
    """Raised when an expression contains invalid or trailing tokens."""


_PLACEHOLDER_RE = re.compile(r"\{\{\s*([^}\s]+)\s*\}\}")
_TOKEN_RE = re.compile(
    r"\s*(?:(?P<op>==|!=|>=|<=|>|<)|(?P<lpar>\()|(?P<rpar>\))|"
    r"(?P<string>'(?:\\.|[^'\\])*'|\"(?:\\.|[^\"\\])*\")|"
    r"(?P<number>-?(?:\d+\.\d+|\d+))|(?P<word>[^\s()<>!=]+))"
)


@dataclass(frozen=True)
class Token:
    kind: str
    value: Any
    offset: int


def _render(expr: str, pool: dict) -> str:
    """Substitute placeholders with JSON literals while preserving types."""
    def replace(match: re.Match) -> str:
        value = _lookup(match.group(1).strip(), pool)
        if value is None:
            return "null"
        if isinstance(value, (dict, list)):
            return json.dumps(value, ensure_ascii=False)
        return json.dumps(value, ensure_ascii=False)

    return _PLACEHOLDER_RE.sub(replace, str(expr))


def _tokenize(text: str) -> list[Token]:
    text = text.strip()
    tokens: list[Token] = []
    pos = 0
    while pos < len(text):
        match = _TOKEN_RE.match(text, pos)
        if not match:
            raise ConditionSyntaxError(f"invalid token at offset {pos}")
        kind = match.lastgroup
        raw = match.group(kind)
        if kind == "op":
            value = raw
        elif kind == "lpar":
            value = raw
        elif kind == "rpar":
            value = raw
        elif kind == "string":
            try:
                value = json.loads(raw) if raw.startswith('"') else bytes(raw[1:-1], "utf-8").decode("unicode_escape")
            except Exception as exc:
                raise ConditionSyntaxError(f"invalid string at offset {pos}") from exc
        elif kind == "number":
            value = float(raw) if "." in raw else int(raw)
        else:
            upper = raw.upper()
            if upper in {"AND", "OR", "NOT"}:
                kind, value = upper.lower(), upper
            elif upper in {"TRUE", "YES"}:
                value = True
            elif upper in {"FALSE", "NO"}:
                value = False
            elif upper in {"NULL", "NONE"}:
                value = None
            else:
                value = raw
        tokens.append(Token(kind, value, pos))
        pos = match.end()
    return tokens


class _Parser:
    def __init__(self, tokens: list[Token]):
        self.tokens = tokens
        self.pos = 0

    def peek(self) -> Token | None:
        return self.tokens[self.pos] if self.pos < len(self.tokens) else None

    def take(self, kind: str | None = None) -> Token:
        token = self.peek()
        if token is None:
            raise ConditionSyntaxError("unexpected end of expression")
        if kind and token.kind != kind:
            raise ConditionSyntaxError(f"expected {kind} at offset {token.offset}")
        self.pos += 1
        return token

    def parse(self) -> bool:
        if not self.tokens:
            raise ConditionSyntaxError("expression is empty")
        value = self.parse_or()
        if self.peek() is not None:
            token = self.peek()
            raise ConditionSyntaxError(f"unexpected token at offset {token.offset}")
        return bool(value)

    def parse_or(self) -> Any:
        value = self.parse_and()
        while self.peek() and self.peek().kind == "or":
            self.take()
            right = self.parse_and()
            value = bool(value) or bool(right)
        return value

    def parse_and(self) -> Any:
        value = self.parse_not()
        while self.peek() and self.peek().kind == "and":
            self.take()
            right = self.parse_not()
            value = bool(value) and bool(right)
        return value

    def parse_not(self) -> Any:
        if self.peek() and self.peek().kind == "not":
            self.take()
            return not bool(self.parse_not())
        if self.peek() and self.peek().kind == "lpar":
            self.take("lpar")
            value = self.parse_or()
            self.take("rpar")
            return value
        return self.parse_comparison()

    def parse_value(self) -> Any:
        token = self.take()
        if token.kind in {"op", "lpar", "rpar", "and", "or", "not"}:
            raise ConditionSyntaxError(f"expected value at offset {token.offset}")
        return token.value

    def parse_comparison(self) -> bool:
        left = self.parse_value()
        token = self.peek()
        if token is None or token.kind != "op":
            return bool(left)
        op = self.take("op").value
        right = self.parse_value()
        if op == "==":
            return left == right
        if op == "!=":
            return left != right
        try:
            if op == ">=":
                return left >= right
            if op == "<=":
                return left <= right
            if op == ">":
                return left > right
            if op == "<":
                return left < right
        except TypeError as exc:
            raise ConditionSyntaxError(f"values are not comparable: {left!r} {op} {right!r}") from exc
        raise ConditionSyntaxError(f"unsupported operator {op}")


def validate_expression(expr: str) -> str | None:
    """Return a human-readable syntax error, or ``None`` when valid."""
    if not str(expr or "").strip():
        return "expression is required"
    try:
        placeholders = _PLACEHOLDER_RE.sub("true", str(expr))
        _Parser(_tokenize(placeholders)).parse()
    except ConditionSyntaxError as exc:
        return str(exc)
    return None


def evaluate(expr: str, pool: dict) -> bool:
    """Evaluate a typed expression against the workflow variable pool."""
    if not str(expr or "").strip():
        raise ConditionSyntaxError("expression is required")
    return _Parser(_tokenize(_render(str(expr), pool))).parse()
