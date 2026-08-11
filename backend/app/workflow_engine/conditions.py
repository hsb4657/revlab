"""条件表达式求值:支持 == != > < >= <= AND OR NOT 与括号(数值/字符串比较)"""
from __future__ import annotations
import re

TOKEN_RE = re.compile(r"\s*(==|!=|>=|<=|>|<|AND|OR|NOT|\(|\)|[^\s()]+)")


def _tokens(expr: str) -> list:
    return [t for t in TOKEN_RE.findall(expr) if t.strip()]


def _to_number(s) -> float | None:
    try:
        return float(s)
    except (TypeError, ValueError):
        return None


def _cmp(a, b) -> bool:
    na, nb = _to_number(a), _to_number(b)
    if na is not None and nb is not None:
        return na, nb
    return str(a), str(b)


def _parse(tokens: list, pos=0):
    """递归下降:expr := term (OR term)* ; term := factor (AND factor)*; factor := NOT factor | ( expr ) | cmp"""
    def peek():
        return tokens[pos] if pos < len(tokens) else None

    def parse_factor():
        nonlocal pos
        t = peek()
        if t == "NOT":
            pos += 1
            return not parse_factor()
        if t == "(":
            pos += 1
            v = parse_or()
            if peek() == ")":
                pos += 1
            return v
        return parse_cmp()

    def parse_cmp():
        nonlocal pos
        left = peek()
        if left is None:
            return False
        pos += 1
        op = peek()
        if op in ("==", "!=", ">=", "<=", ">", "<"):
            pos += 1
            right = peek()
            pos += 1
            if right is None:
                return False
            a, b = _cmp(left, right)
            if op == "==":
                return a == b
            if op == "!=":
                return a != b
            if op == ">=":
                return a >= b
            if op == "<=":
                return a <= b
            if op == ">":
                return a > b
            if op == "<":
                return a < b
        # 无运算符:非空字符串为真
        return bool(left) and left.lower() not in ("false", "0", "none", "null", "no")

    def parse_and():
        nonlocal pos
        v = parse_factor()
        while peek() == "AND":
            pos += 1
            r = parse_factor()
            v = v and r
        return v

    def parse_or():
        nonlocal pos
        v = parse_and()
        while peek() == "OR":
            pos += 1
            r = parse_and()
            v = v or r
        return v

    return parse_or()


def evaluate(expr, pool: dict) -> bool:
    """求值条件表达式。先用变量池解析占位符,再解析表达式。"""
    from .variables import resolve
    if not expr or not str(expr).strip():
        return False
    s = resolve(str(expr), pool)
    s = s.strip()
    try:
        return bool(_parse(_tokens(s)))
    except Exception:
        # 退化:布尔文本
        return s.lower() in ("true", "yes", "1")
