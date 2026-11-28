"""Minimal, strict (de)serialization for frozen dataclass value objects.

Supports nested dataclasses, ``tuple[X, ...]``, ``list[X]``, ``dict[str, X]``, ``X | None``
and primitives. Unknown keys are rejected so corrupt manifests fail loudly.
"""

from __future__ import annotations

import dataclasses
import json
import types
import typing
from typing import Any, TypeVar, Union, get_args, get_origin

T = TypeVar("T")


def to_jsonable(value: Any) -> Any:
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        return {f.name: to_jsonable(getattr(value, f.name)) for f in dataclasses.fields(value)}
    if isinstance(value, (list, tuple)):
        return [to_jsonable(v) for v in value]
    if isinstance(value, dict):
        return {str(k): to_jsonable(v) for k, v in value.items()}
    return value


def dumps(value: Any, *, indent: int | None = 2) -> str:
    return json.dumps(to_jsonable(value), indent=indent, sort_keys=False, allow_nan=False)


_HINTS: dict[type, dict[str, Any]] = {}


def _hints(cls: type) -> dict[str, Any]:
    if cls not in _HINTS:
        _HINTS[cls] = typing.get_type_hints(cls)
    return _HINTS[cls]


def _convert(tp: Any, value: Any, where: str) -> Any:
    origin = get_origin(tp)
    if tp is Any:
        return value
    if origin in (Union, types.UnionType):
        args = get_args(tp)
        if value is None and type(None) in args:
            return None
        non_none = [a for a in args if a is not type(None)]
        if len(non_none) == 1:
            return _convert(non_none[0], value, where)
        return value
    if origin is tuple:
        args = get_args(tp)
        if not isinstance(value, list | tuple):
            raise ValueError(f"{where}: expected a list")
        if len(args) == 2 and args[1] is Ellipsis:
            return tuple(_convert(args[0], v, f"{where}[]") for v in value)
        return tuple(_convert(a, v, f"{where}[]") for a, v in zip(args, value, strict=True))
    if origin is list:
        (arg,) = get_args(tp)
        if not isinstance(value, list):
            raise ValueError(f"{where}: expected a list")
        return [_convert(arg, v, f"{where}[]") for v in value]
    if origin is dict:
        _, arg = get_args(tp)
        if not isinstance(value, dict):
            raise ValueError(f"{where}: expected a mapping")
        return {str(k): _convert(arg, v, f"{where}.{k}") for k, v in value.items()}
    if isinstance(tp, type) and dataclasses.is_dataclass(tp):
        return from_dict(tp, value, where=where)
    if tp is float and isinstance(value, int) and not isinstance(value, bool):
        return float(value)
    if isinstance(tp, type) and tp in (str, int, float, bool) and not isinstance(value, tp):
        raise ValueError(f"{where}: expected {tp.__name__}, got {type(value).__name__}")
    return value


def from_dict(cls: type[T], data: Any, *, where: str = "$") -> T:
    if not isinstance(data, dict):
        raise ValueError(f"{where}: expected a mapping for {cls.__name__}")
    hints = _hints(cls)
    fields = {f.name: f for f in dataclasses.fields(cls)}  # type: ignore[arg-type]
    unknown = set(data) - set(fields)
    if unknown:
        raise ValueError(f"{where}: unknown field(s) {', '.join(sorted(unknown))}")
    kwargs = {}
    for name, field in fields.items():
        if name in data:
            kwargs[name] = _convert(hints[name], data[name], f"{where}.{name}")
        elif field.default is dataclasses.MISSING and field.default_factory is dataclasses.MISSING:
            raise ValueError(f"{where}: missing field '{name}'")
    return cls(**kwargs)
