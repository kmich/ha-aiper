"""Compatibility package for the runtime-safe Aiper API client.

Python resolves a package directory before a same-named ``api.py`` module, so
existing imports such as ``from .api import AiperApi`` now use the safe client
without rewriting the large legacy file.
"""
from __future__ import annotations

from ..api_safe import AiperApi

__all__ = ["AiperApi"]
