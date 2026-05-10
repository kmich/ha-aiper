"""Compatibility package for the fixed Aiper API client.

Python resolves a package directory before a same-named ``api.py`` module, so
existing imports such as ``from .api import AiperApi`` now use the fixed client
without rewriting the large legacy file.
"""
from __future__ import annotations

from ..api_fixed import AiperApi

__all__ = ["AiperApi"]
