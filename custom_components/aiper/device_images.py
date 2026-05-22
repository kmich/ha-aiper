"""Helpers for Aiper device image URLs."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

DEVICE_IMAGE_KEYS = (
    "deviceModelUrl",
    "deviceModelURL",
    "deviceImageUrl",
    "deviceImageURL",
    "modelUrl",
    "modelURL",
    "imageUrl",
    "imageURL",
    "productImageUrl",
    "productImageURL",
)


def device_model_image_url(device: Mapping[str, Any]) -> str | None:
    """Return the best model image URL from a device payload."""
    for key in DEVICE_IMAGE_KEYS:
        value = device.get(key)
        if isinstance(value, str):
            url = value.strip()
            if url.startswith(("https://", "http://")):
                return url
    return None
