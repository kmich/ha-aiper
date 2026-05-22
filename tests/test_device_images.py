"""Tests for Aiper device image helpers."""

from __future__ import annotations

from custom_components.aiper.device_images import device_model_image_url


def test_device_model_image_url_prefers_valid_api_url() -> None:
    """Known Aiper image URL fields should be usable as entity pictures."""
    assert (
        device_model_image_url(
            {
                "deviceModelUrl": " https://static.example.test/surfer-s2.png ",
                "imageUrl": "https://static.example.test/fallback.png",
            }
        )
        == "https://static.example.test/surfer-s2.png"
    )


def test_device_model_image_url_rejects_non_url_values() -> None:
    """Only absolute HTTP(S) URLs are useful for Home Assistant pictures."""
    assert device_model_image_url({"deviceModelUrl": "surfer-s2.png"}) is None
