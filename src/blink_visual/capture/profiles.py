"""Built-in browser profiles. Different profiles help expose user-agent cloaking."""

from __future__ import annotations

from ..config import ProfileConfig, Viewport

BUILTIN_PROFILES: dict[str, ProfileConfig] = {
    "desktop-chrome": ProfileConfig(
        viewport=Viewport(width=1280, height=900),
        user_agent=(
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
        ),
    ),
    "mobile-safari-ish": ProfileConfig(
        viewport=Viewport(width=390, height=844),
        user_agent=(
            "Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) AppleWebKit/605.1.15 "
            "(KHTML, like Gecko) Version/18.1 Mobile/15E148 Safari/604.1"
        ),
        is_mobile=True,
        has_touch=True,
    ),
}
