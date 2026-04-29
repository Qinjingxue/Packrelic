from typing import Any

from sunpack.config.schema import ConfigField


DEFAULT_CLI_LANGUAGE = "en"


def normalize_cli_language(value: Any) -> str:
    normalized = str(value or "").strip().lower()
    return "zh" if normalized == "zh" else DEFAULT_CLI_LANGUAGE


CONFIG_FIELDS = (
    ConfigField(
        path=("cli", "language"),
        default=DEFAULT_CLI_LANGUAGE,
        normalize=normalize_cli_language,
        owner=__name__,
    ),
)
