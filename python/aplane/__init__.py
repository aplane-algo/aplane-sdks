"""Historical handoff package for the APlane SDK.

The SDK moved to the ``aplanesdk`` package.
"""

from ._version import __version__

MOVED_TO = "aplanesdk"
MOVED_TO_REPOSITORY = "https://github.com/aplane-algo/aplanesdk"


def migration_message() -> str:
    return (
        "The APlane SDK moved from the 'aplane' package to 'aplanesdk'. "
        "Install it with: pip install aplanesdk"
    )


__all__ = ["MOVED_TO", "MOVED_TO_REPOSITORY", "__version__", "migration_message"]
