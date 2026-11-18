"""Backward-compatible entrypoint for the provider-neutral host upgrade drill."""
from self_managed_upgrade_smoke import *  # noqa: F401,F403

if __name__ == "__main__":
    sys.exit(main())
