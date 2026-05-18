#!/usr/bin/env python3
"""Generate production secrets for TerraVault.

Prints a block of environment variables ready to paste into .env:
  - POSTGRES_PASSWORD
  - GRAFANA_ADMIN_PASSWORD
  - TERRAVAULT_API_KEY        (plaintext — store in your password manager, do NOT commit)
  - TERRAVAULT_API_KEY_HASH   (bcrypt — safe to put in .env)

Usage:
    python scripts/generate_secrets.py
    python scripts/generate_secrets.py --no-banner > .env.secrets
"""

import argparse
import secrets
import string

import bcrypt


ALPHABET = string.ascii_letters + string.digits + "-_"


def random_secret(length: int) -> str:
    return "".join(secrets.choice(ALPHABET) for _ in range(length))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--no-banner", action="store_true", help="Suppress human-readable banner")
    args = parser.parse_args()

    postgres_password = random_secret(32)
    grafana_password = random_secret(24)
    api_key = random_secret(40)
    api_key_hash = bcrypt.hashpw(api_key.encode(), bcrypt.gensalt()).decode()

    if not args.no_banner:
        print("# ---------------------------------------------------------------")
        print("# TerraVault production secrets — generated locally, never logged")
        print("# Append/replace these in .env, then DELETE this output.")
        print("# Store TERRAVAULT_API_KEY (plaintext) in a password manager.")
        print("# ---------------------------------------------------------------")
    print(f"POSTGRES_PASSWORD={postgres_password}")
    print(f"GRAFANA_ADMIN_PASSWORD={grafana_password}")
    print(f"TERRAVAULT_API_KEY={api_key}")
    print(f"TERRAVAULT_API_KEY_HASH={api_key_hash}")


if __name__ == "__main__":
    main()
