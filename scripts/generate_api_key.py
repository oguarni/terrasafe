#!/usr/bin/env python3
"""
Utility script to generate API key hashes for TerraSafe.

This script helps generate bcrypt hashes of API keys for use in the
TERRASAFE_API_KEY_HASH environment variable.

Usage:
    python scripts/generate_api_key.py
    python scripts/generate_api_key.py --key "your-api-key"
    python scripts/generate_api_key.py --random
"""

import argparse
import secrets
import string
import bcrypt
import sys


def generate_random_api_key(length: int = 32) -> str:
    """
    Generate a random API key.

    Args:
        length: Length of the API key (default: 32)

    Returns:
        Random API key string
    """
    alphabet = string.ascii_letters + string.digits + "-_"
    return ''.join(secrets.choice(alphabet) for _ in range(length))


def hash_api_key(api_key: str) -> str:
    """
    Hash an API key using bcrypt.

    Args:
        api_key: Plain text API key

    Returns:
        Bcrypt hashed API key
    """
    return bcrypt.hashpw(api_key.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')


def main():
    """Main function."""
    parser = argparse.ArgumentParser(
        description="Generate API key hashes for TerraSafe",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Generate hash for a specific key
  python scripts/generate_api_key.py --key "my-secret-key-123"

  # Generate a random key and its hash
  python scripts/generate_api_key.py --random

  # Interactive mode (default)
  python scripts/generate_api_key.py
        """
    )

    parser.add_argument(
        '--key',
        type=str,
        help='API key to hash (if not provided, will prompt or use --random)'
    )

    parser.add_argument(
        '--random',
        action='store_true',
        help='Generate a random API key'
    )

    parser.add_argument(
        '--length',
        type=int,
        default=32,
        help='Length of random API key (default: 32)'
    )

    args = parser.parse_args()

    print("=" * 70)
    print("TerraSafe API Key Hash Generator")
    print("=" * 70)
    print()

    # Determine the API key
    if args.random:
        api_key = generate_random_api_key(args.length)
        print(f"Generated random API key: {api_key}")
        print()
    elif args.key:
        api_key = args.key
        print(f"Using provided API key: {api_key}")
        print()
    else:
        # Interactive mode
        print("Enter your API key (or press Enter to generate a random one):")
        api_key = input("> ").strip()

        if not api_key:
            api_key = generate_random_api_key()
            print(f"\nGenerated random API key: {api_key}")
            print()

    # Validate API key
    if len(api_key) < 16:
        print("WARNING: API key is shorter than 16 characters.")
        print("Consider using a longer key for better security.")
        print()
        response = input("Continue anyway? (y/N): ").strip().lower()
        if response != 'y':
            print("Aborted.")
            sys.exit(1)
        print()

    # Generate hash
    print("Generating bcrypt hash...")
    hashed_key = hash_api_key(api_key)

    print()
    print("=" * 70)
    print("RESULTS")
    print("=" * 70)
    print()
    print(f"Plain API Key:  {api_key}")
    print(f"Hashed Key:     {hashed_key}")
    print()
    print("=" * 70)
    print("USAGE INSTRUCTIONS")
    print("=" * 70)
    print()
    print("1. Add the following to your .env file:")
    print()
    print(f"   TERRASAFE_API_KEY_HASH={hashed_key}")
    print(f"   API_KEY_HASH={hashed_key}")
    print()
    print("2. Use this API key in your requests:")
    print()
    print(f"   X-API-Key: {api_key}")
    print()
    print("3. Example curl command:")
    print()
    print(f"   curl -X POST -H 'X-API-Key: {api_key}' \\")
    print("        -F 'file=@terraform.tf' \\")
    print("        http://localhost:8000/scan")
    print()
    print("=" * 70)
    print()
    print("IMPORTANT SECURITY NOTES:")
    print("- Store the plain API key securely (e.g., password manager)")
    print("- Do NOT commit the plain API key to version control")
    print("- Only the hashed key should be in environment variables")
    print("- Rotate your API keys regularly")
    print()


if __name__ == "__main__":
    main()
