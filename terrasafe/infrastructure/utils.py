"""Shared utility functions for TerraSafe"""


def categorize_vulnerability(message: str) -> str:
    """
    Categorize vulnerability based on message content.

    Args:
        message: Vulnerability message

    Returns:
        Category string (e.g., 'hardcoded_secret', 'open_port', 'public_access', etc.)
    """
    message_lower = message.lower()

    if 'hardcoded' in message_lower or 'secret' in message_lower:
        return 'hardcoded_secret'
    elif 'open security group' in message_lower or 'exposed to internet' in message_lower:
        return 'open_port'
    elif 's3 bucket' in message_lower and 'public' in message_lower:
        return 'public_access'
    elif 'unencrypted' in message_lower:
        return 'unencrypted_storage'
    elif 'mfa' in message_lower or 'authentication' in message_lower:
        return 'weak_authentication'
    else:
        return 'other'
