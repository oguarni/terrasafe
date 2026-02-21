"""Input validation for database operations"""
import re


def validate_file_hash(file_hash: str) -> str:
    """Validate SHA-256 hash format

    Args:
        file_hash: Hash string to validate

    Returns:
        Validated hash in lowercase

    Raises:
        TypeError: If file_hash is not a string
        ValueError: If file_hash doesn't match SHA-256 format
    """
    if not isinstance(file_hash, str):
        raise TypeError("File hash must be string")

    if not re.match(r'^[a-f0-9]{64}$', file_hash.lower()):
        raise ValueError(f"Invalid SHA-256 hash format: {file_hash}")

    return file_hash.lower()


def validate_scan_id(scan_id: str) -> str:
    """Validate UUID format

    Args:
        scan_id: UUID string to validate

    Returns:
        Validated UUID in lowercase

    Raises:
        ValueError: If scan_id doesn't match UUID format
    """
    uuid_pattern = r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'

    if not re.match(uuid_pattern, scan_id.lower()):
        raise ValueError(f"Invalid UUID format: {scan_id}")

    return scan_id.lower()


def sanitize_filename(filename: str) -> str:
    """Sanitize filename for safe storage

    Args:
        filename: Filename to sanitize

    Returns:
        Sanitized filename (max 255 chars)
    """
    # Remove path traversal attempts (handle nested patterns like ....// -> ../)
    while '../' in filename or '..\\' in filename:
        filename = filename.replace('../', '').replace('..\\', '')

    # Keep only safe characters
    safe_filename = re.sub(r'[^a-zA-Z0-9._-]', '_', filename)

    return safe_filename[:255]  # Max filename length
