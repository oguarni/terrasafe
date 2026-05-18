"""
Redis caching placeholder for TerraVault.

SecureCache was removed — it was never integrated into the scan pipeline.
The scanner uses instance-level dicts for caching. Rate limiting uses
FallbackRateLimiter (in-memory) or slowapi (Redis-backed via the API layer).
"""
