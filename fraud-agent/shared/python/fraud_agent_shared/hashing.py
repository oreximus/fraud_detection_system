"""SHA-256 hashing utilities for privacy-preserving community reporting.

Raw message text NEVER leaves the device. Only hashed indicators are shared.
"""
import hashlib
import hmac
from typing import Union

from .types import IndicatorType


def get_salt() -> str:
    """Get or generate salt for indicator hashing.
    
    In production, this should be retrieved from secure storage
    (e.g., Android Keystore or OS keychain).
    """
    import os
    salt = os.environ.get("FRAUD_AGENT_SALT")
    if salt is None:
        salt = hashlib.sha256(os.urandom(32)).hexdigest()[:32]
    return salt


async def hash_indicator(
    indicator: str,
    indicator_type: IndicatorType,
    salt: Union[str, None] = None
) -> str:
    """Hash an indicator using SHA-256 with salt for privacy-preserving sharing.
    
    Args:
        indicator: The raw indicator value (URL, phone, email)
        indicator_type: Type of indicator for domain separation
        salt: Optional salt, retrieved from secure storage if not provided
    
    Returns:
        SHA-256 hash of the salted, typed indicator
    """
    if salt is None:
        salt = get_salt()
    
    combined = f"{indicator_type.value}:{salt}:{indicator}"
    return hashlib.sha256(combined.encode("utf-8")).hexdigest()


def hash_indicator_sync(
    indicator: str,
    indicator_type: IndicatorType,
    salt: Union[str, None] = None
) -> str:
    """Synchronous version of hash_indicator for non-async contexts."""
    if salt is None:
        salt = get_salt()
    
    combined = f"{indicator_type.value}:{salt}:{indicator}"
    return hashlib.sha256(combined.encode("utf-8")).hexdigest()


def verify_hash(
    indicator: str,
    indicator_type: IndicatorType,
    hash_value: str,
    salt: Union[str, None] = None
) -> bool:
    """Verify that an indicator matches a hash value.
    
    Args:
        indicator: The raw indicator to verify
        indicator_type: Type of indicator
        hash_value: The expected hash value
        salt: Optional salt used during hashing
    
    Returns:
        True if the indicator matches the hash
    """
    computed_hash = hash_indicator_sync(indicator, indicator_type, salt)
    return hmac.compare_digest(computed_hash, hash_value)


def hash_content(content: str) -> str:
    """Hash content for logging purposes (does not include salt).
    
    Only use this for internal logging, not for community sharing.
    """
    return hashlib.sha256(content.encode("utf-8")).hexdigest()