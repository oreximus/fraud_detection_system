"""Unit tests for shared module hashing utilities."""
import pytest

from fraud_agent_shared.hashing import (
    hash_indicator_sync,
    verify_hash,
    hash_content,
)
from fraud_agent_shared.types import IndicatorType


class TestHashing:
    """Tests for indicator hashing functions."""

    def test_hash_indicator_url(self):
        """Test hashing a URL indicator."""
        indicator = "https://example.com/login"
        hash_val = hash_indicator_sync(indicator, IndicatorType.URL)
        
        assert isinstance(hash_val, str)
        assert len(hash_val) == 64
        assert hash_val == hash_indicator_sync(indicator, IndicatorType.URL)

    def test_hash_indicator_phone(self):
        """Test hashing a phone indicator."""
        indicator = "+1234567890"
        hash_val = hash_indicator_sync(indicator, IndicatorType.PHONE)
        
        assert isinstance(hash_val, str)
        assert len(hash_val) == 64

    def test_hash_indicator_with_salt(self):
        """Test hashing with custom salt."""
        indicator = "https://example.com"
        salt = "test_salt_12345"
        
        hash_val = hash_indicator_sync(indicator, IndicatorType.URL, salt)
        
        assert isinstance(hash_val, str)
        assert len(hash_val) == 64

    def test_different_salt_produces_different_hash(self):
        """Test that different salts produce different hashes."""
        indicator = "https://example.com"
        
        hash1 = hash_indicator_sync(indicator, IndicatorType.URL, "salt1")
        hash2 = hash_indicator_sync(indicator, IndicatorType.URL, "salt2")
        
        assert hash1 != hash2

    def test_verify_hash_valid(self):
        """Test verifying a valid hash."""
        indicator = "+1234567890"
        salt = "test_salt"
        hash_val = hash_indicator_sync(indicator, IndicatorType.PHONE, salt)
        
        assert verify_hash(indicator, IndicatorType.PHONE, hash_val, salt) is True

    def test_verify_hash_invalid(self):
        """Test verifying an invalid hash."""
        indicator = "+1234567890"
        salt = "test_salt"
        
        assert verify_hash(indicator, IndicatorType.PHONE, "invalid_hash", salt) is False

    def test_hash_content(self):
        """Test content hashing."""
        content = "Urgent: Your account has been compromised!"
        hash_val = hash_content(content)
        
        assert isinstance(hash_val, str)
        assert len(hash_val) == 64

    def test_hash_content_deterministic(self):
        """Test content hashing is deterministic."""
        content = "Test message"
        
        hash1 = hash_content(content)
        hash2 = hash_content(content)
        
        assert hash1 == hash2