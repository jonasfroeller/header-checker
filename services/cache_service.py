import time
import threading
from typing import Dict, Any, Optional


class CacheService:
    """Simple in-memory cache with TTL support"""

    def __init__(self, default_ttl: int = 3600):  # 1 hour default TTL
        self.cache: Dict[str, Dict[str, Any]] = {}
        self.default_ttl = default_ttl
        self.lock = threading.RLock()
        self.hits = 0
        self.misses = 0

    def get(self, key: str) -> Optional[Dict[str, Any]]:
        """Get value from cache if not expired"""
        with self.lock:
            if key in self.cache:
                entry = self.cache[key]
                if time.time() < entry['expires_at']:
                    self.hits += 1
                    return entry['data']
                else:
                    # Remove expired entry
                    del self.cache[key]

            self.misses += 1
            return None

    def set(self, key: str, value: Dict[str, Any], ttl: Optional[int] = None) -> None:
        """Set value in cache with TTL"""
        if ttl is None:
            ttl = self.default_ttl

        expires_at = time.time() + ttl

        with self.lock:
            self.cache[key] = {
                'data': value,
                'expires_at': expires_at,
                'created_at': time.time()
            }

    def delete(self, key: str) -> bool:
        """Delete specific key from cache"""
        with self.lock:
            if key in self.cache:
                del self.cache[key]
                return True
            return False

    def clear(self) -> None:
        """Clear all cache entries"""
        with self.lock:
            self.cache.clear()
            self.hits = 0
            self.misses = 0

    def cleanup_expired(self) -> int:
        """Remove expired entries and return count of removed items"""
        current_time = time.time()
        expired_keys = []

        with self.lock:
            for key, entry in self.cache.items():
                if current_time >= entry['expires_at']:
                    expired_keys.append(key)

            for key in expired_keys:
                del self.cache[key]

        return len(expired_keys)

    def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics"""
        with self.lock:
            total_requests = self.hits + self.misses
            hit_rate = (self.hits / total_requests *
                        100) if total_requests > 0 else 0

            return {
                'total_entries': len(self.cache),
                'hits': self.hits,
                'misses': self.misses,
                'hit_rate': round(hit_rate, 2),
                'expired_cleaned': self.cleanup_expired()
            }
