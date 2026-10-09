"""In-memory thread-safe guestbook comment storage for Stored XSS simulation."""

import threading
from typing import Any

from xsslab.defense.encoder import ContextAwareEncoder


class StoredXSSStorage:
    """Thread-safe in-memory comment repository for Stored XSS lab simulations."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._comments: list[dict[str, Any]] = []

    def add_comment(self, author: str, content: str, mode: str = "insecure") -> dict[str, Any]:
        """Store a comment record under insecure or hardened semantics.

        Args:
            author: Name of user posting the comment.
            content: Raw or encoded text of the comment.
            mode: 'insecure' stores raw HTML; 'hardened' applies HTML entity encoding.

        Returns:
            Dictionary containing stored record metadata.
        """
        with self._lock:
            stored_author = author
            stored_content = content
            if mode == "hardened":
                stored_author = ContextAwareEncoder.encode_for_html(author)
                stored_content = ContextAwareEncoder.encode_for_html(content)

            record: dict[str, Any] = {
                "id": len(self._comments) + 1,
                "author": stored_author,
                "content": stored_content,
                "mode": mode,
            }
            self._comments.append(record)
            return record

    def get_comments(self) -> list[dict[str, Any]]:
        """Retrieve all currently stored comments."""
        with self._lock:
            return [dict(comment) for comment in self._comments]

    def clear(self) -> None:
        """Reset and wipe all stored comments."""
        with self._lock:
            self._comments.clear()

    def count(self) -> int:
        """Return number of currently stored comments."""
        with self._lock:
            return len(self._comments)
