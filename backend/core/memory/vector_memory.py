"""Vector-backed persistent memory for the LLM-driven agent.

Uses TF-IDF for lightweight semantic search without external dependencies.
Memories are stored in SQLite via SQLAlchemy and persisted per-target.
"""

import json
import logging
import math
import re
import time
import uuid
from collections import Counter
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


@dataclass
class MemoryEntry:
    """A single memory entry."""
    id: str
    content: str
    category: str
    metadata: Dict[str, Any]
    target: str
    operation_id: str
    created_at: float
    score: float = 0.0  # Populated during search


class VectorMemory:
    """In-process vector memory with TF-IDF search.

    Provides semantic-ish search over stored memories without requiring
    external vector databases or embedding models. Good enough for
    operational memory during a single assessment.

    For production use, can be backed by SQLAlchemy models (see memory model).
    This implementation uses in-memory storage with optional file persistence.
    """

    def __init__(self, target: str, operation_id: str, persist_dir: Optional[str] = None):
        self.target = target
        self.operation_id = operation_id
        self.persist_dir = persist_dir
        self._entries: List[MemoryEntry] = []
        self._idf_cache: Dict[str, float] = {}
        self._dirty = False

        # Load from disk if persist_dir exists.
        # This loads ALL memories for this target (across operations),
        # enabling cross-engagement learning. Future scans against the
        # same target automatically get prior recon, findings, and context.
        if persist_dir:
            self._load()

    def store(
        self,
        content: str,
        category: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> MemoryEntry:
        """Store a new memory entry.

        Args:
            content: Memory content text.
            category: Category (recon, finding, credential, observation, hypothesis, evidence).
            metadata: Optional metadata dict.

        Returns:
            The created MemoryEntry.
        """
        entry = MemoryEntry(
            id=str(uuid.uuid4())[:8],
            content=content,
            category=category,
            metadata=metadata or {},
            target=self.target,
            operation_id=self.operation_id,
            created_at=time.time(),
        )
        self._entries.append(entry)
        self._idf_cache.clear()  # Invalidate IDF cache
        self._dirty = True

        if self.persist_dir:
            self._save()

        logger.debug(f"Memory stored: [{category}] {content[:80]}...")
        return entry

    def search(
        self,
        query: str,
        category: Optional[str] = None,
        top_k: int = 5,
    ) -> List[MemoryEntry]:
        """Search memories by keyword relevance (TF-IDF).

        Args:
            query: Search query (keywords or natural language).
            category: Optional category filter.
            top_k: Number of results to return.

        Returns:
            List of MemoryEntry with scores, sorted by relevance.
        """
        if not self._entries:
            return []

        # Filter by category if specified
        candidates = self._entries
        if category:
            candidates = [e for e in candidates if e.category == category]

        if not candidates:
            return []

        # Tokenize query
        query_tokens = self._tokenize(query)
        if not query_tokens:
            return candidates[:top_k]

        # Calculate IDF across all entries
        self._compute_idf()

        # Score each candidate
        scored = []
        for entry in candidates:
            score = self._tfidf_score(query_tokens, entry.content)
            # Boost recent entries slightly
            recency_bonus = 0.1 * (1.0 / (1.0 + (time.time() - entry.created_at) / 3600))
            entry_copy = MemoryEntry(
                id=entry.id,
                content=entry.content,
                category=entry.category,
                metadata=entry.metadata,
                target=entry.target,
                operation_id=entry.operation_id,
                created_at=entry.created_at,
                score=score + recency_bonus,
            )
            scored.append(entry_copy)

        # Sort by score descending
        scored.sort(key=lambda e: e.score, reverse=True)
        return scored[:top_k]

    def list_entries(self, category: Optional[str] = None) -> List[MemoryEntry]:
        """List all stored memories, optionally filtered by category."""
        if category:
            return [e for e in self._entries if e.category == category]
        return list(self._entries)

    def get_overview(self, max_entries: int = 10) -> str:
        """Get a text overview of stored memories for prompt injection."""
        if not self._entries:
            return "No memories stored yet."

        by_category: Dict[str, List[MemoryEntry]] = {}
        for entry in self._entries:
            by_category.setdefault(entry.category, []).append(entry)

        lines = [f"**{len(self._entries)} memories stored**:"]
        for cat, entries in sorted(by_category.items()):
            lines.append(f"- {cat}: {len(entries)} entries")
            for entry in entries[-3:]:  # Last 3 per category
                preview = entry.content[:100].replace("\n", " ")
                lines.append(f"  - {preview}")

        return "\n".join(lines)

    def get_plan(self) -> Optional[Dict[str, Any]]:
        """Get the most recent plan from memory."""
        plan_entries = [e for e in self._entries if e.category == "plan"]
        if plan_entries:
            try:
                return json.loads(plan_entries[-1].content)
            except (json.JSONDecodeError, TypeError):
                return None
        return None

    def store_plan(self, plan: Dict[str, Any]) -> None:
        """Store a plan in memory."""
        self.store(
            content=json.dumps(plan),
            category="plan",
            metadata={"type": "operation_plan"},
        )

    # ------------------------------------------------------------------
    # TF-IDF implementation
    # ------------------------------------------------------------------

    @staticmethod
    def _tokenize(text: str) -> List[str]:
        """Tokenize text into lowercase words, removing stopwords."""
        stopwords = {
            "the", "a", "an", "is", "are", "was", "were", "be", "been",
            "being", "have", "has", "had", "do", "does", "did", "will",
            "would", "could", "should", "may", "might", "can", "shall",
            "to", "of", "in", "for", "on", "with", "at", "by", "from",
            "as", "into", "through", "during", "before", "after", "and",
            "but", "or", "not", "no", "if", "then", "than", "that",
            "this", "it", "its", "i", "my", "we", "our", "you", "your",
        }
        words = re.findall(r'[a-z0-9]+', text.lower())
        return [w for w in words if w not in stopwords and len(w) > 1]

    def _compute_idf(self) -> None:
        """Compute inverse document frequency across all entries."""
        if self._idf_cache:
            return

        n_docs = len(self._entries)
        if n_docs == 0:
            return

        # Count documents containing each term
        doc_freq: Counter = Counter()
        for entry in self._entries:
            tokens = set(self._tokenize(entry.content))
            for token in tokens:
                doc_freq[token] += 1

        # IDF = log(N / (1 + df))
        self._idf_cache = {
            term: math.log(n_docs / (1 + df))
            for term, df in doc_freq.items()
        }

    def _tfidf_score(self, query_tokens: List[str], document: str) -> float:
        """Calculate TF-IDF similarity between query tokens and a document."""
        doc_tokens = self._tokenize(document)
        if not doc_tokens:
            return 0.0

        # Term frequency in document
        tf: Counter = Counter(doc_tokens)
        max_tf = max(tf.values()) if tf else 1

        score = 0.0
        for token in query_tokens:
            if token in tf:
                # Normalized TF * IDF
                normalized_tf = tf[token] / max_tf
                idf = self._idf_cache.get(token, 0.0)
                score += normalized_tf * idf

        return score

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def _save(self) -> None:
        """Save memories to disk."""
        if not self.persist_dir:
            return

        import os
        os.makedirs(self.persist_dir, exist_ok=True)

        data = [
            {
                "id": e.id,
                "content": e.content,
                "category": e.category,
                "metadata": e.metadata,
                "target": e.target,
                "operation_id": e.operation_id,
                "created_at": e.created_at,
            }
            for e in self._entries
        ]

        filepath = os.path.join(self.persist_dir, "memories.json")
        with open(filepath, "w") as f:
            json.dump(data, f, indent=2)

        self._dirty = False

    def _load(self) -> None:
        """Load memories from disk."""
        if not self.persist_dir:
            return

        import os
        filepath = os.path.join(self.persist_dir, "memories.json")
        if not os.path.exists(filepath):
            return

        try:
            with open(filepath) as f:
                data = json.load(f)

            self._entries = [
                MemoryEntry(
                    id=d["id"],
                    content=d["content"],
                    category=d["category"],
                    metadata=d.get("metadata", {}),
                    target=d["target"],
                    operation_id=d["operation_id"],
                    created_at=d["created_at"],
                )
                for d in data
            ]
            logger.info(f"Loaded {len(self._entries)} memories from {filepath}")
        except Exception as e:
            logger.warning(f"Failed to load memories: {e}")
