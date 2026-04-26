"""Hybrid relevance filter combining BM25 and semantic matching."""

import re
from typing import List, Dict, Any, Tuple
from rank_bm25 import BM25Okapi
from sentence_transformers import SentenceTransformer
import numpy as np


class HybridRelevanceFilter:
    """
    Filter CVEs by relevance to user's tech stack.

    Combines:
    - BM25: Sparse lexical matching (handles fuzzy text matches)
    - Sentence transformers: Dense semantic matching

    Only relevant CVEs reach the local LLM for reasoning.
    """

    def __init__(
        self,
        sparse_weight: float = 0.5,
        dense_weight: float = 0.5,
        relevance_threshold: float = 0.3,
        model_name: str = "all-MiniLM-L6-v2"
    ):
        """
        Initialize hybrid relevance filter.

        Args:
            sparse_weight: Weight for BM25 score (0-1)
            dense_weight: Weight for semantic score (0-1)
            relevance_threshold: Minimum combined score to pass filter
            model_name: Sentence transformer model name
        """
        self.sparse_weight = sparse_weight
        self.dense_weight = dense_weight
        self.relevance_threshold = relevance_threshold

        # Initialize models
        print("Loading semantic similarity model...")
        self.semantic_model = SentenceTransformer(model_name)
        self.bm25 = None
        self.tech_stack_corpus = []
        self.tech_stack_embeddings = None

    def _extract_version_from_string(self, version_string: str) -> str:
        """
        Extract and normalize version number from string.

        Args:
            version_string: Version string (e.g., "1.18.0", "v2.1")

        Returns:
            Normalized version string
        """
        # Remove 'v' prefix and extract version numbers
        version = re.sub(r'^v', '', version_string.lower())
        version = re.sub(r'[^0-9.]', '', version)
        return version

    def _build_tech_stack_corpus(self, tech_stack_components: List[str]) -> List[str]:
        """
        Build corpus for BM25 from tech stack components.

        Args:
            tech_stack_components: List of component names/types

        Returns:
            Tokenized corpus for BM25
        """
        corpus = []

        for component in tech_stack_components:
            # Tokenize by splitting on special characters
            tokens = re.findall(r'\w+', component.lower())
            corpus.append(tokens)

        return corpus

    def _parse_version_range(self, version_string: str) -> Tuple[str, str]:
        """
        Parse version range from affected product string.

        Args:
            version_string: Version string from CVE (e.g., "nginx 1.x")

        Returns:
            Tuple of (product_name, version_pattern)
        """
        # Try to extract product name and version
        parts = version_string.lower().split()

        if len(parts) >= 2:
            product_name = parts[0]
            version_pattern = ' '.join(parts[1:])
        else:
            product_name = version_string
            version_pattern = ''

        return product_name, version_pattern

    def _check_version_match(self, cve_version: str, component_version: str) -> bool:
        """
        Check if CVE version matches component version.

        Args:
            cve_version: Version from CVE (may include ranges like "1.x")
            component_version: Actual component version

        Returns:
            True if versions match
        """
        cve_ver = self._extract_version_from_string(cve_version)
        comp_ver = self._extract_version_from_string(component_version)

        # Handle wildcard versions (e.g., "1.x" matches "1.18.0")
        if 'x' in cve_ver or '*' in cve_ver:
            # Match major version
            cve_major = cve_ver.split('.')[0]
            comp_major = comp_ver.split('.')[0]
            return cve_major == comp_major

        # Exact match
        return cve_ver == comp_ver

    def fit(self, tech_stack_components: List[str]):
        """
        Build index from tech stack components.

        Args:
            tech_stack_components: List of component names/types/versions
        """
        self.tech_stack_corpus = tech_stack_components

        # Build BM25 index
        tokenized_corpus = self._build_tech_stack_corpus(tech_stack_components)
        self.bm25 = BM25Okapi(tokenized_corpus)

        # Build semantic embeddings
        self.tech_stack_embeddings = self.semantic_model.encode(
            tech_stack_components,
            convert_to_numpy=True
        )

        print(f"Built relevance filter index for {len(tech_stack_components)} tech stack components")

    def _compute_sparse_score(self, query: str) -> float:
        """
        Compute BM25 score for query against tech stack.

        Args:
            query: Query string (CVE description or affected product)

        Returns:
            Maximum BM25 score
        """
        if self.bm25 is None:
            return 0.0

        # Tokenize query
        query_tokens = re.findall(r'\w+', query.lower())

        # Get BM25 scores
        scores = self.bm25.get_scores(query_tokens)

        # Return max score (best match)
        return float(np.max(scores)) if len(scores) > 0 else 0.0

    def _compute_dense_score(self, query: str) -> float:
        """
        Compute semantic similarity score for query.

        Args:
            query: Query string

        Returns:
            Maximum cosine similarity score
        """
        if self.tech_stack_embeddings is None:
            return 0.0

        # Encode query
        query_embedding = self.semantic_model.encode(
            [query],
            convert_to_numpy=True
        )[0]

        # Compute cosine similarity
        similarities = np.dot(self.tech_stack_embeddings, query_embedding) / (
            np.linalg.norm(self.tech_stack_embeddings, axis=1) *
            np.linalg.norm(query_embedding) + 1e-8
        )

        # Return max score
        return float(np.max(similarities))

    def score_cve(self, cve: Dict[str, Any]) -> float:
        """
        Compute combined relevance score for a CVE.

        Args:
            cve: CVE dictionary

        Returns:
            Combined relevance score (0-1)
        """
        scores = []

        # Score based on description
        description = cve.get('description', '') or cve.get('summary', {}).get('brief_description', '')
        if description:
            sparse_desc = self._compute_sparse_score(description)
            dense_desc = self._compute_dense_score(description)
            combined_desc = (
                self.sparse_weight * sparse_desc +
                self.dense_weight * dense_desc
            )
            scores.append(combined_desc)

        # Score based on affected products
        for product in cve.get('affected_products', [])[:3]:  # Limit to first 3
            sparse_prod = self._compute_sparse_score(product)
            dense_prod = self._compute_dense_score(product)
            combined_prod = (
                self.sparse_weight * sparse_prod +
                self.dense_weight * dense_prod
            )
            scores.append(combined_prod)

        # Return maximum score across all signals
        return float(np.max(scores)) if scores else 0.0

    def filter_cves(self, cves: List[Dict[str, Any]]) -> Tuple[List[Dict[str, Any]], Dict[str, float]]:
        """
        Filter CVEs by relevance to tech stack.

        Args:
            cves: List of CVE dictionaries

        Returns:
            Tuple of (filtered_cves, scores_dict mapping cve_id to score)
        """
        filtered = []
        scores = {}

        for cve in cves:
            cve_id = cve.get('cve_id', 'unknown')
            score = self.score_cve(cve)
            scores[cve_id] = score

            if score >= self.relevance_threshold:
                # Add score to CVE for downstream use
                cve['relevance_score'] = score
                filtered.append(cve)

        print(f"Filtered {len(cves)} CVEs -> {len(filtered)} relevant (threshold: {self.relevance_threshold})")

        return filtered, scores


if __name__ == "__main__":
    # Test the filter
    tech_stack = [
        "nginx-frontend",
        "web_server",
        "nginx-frontend 1.18.0",
        "web_server 1.18.0",
        "postgres-db",
        "database",
        "postgres-db 12.4",
        "database 12.4"
    ]

    # Sample CVEs
    sample_cves = [
        {
            'cve_id': 'CVE-2021-23017',
            'description': 'nginx before 1.18.0 has a memory corruption vulnerability',
            'affected_products': ['nginx:1.18.0'],
            'summary': {'brief_description': 'nginx memory corruption'}
        },
        {
            'cve_id': 'CVE-2020-1234',
            'description': 'Apache Struts vulnerability',
            'affected_products': ['apache:struts:2.0'],
            'summary': {'brief_description': 'Apache Struts RCE'}
        },
        {
            'cve_id': 'CVE-2023-1234',
            'description': 'PostgreSQL database SQL injection',
            'affected_products': ['postgresql:12.4'],
            'summary': {'brief_description': 'PostgreSQL SQLi'}
        }
    ]

    # Initialize and fit filter
    filter = HybridRelevanceFilter(relevance_threshold=0.2)
    filter.fit(tech_stack)

    # Filter CVEs
    filtered, scores = filter.filter_cves(sample_cves)

    print(f"\nFiltered {len(filtered)} relevant CVEs:")
    for cve in filtered:
        print(f"  {cve['cve_id']}: {scores[cve['cve_id']]:.3f}")
