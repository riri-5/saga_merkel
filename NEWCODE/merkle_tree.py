"""
Merkle tree helpers for tamper-evident SAGA interaction batches.
"""
import hashlib
from typing import Iterable, List, Optional


def _hash_pair(left: str, right: str) -> str:
    return hashlib.sha256((left + right).encode("utf-8")).hexdigest()


def build_merkle_tree(interaction_hashes: Iterable[str]) -> List[List[str]]:
    """
    Build a Merkle tree from leaf hashes.

    Returns a list of levels, where level 0 contains leaves and the last level
    contains a single root. If a level has an odd number of nodes, the final
    node is duplicated, matching common append-only log practice.
    """
    leaves = list(interaction_hashes)
    if not leaves:
        return []

    tree = [leaves]
    current_level = leaves
    while len(current_level) > 1:
        next_level = []
        for index in range(0, len(current_level), 2):
            left = current_level[index]
            right = current_level[index + 1] if index + 1 < len(current_level) else left
            next_level.append(_hash_pair(left, right))
        tree.append(next_level)
        current_level = next_level
    return tree


def generate_merkle_root(interaction_hashes: Iterable[str]) -> Optional[str]:
    tree = build_merkle_tree(interaction_hashes)
    if not tree:
        return None
    return tree[-1][0]


def generate_merkle_proof(interaction_hashes: Iterable[str], interaction_hash: str) -> List[dict]:
    """
    Generate a proof for a leaf hash in a batch.

    Each proof item records the sibling hash and whether that sibling belongs on
    the left or right side during verification.
    """
    tree = build_merkle_tree(interaction_hashes)
    if not tree:
        return []

    try:
        index = tree[0].index(interaction_hash)
    except ValueError:
        return []

    proof = []
    for level in tree[:-1]:
        is_right_node = index % 2 == 1
        sibling_index = index - 1 if is_right_node else index + 1
        if sibling_index >= len(level):
            sibling_index = index
        proof.append({
            "position": "left" if is_right_node else "right",
            "hash": level[sibling_index],
        })
        index //= 2
    return proof


def verify_merkle_proof(interaction_hash: str, proof: List[dict], merkle_root: str) -> bool:
    computed_hash = interaction_hash
    for item in proof:
        sibling_hash = item.get("hash")
        if item.get("position") == "left":
            computed_hash = _hash_pair(sibling_hash, computed_hash)
        elif item.get("position") == "right":
            computed_hash = _hash_pair(computed_hash, sibling_hash)
        else:
            return False
    return computed_hash == merkle_root
