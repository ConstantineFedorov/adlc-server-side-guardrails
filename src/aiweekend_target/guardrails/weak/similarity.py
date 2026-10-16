"""Similarity gate with absolute-score and benign-margin protection."""

from math import isfinite


def similarity_gate(
    attack_similarity, benign_similarity, *, min_similarity, min_margin
):
    """Accept only when both the absolute score and score margin pass."""
    values = (
        attack_similarity,
        benign_similarity,
        min_similarity,
        min_margin,
    )

    if any(
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not isfinite(value)
        for value in values
    ):
        return False

    attack_passes = attack_similarity + 1e-9 >= min_similarity
    margin_passes = (
        attack_similarity - benign_similarity + 1e-9 >= min_margin
    )

    return attack_passes and margin_passes
