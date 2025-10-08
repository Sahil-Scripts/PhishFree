"""
backend/ensemble.py

Utilities to combine text / cnn / gnn scores into a final risk score.

Primary function:
    combine_scores(text_score, cnn_score=None, gnn_score=None, weights=None)

Returns:
    {
        "score": <float 0..1>,
        "label": "phish"|"unknown"|"legit",
        "components": {"text":..., "cnn":..., "gnn":...},
        "reasons": [ ... human-readable reasons ... ]
    }

Default weights: text 0.6, cnn 0.2, gnn 0.2 (tune these).
"""

from typing import Optional, Dict, Any

def _norm_score(s: Optional[float]) -> float:
    """Normalize/validate individual score value (None -> 0.0, clamp 0..1)."""
    try:
        if s is None:
            return 0.0
        v = float(s)
        if v != v:  # NaN
            return 0.0
        return max(0.0, min(1.0, v))
    except Exception:
        return 0.0

def combine_scores(text_score: float,
                   cnn_score: Optional[float] = None,
                   gnn_score: Optional[float] = None,
                   weights: Optional[Dict[str, float]] = None) -> Dict[str, Any]:
    """
    Combine the scores into a final risk score.

    Args:
        text_score: required, 0..1
        cnn_score: optional, 0..1
        gnn_score: optional, 0..1
        weights: optional dict with keys "text","cnn","gnn" (values non-negative).
                 If provided weights don't sum to 1, they will be normalized.
                 Default: {"text":0.6, "cnn":0.2, "gnn":0.2}
    """
    t = _norm_score(text_score)
    c = _norm_score(cnn_score)
    g = _norm_score(gnn_score)

    if weights is None:
        weights = {"text": 0.5, "cnn": 0.3, "gnn": 0.2}  # Balanced weights with text priority
    # ensure keys present
    w_text = float(weights.get("text", 0.0))
    w_cnn = float(weights.get("cnn", 0.0))
    w_gnn = float(weights.get("gnn", 0.0))
    s = w_text + w_cnn + w_gnn
    if s <= 0:
        # fallback to equal weights for present components
        present = [k for k, v in [("text", t), ("cnn", c), ("gnn", g)] if v is not None]
        if len(present) == 0:
            w_text, w_cnn, w_gnn = 1.0, 0.0, 0.0
        else:
            w_text = 1.0 if t is not None else 0.0
            w_cnn = 0.0
            w_gnn = 0.0
        s = w_text + w_cnn + w_gnn

    # normalize weights
    w_text /= s
    w_cnn /= s
    w_gnn /= s

    final = w_text * t + w_cnn * c + w_gnn * g
    final = max(0.0, min(1.0, final))
    
    # Apply intelligent combination logic - much more conservative
    # If all models agree on low risk, be very conservative
    low_risk_count = sum(1 for score in [t, c, g] if score < 0.2)
    if low_risk_count >= 2:
        final = final * 0.3  # Reduce final score by 70%
    
    # If any model is very low, reduce overall score
    very_low_count = sum(1 for score in [t, c, g] if score < 0.1)
    if very_low_count >= 1:
        final = final * 0.5  # Reduce final score by 50%
    
    # If all models agree on high risk, be more confident
    high_risk_count = sum(1 for score in [t, c, g] if score > 0.7)
    if high_risk_count >= 2:
        final = min(final * 1.2, 1.0)  # Increase final score by 20%, cap at 1.0
    
    # Ensure final score is within bounds
    final = max(0.0, min(1.0, final))

    # derive a human-friendly label with moderate thresholds
    if final >= 0.7:
        label = "phish"
    elif final >= 0.4:
        label = "suspicious"
    else:
        label = "legit"

    reasons = [f"combined_score={final:.3f}",
               f"weights(text,cnn,gnn)=({w_text:.2f},{w_cnn:.2f},{w_gnn:.2f})",
               f"components(text,cnn,gnn)=({t:.2f},{c:.2f},{g:.2f})"]

    # add short human reasons depending on components
    if t >= 0.6:
        reasons.append("text model suggests phishing")
    elif t >= 0.35:
        reasons.append("text model somewhat suspicious")
    else:
        reasons.append("text model low risk")

    if c >= 0.6:
        reasons.append("visual model strongly suspicious")
    elif c >= 0.35:
        reasons.append("visual model slightly suspicious")

    if g >= 0.6:
        reasons.append("graph model strongly suspicious")
    elif g >= 0.35:
        reasons.append("graph model somewhat suspicious")

    return {
        "score": float(final),
        "label": label,
        "components": {"text": t, "cnn": c, "gnn": g},
        "weights": {"text": w_text, "cnn": w_cnn, "gnn": w_gnn},
        "reasons": reasons
    }


# Small CLI demo
if __name__ == "__main__":
    import json
    print("Ensemble combine demo")
    examples = [
        (0.8, 0.1, None),
        (0.2, 0.7, 0.1),
        (0.5, None, 0.9),
        (0.1, None, None),
    ]
    for t, c, g in examples:
        out = combine_scores(t, cnn_score=c, gnn_score=g)
        print(json.dumps(out, indent=2))
