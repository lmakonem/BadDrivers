"""
DNS Analysis Service - Core algorithms for DGA detection and domain analysis.

Includes:
- Shannon entropy calculation
- Impossible n-gram detection
- Consonant/vowel ratio analysis
- DGA scoring
"""

import math
from collections import Counter
from typing import List, Dict, Any
import re


# Impossible bigrams in English - strong DGA indicators
IMPOSSIBLE_BIGRAMS = {
    "qh", "qj", "qk", "qm", "qn", "qp", "qt", "qv", "qw", "qx", "qy", "qz",
    "xj", "xq", "xz",
    "vb", "vc", "vd", "vf", "vg", "vj", "vk", "vm", "vn", "vp", "vq", "vt", "vw", "vx", "vz",
    "bx", "cx", "dx", "fx", "gx", "hx", "jx", "kx", "mx", "nx", "px", "rx", "sx", "tx", "wx", "zx",
    "bq", "cq", "dq", "fq", "gq", "hq", "jq", "kq", "lq", "mq", "nq", "pq", "rq", "sq", "tq", "vq", "wq", "zq",
    "bz", "cz", "dz", "fz", "gz", "jz", "kz", "pz", "qz", "sz", "tz", "vz", "wz", "xz",
    "jj", "kk", "qq", "vv", "ww", "xx", "yy", "zz",
    "fk", "fv", "fz", "gv", "gf", "hk", "hv", "hz",
    "jb", "jc", "jd", "jf", "jg", "jh", "jk", "jl", "jm", "jn", "jp", "jq", "jr", "js", "jt", "jv", "jw", "jx", "jy", "jz",
    "kg", "kj", "kq", "kv", "kx", "kz",
}

VOWELS = set("aeiou")
CONSONANTS = set("bcdfghjklmnpqrstvwxyz")


def calculate_entropy(text: str) -> float:
    """
    Calculate Shannon entropy of a string.
    
    Higher entropy indicates more randomness (potential DGA).
    Typical legitimate domains: 2.5-3.5
    DGA domains: 3.5-4.5+
    """
    if not text:
        return 0.0
    
    # Count character frequencies
    freq = Counter(text.lower())
    length = len(text)
    
    # Calculate entropy
    entropy = 0.0
    for count in freq.values():
        if count > 0:
            p = count / length
            entropy -= p * math.log2(p)
    
    return round(entropy, 4)


def find_impossible_ngrams(text: str) -> List[str]:
    """
    Find impossible/unlikely bigrams in the text.
    
    These are character combinations that rarely/never appear in
    natural language but are common in random DGA strings.
    """
    text = text.lower()
    found = []
    
    for i in range(len(text) - 1):
        bigram = text[i:i+2]
        if bigram in IMPOSSIBLE_BIGRAMS:
            found.append(bigram)
    
    return found


def calculate_character_ratios(text: str) -> Dict[str, float]:
    """
    Calculate vowel/consonant/digit ratios.
    
    DGA domains often have:
    - Low vowel ratio (< 0.25)
    - High consonant ratio (> 0.75)
    - Higher digit ratio
    """
    text = text.lower()
    if not text:
        return {"vowel_ratio": 0, "consonant_ratio": 0, "digit_ratio": 0}
    
    vowel_count = sum(1 for c in text if c in VOWELS)
    consonant_count = sum(1 for c in text if c in CONSONANTS)
    digit_count = sum(1 for c in text if c.isdigit())
    alpha_count = vowel_count + consonant_count
    
    return {
        "vowel_ratio": round(vowel_count / len(text), 4) if text else 0,
        "consonant_ratio": round(consonant_count / len(text), 4) if text else 0,
        "digit_ratio": round(digit_count / len(text), 4) if text else 0,
        "vowel_to_consonant": round(vowel_count / consonant_count, 4) if consonant_count else 0,
    }


def extract_domain_parts(domain: str) -> Dict[str, Any]:
    """Extract the registered domain and subdomain parts."""
    # Remove protocol if present
    domain = re.sub(r"^https?://", "", domain)
    # Remove path
    domain = domain.split("/")[0]
    # Remove port
    domain = domain.split(":")[0]
    
    parts = domain.lower().split(".")
    
    # Simple TLD extraction (would use tldextract in production)
    if len(parts) >= 2:
        tld = parts[-1]
        sld = parts[-2]
        subdomain = ".".join(parts[:-2]) if len(parts) > 2 else ""
    else:
        tld = ""
        sld = parts[0] if parts else ""
        subdomain = ""
    
    return {
        "full_domain": domain,
        "subdomain": subdomain,
        "sld": sld,  # Second-level domain (the "name" part)
        "tld": tld,
        "label_count": len(parts),
    }


def calculate_dga_score(
    entropy: float,
    impossible_ngrams: List[str],
    ratios: Dict[str, float],
    length: int,
) -> float:
    """
    Calculate overall DGA probability score (0-1).
    
    Combines multiple signals:
    - High entropy
    - Impossible n-grams
    - Low vowel ratio
    - Unusual length
    """
    score = 0.0
    
    # Entropy score (0-0.35)
    if entropy > 4.0:
        score += 0.35
    elif entropy > 3.5:
        score += 0.25
    elif entropy > 3.0:
        score += 0.10
    
    # Impossible n-gram score (0-0.30)
    ngram_count = len(impossible_ngrams)
    if ngram_count >= 3:
        score += 0.30
    elif ngram_count >= 2:
        score += 0.20
    elif ngram_count >= 1:
        score += 0.10
    
    # Vowel ratio score (0-0.20)
    vowel_ratio = ratios.get("vowel_ratio", 0.3)
    if vowel_ratio < 0.15:
        score += 0.20
    elif vowel_ratio < 0.20:
        score += 0.15
    elif vowel_ratio < 0.25:
        score += 0.05
    
    # Length score (0-0.15)
    if length > 20:
        score += 0.15
    elif length > 15:
        score += 0.10
    elif length > 12:
        score += 0.05
    
    return min(round(score, 2), 1.0)


def analyze_domain(domain: str) -> Dict[str, Any]:
    """
    Perform comprehensive domain analysis for DGA detection.
    
    Returns analysis results including:
    - Entropy
    - Character ratios
    - Impossible n-grams
    - DGA score
    - Classification
    """
    parts = extract_domain_parts(domain)
    
    # Analyze the SLD (main domain name, not subdomains)
    sld = parts["sld"]
    
    entropy = calculate_entropy(sld)
    impossible = find_impossible_ngrams(sld)
    ratios = calculate_character_ratios(sld)
    dga_score = calculate_dga_score(entropy, impossible, ratios, len(sld))
    
    # Classification based on DGA score
    if dga_score >= 0.7:
        classification = "malicious"
        confidence = min(0.95, 0.7 + (dga_score - 0.7))
    elif dga_score >= 0.4:
        classification = "suspicious"
        confidence = 0.5 + (dga_score - 0.4) * 0.5
    else:
        classification = "benign"
        confidence = 0.8 - dga_score
    
    return {
        "domain": domain,
        "entropy": entropy,
        "length": len(sld),
        "label_count": parts["label_count"],
        "digit_ratio": ratios["digit_ratio"],
        "consonant_ratio": ratios["consonant_ratio"],
        "vowel_ratio": ratios["vowel_ratio"],
        "has_digits": any(c.isdigit() for c in sld),
        "tld": parts["tld"],
        "is_dga_like": dga_score >= 0.5,
        "dga_score": dga_score,
        "impossible_ngrams": impossible,
        "classification": classification,
        "confidence": round(confidence, 2),
    }
