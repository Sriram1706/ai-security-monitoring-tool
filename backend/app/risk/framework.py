from dataclasses import dataclass


RISK_CATEGORIES = [
    "prompt_injection",
    "sensitive_data_exposure",
    "toxicity_or_harm",
    "hallucination",
    "policy_violation",
    "model_misuse",
    "adversarial_input",
    "illegal_activity",
]

SEVERITY_LEVELS = {
    "low": (0, 34),
    "medium": (35, 64),
    "high": (65, 84),
    "critical": (85, 100),
}

RISK_FINDING_JSON_SCHEMA = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "title": "RiskFinding",
    "type": "object",
    "required": ["risk_type", "severity", "score", "explanation"],
    "properties": {
        "risk_type": {"type": "string"},
        "severity": {"type": "string", "enum": ["low", "medium", "high", "critical"]},
        "score": {"type": "integer", "minimum": 0, "maximum": 100},
        "explanation": {"type": "string", "minLength": 1},
    },
    "additionalProperties": False,
}


@dataclass
class RiskExample:
    category: str
    base_score: int
    weight: float


def calculate_weighted_score(examples: list[RiskExample]) -> int:
    numerator = sum(x.base_score * x.weight for x in examples)
    denominator = sum(100 * x.weight for x in examples)
    if denominator == 0:
        return 0
    return round((numerator / denominator) * 100)
