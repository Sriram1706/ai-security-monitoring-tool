# Risk Scoring Framework (0-100)

## Categories
- `prompt_injection`
- `sensitive_data_exposure`
- `toxicity_or_harm`
- `hallucination`
- `policy_violation`
- `model_misuse`
- `adversarial_input`

## Severity Levels
- `low`: 0-34
- `medium`: 35-64
- `high`: 65-84
- `critical`: 85-100

## Formula
For findings `i`:
- `base_i` in `[0,100]`
- `weight_i` from category weight map

`total_score = round( (sum(base_i * weight_i) / sum(100 * weight_i)) * 100 )`

## Example
Findings:
- Prompt Injection: `base=70, weight=1.0`
- Data Exposure: `base=90, weight=1.0`
- Hallucination: `base=42, weight=0.6`

Calculation:
- Numerator = `70 + 90 + 25.2 = 185.2`
- Denominator = `100 + 100 + 60 = 260`
- Score = `(185.2 / 260) * 100 = 71.23` => `71` (`high`)

## Structured Output JSON Schema
```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "title": "RiskFinding",
  "type": "object",
  "required": ["risk_type", "severity", "score", "explanation"],
  "properties": {
    "risk_type": { "type": "string" },
    "severity": { "type": "string", "enum": ["low", "medium", "high", "critical"] },
    "score": { "type": "integer", "minimum": 0, "maximum": 100 },
    "explanation": { "type": "string", "minLength": 1 }
  },
  "additionalProperties": false
}
```
