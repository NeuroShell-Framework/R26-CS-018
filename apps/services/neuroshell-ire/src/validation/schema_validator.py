# NeuroShell IRE — Schema Validator
# Validate parsed JSON against intent schema with hallucination classification

from typing import List, Union
from pydantic import ValidationError
from src.schemas.intent_schema import IntentSchema, SchemaValidationError
from src.validation.hallucination_taxonomy import HallucinationClass, ValidationFinding
from src.utils.logging_config import get_logger


class SchemaValidator:
    def __init__(self):
        self.logger = get_logger(__name__)
        self.last_findings: List[ValidationFinding] = []

    def validate(self, data: Union[dict, IntentSchema]) -> IntentSchema:
        self.last_findings = []

        if isinstance(data, IntentSchema):
            result = data
            self.last_findings.append(
                ValidationFinding(
                    validator="schema_validator",
                    passed=True,
                    hallucination_class=None,
                    detail="Intent schema structure already validated as IntentSchema instance",
                    severity="block",
                )
            )
            return result

        try:
            result = IntentSchema.model_validate(data)
            self.last_findings.append(
                ValidationFinding(
                    validator="schema_validator",
                    passed=True,
                    hallucination_class=None,
                    detail="Pydantic intent schema structure validated successfully",
                    severity="block",
                )
            )
        except ValidationError as e:
            first_error = e.errors()[0]
            field_path = " -> ".join(str(x) for x in first_error["loc"])
            msg = first_error["msg"]

            h_class = HallucinationClass.UNGROUNDED_CONFIDENCE
            if "ports" in field_path:
                h_class = HallucinationClass.FABRICATED_PARAMETER
            elif "cve_ids" in field_path:
                h_class = HallucinationClass.FABRICATED_CVE
            elif "target" in field_path or "intent" in field_path:
                h_class = HallucinationClass.TARGET_TYPE_MISMATCH
            elif "rejection_reason" in msg or "confidence" in msg or "AMBIGUOUS" in msg or "REJECTED" in msg:
                h_class = HallucinationClass.UNGROUNDED_CONFIDENCE

            finding = ValidationFinding(
                validator="schema_validator",
                passed=False,
                hallucination_class=h_class,
                detail=f"Schema validation failed on field '{field_path}': {msg}",
                severity="block",
            )
            self.last_findings.append(finding)
            err = SchemaValidationError(
                f"Schema validation failed on field '{field_path}': {msg}",
                field=field_path,
            )
            err.findings = self.last_findings
            raise err

        self.logger.debug("schema_validated", intent=result.intent.value)
        return result
