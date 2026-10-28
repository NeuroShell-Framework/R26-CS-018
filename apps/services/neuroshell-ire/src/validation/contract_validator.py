import re
from typing import List, Optional, Tuple
from src.schemas.planner_contract import PlannerContract
from src.schemas.intent_schema import IntentType
from src.validation.hallucination_taxonomy import HallucinationClass, ValidationFinding
from src.utils.logging_config import get_logger


class ContractValidationError(ValueError):
    """Raised when a PlannerContract fails contract validation checks."""
    findings: List[ValidationFinding]

    def __init__(self, message: str, findings: Optional[List[ValidationFinding]] = None):
        super().__init__(message)
        self.findings = findings or []


class ContractValidator:
    def __init__(self):
        self.logger = get_logger(__name__)
        self.last_findings: List[ValidationFinding] = []

    def validate(
        self, contract: PlannerContract
    ) -> Tuple[PlannerContract, List[str]]:
        from config.enforcement_policy import get_enforcement_policy
        policy = get_enforcement_policy()
        conf_sev = policy.get_severity(HallucinationClass.UNGROUNDED_CONFIDENCE)
        intent_sev = policy.get_severity(HallucinationClass.CONTRADICTORY_ACTION_TARGET)

        warnings: List[str] = []
        self.last_findings = []

        if 0.0 <= contract.confidence <= 1.0:
            self.last_findings.append(
                ValidationFinding(
                    validator="contract_validator",
                    passed=True,
                    hallucination_class=None,
                    detail=f"Contract confidence {contract.confidence} within valid [0.0, 1.0] range",
                    severity="block",
                )
            )
        else:
            msg = f"Confidence {contract.confidence} out of [0,1] range"
            self.last_findings.append(
                ValidationFinding(
                    validator="contract_validator",
                    passed=False,
                    hallucination_class=HallucinationClass.UNGROUNDED_CONFIDENCE,
                    detail=msg,
                    severity="block",
                )
            )
            raise ContractValidationError(msg, findings=self.last_findings)

        if contract.intent is not None:
            self.last_findings.append(
                ValidationFinding(
                    validator="contract_validator",
                    passed=True,
                    hallucination_class=None,
                    detail=f"Contract intent '{contract.intent.value}' present",
                    severity="block",
                )
            )
        else:
            msg = "Contract must have an intent"
            self.last_findings.append(
                ValidationFinding(
                    validator="contract_validator",
                    passed=False,
                    hallucination_class=HallucinationClass.CONTRADICTORY_ACTION_TARGET,
                    detail=msg,
                    severity=intent_sev,
                )
            )
            if intent_sev == "block":
                raise ContractValidationError(msg, findings=self.last_findings)
            warnings.append(msg)

        self.logger.info(
            "contract_validated",
            intent=contract.intent.value if contract.intent else "none",
            warnings=len(warnings),
        )

        return contract, warnings
