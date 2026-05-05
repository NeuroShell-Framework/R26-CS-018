import re
from typing import List, Tuple
from src.schemas.planner_contract import PlannerContract
from src.schemas.intent_schema import IntentType
from src.utils.logging_config import get_logger


class ContractValidator:
    def __init__(self):
        self.logger = get_logger(__name__)

    def validate(
        self, contract: PlannerContract
    ) -> Tuple[PlannerContract, List[str]]:
        warnings = []

        if not (0.0 <= contract.confidence <= 1.0):
            raise ValueError(
                f"Confidence {contract.confidence} out of [0,1] range"
            )

        if contract.intent is None:
            raise ValueError("Contract must have an intent")

        self.logger.info(
            "contract_validated",
            intent=contract.intent.value if contract.intent else "none",
            warnings=len(warnings),
        )

        return contract, warnings
