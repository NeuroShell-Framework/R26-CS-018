# NeuroShell IRE — Schema Validator
# Validate parsed JSON against intent schema

from pydantic import ValidationError
from src.schemas.intent_schema import IntentSchema, SchemaValidationError
from src.utils.logging_config import get_logger


class SchemaValidator:
    def __init__(self):
        self.logger = get_logger(__name__)

    def validate(self, data: dict) -> IntentSchema:
        try:
            result = IntentSchema.model_validate(data)
        except ValidationError as e:
            first_error = e.errors()[0]
            field_path = " -> ".join(str(x) for x in first_error["loc"])
            msg = first_error["msg"]
            raise SchemaValidationError(
                f"Schema validation failed on field '{field_path}': {msg}",
                field=field_path
            )

        self.logger.debug("schema_validated", intent=result.intent.value)
        return result
