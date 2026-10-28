import yaml
from pathlib import Path
from typing import Any
from functools import lru_cache
from src.utils.logging_config import get_logger


class FeatureFlags:
    def __init__(self, config_path: str = "config/features.yaml"):
        self.logger = get_logger(__name__)
        self._config_path = Path(config_path)
        self._flags: dict = {}
        self._tuning: dict = {}
        self._load()
        enabled = [k for k, v in self._flags.items() if v]
        disabled = [k for k, v in self._flags.items() if not v]
        self.logger.info(
            "feature_flags_loaded",
            extra={"enabled": enabled, "disabled": disabled}
        )

    def _load(self) -> None:
        try:
            with open(self._config_path, "r") as f:
                data = yaml.safe_load(f)
            self._flags = data.get("features", {})
            self._tuning = data.get("tuning", {})
        except FileNotFoundError:
            self.logger.warning("features_config_not_found", extra={"path": str(self._config_path)})
            self._flags = {}
            self._tuning = {}
        except yaml.YAMLError as e:
            self.logger.error("features_config_parse_error", extra={"error": str(e)})
            self._flags = {}
            self._tuning = {}

    def is_enabled(self, feature: str) -> bool:
        return self._flags.get(feature, False)

    def get_tuning(self, key: str, default: Any = None) -> Any:
        return self._tuning.get(key, default)

    def reload(self) -> None:
        self.logger.info("feature_flags_reloading")
        self._load()
        self.logger.info("feature_flags_reloaded")

    @property
    def session_context(self) -> bool:
        return self.is_enabled("session_context")

    @property
    def rbac(self) -> bool:
        return self.is_enabled("rbac")

    @property
    def adversarial_detection(self) -> bool:
        return self.is_enabled("adversarial_detection")

    @property
    def semantic_cache(self) -> bool:
        return self.is_enabled("semantic_cache")

    @property
    def sub_intent(self) -> bool:
        return self.is_enabled("sub_intent")

    @property
    def schema_v2(self) -> bool:
        return self.is_enabled("schema_v2")

    @property
    def xai(self) -> bool:
        return self.is_enabled("xai")

    @property
    def uncertainty_estimation(self) -> bool:
        return self.is_enabled("uncertainty_estimation")

    @property
    def continual_learning(self) -> bool:
        return self.is_enabled("continual_learning")

    @property
    def speculative_decoding(self) -> bool:
        return self.is_enabled("speculative_decoding")


@lru_cache()
def get_feature_flags() -> FeatureFlags:
    """
    Returns the singleton FeatureFlags instance.
    Cached after first call — call reload() to refresh config.
    """
    return FeatureFlags()
