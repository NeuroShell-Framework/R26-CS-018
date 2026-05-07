import pytest
import yaml
import tempfile
import os
from config.feature_flags import FeatureFlags, get_feature_flags


@pytest.fixture
def real_flags():
    return FeatureFlags(config_path="config/features.yaml")


@pytest.fixture
def tmp_yaml():
    path = os.path.join(tempfile.gettempdir(), "test_features.yaml")
    yield path
    if os.path.exists(path):
        os.remove(path)


@pytest.fixture
def make_flags(tmp_yaml):
    def _make(features=None, tuning=None):
        data = {}
        if features is not None:
            data["features"] = features
        if tuning is not None:
            data["tuning"] = tuning
        with open(tmp_yaml, "w") as f:
            yaml.safe_dump(data, f)
        return FeatureFlags(config_path=tmp_yaml)
    return _make


class TestFeatureFlagsLoad:

    def test_load_real_config_parses_features(self, real_flags):
        """Real config file loads features dict correctly."""
        assert isinstance(real_flags._flags, dict)
        assert "session_context" in real_flags._flags

    def test_load_real_config_parses_tuning(self, real_flags):
        """Real config file loads tuning dict correctly."""
        assert isinstance(real_flags._tuning, dict)
        assert "session_ttl_minutes" in real_flags._tuning

    def test_load_missing_file_sets_empty_dicts(self, make_flags):
        """Missing config file results in empty _flags and _tuning."""
        flags = FeatureFlags(config_path="/nonexistent/path.yaml")
        assert flags._flags == {}
        assert flags._tuning == {}

    def test_load_invalid_yaml_sets_empty_dicts(self, tmp_yaml):
        """Invalid YAML content results in empty _flags and _tuning."""
        with open(tmp_yaml, "w") as f:
            f.write("{{{{invalid yaml:::")
        flags = FeatureFlags(config_path=tmp_yaml)
        assert flags._flags == {}
        assert flags._tuning == {}


class TestIsEnabled:

    def test_enabled_flag_returns_true(self, real_flags):
        """is_enabled returns True for enabled features."""
        assert real_flags.is_enabled("session_context") is True

    def test_disabled_flag_returns_false(self, real_flags):
        """is_enabled returns False for disabled features."""
        assert real_flags.is_enabled("xai") is False

    def test_unknown_flag_returns_false(self, real_flags):
        """is_enabled returns False for features not in config."""
        assert real_flags.is_enabled("nonexistent_feature") is False

    def test_explicit_true_feature(self, make_flags):
        """Feature explicitly set to True returns enabled."""
        flags = make_flags(features={"my_feature": True})
        assert flags.is_enabled("my_feature") is True

    def test_explicit_false_feature(self, make_flags):
        """Feature explicitly set to False returns disabled."""
        flags = make_flags(features={"my_feature": False})
        assert flags.is_enabled("my_feature") is False


class TestGetTuning:

    def test_get_existing_tuning_value(self, real_flags):
        """get_tuning returns the correct value for an existing key."""
        assert real_flags.get_tuning("session_ttl_minutes") == 30

    def test_get_tuning_returns_default_for_missing(self, real_flags):
        """get_tuning returns the provided default for missing keys."""
        assert real_flags.get_tuning("nonexistent_key", 99) == 99

    def test_get_tuning_returns_none_default(self, real_flags):
        """get_tuning returns None when no default is provided for missing key."""
        assert real_flags.get_tuning("nonexistent_key") is None

    def test_get_tuning_float_value(self, real_flags):
        """get_tuning correctly returns float values."""
        assert real_flags.get_tuning("semantic_cache_threshold") == 0.82

    def test_get_tuning_from_custom_config(self, make_flags):
        """get_tuning works with custom tuning config."""
        flags = make_flags(tuning={"custom_val": 42})
        assert flags.get_tuning("custom_val") == 42


class TestFeatureProperties:

    def test_session_context_property(self, real_flags):
        """session_context property returns correct value."""
        assert real_flags.session_context is True

    def test_rbac_property(self, real_flags):
        """rbac property returns correct value."""
        assert real_flags.rbac is True

    def test_adversarial_detection_property(self, real_flags):
        """adversarial_detection property returns correct value."""
        assert real_flags.adversarial_detection is True

    def test_semantic_cache_property(self, real_flags):
        """semantic_cache property returns correct value."""
        assert real_flags.semantic_cache is True

    def test_sub_intent_property(self, real_flags):
        """sub_intent property returns correct value."""
        assert real_flags.sub_intent is True

    def test_schema_v2_property(self, real_flags):
        """schema_v2 property returns correct value."""
        assert real_flags.schema_v2 is True

    def test_xai_property(self, real_flags):
        """xai property returns correct value (disabled by default)."""
        assert real_flags.xai is False

    def test_uncertainty_estimation_property(self, real_flags):
        """uncertainty_estimation property returns correct value."""
        assert real_flags.uncertainty_estimation is False

    def test_continual_learning_property(self, real_flags):
        """continual_learning property returns correct value."""
        assert real_flags.continual_learning is False

    def test_speculative_decoding_property(self, real_flags):
        """speculative_decoding property returns correct value."""
        assert real_flags.speculative_decoding is False


class TestReload:

    def test_reload_refreshes_from_disk(self, tmp_yaml):
        """reload re-reads the config file from disk."""
        with open(tmp_yaml, "w") as f:
            yaml.safe_dump({"features": {"flag_a": True}}, f)
        flags = FeatureFlags(config_path=tmp_yaml)
        assert flags.is_enabled("flag_a") is True

        with open(tmp_yaml, "w") as f:
            yaml.safe_dump({"features": {"flag_a": False}}, f)
        flags.reload()
        assert flags.is_enabled("flag_a") is False

    def test_reload_handles_file_disappearing(self, tmp_yaml):
        """reload handles config file being removed after initial load."""
        with open(tmp_yaml, "w") as f:
            yaml.safe_dump({"features": {"flag_a": True}}, f)
        flags = FeatureFlags(config_path=tmp_yaml)
        os.remove(tmp_yaml)
        flags.reload()
        assert flags._flags == {}

    def test_reload_handles_yaml_corruption(self, tmp_yaml):
        """reload handles corrupted YAML on disk gracefully."""
        with open(tmp_yaml, "w") as f:
            yaml.safe_dump({"features": {"flag_a": True}}, f)
        flags = FeatureFlags(config_path=tmp_yaml)
        with open(tmp_yaml, "w") as f:
            f.write("not: valid: yaml: {{{{")
        flags.reload()
        assert flags._flags == {}


class TestGetFeatureFlags:

    def test_get_feature_flags_returns_singleton(self):
        """get_feature_flags returns a cached singleton instance."""
        f1 = get_feature_flags()
        f2 = get_feature_flags()
        assert f1 is f2

    def test_get_feature_flags_returns_feature_flags_instance(self):
        """get_feature_flags returns a FeatureFlags instance."""
        result = get_feature_flags()
        assert isinstance(result, FeatureFlags)
