# NeuroShell IRE — Global Pytest Configuration & Test Isolation Fixtures

import pytest
from config.settings import get_settings


@pytest.fixture(autouse=True)
def restore_settings():
    """
    Autouse fixture to reset global Settings singleton and clear cache after every test,
    preventing state pollution across unit and integration tests.
    """
    yield
    get_settings.cache_clear()
