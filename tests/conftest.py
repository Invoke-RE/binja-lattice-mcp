import os
import pytest

@pytest.fixture(scope="session", autouse=True)
def setup_test_env():
    """Ensure Binary Ninja is in headless mode for testing"""
    os.environ["BN_DISABLE_UI"] = "1"
    yield 