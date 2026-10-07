"""Unit tests verifying foundation settings and configuration loading."""

from xsslab.config.settings import Settings, get_settings


def test_settings_default_values() -> None:
    """Verify application settings load with secure default values."""
    settings = get_settings()
    assert settings.app_name == "XSS Detection Lab"
    assert settings.version == "0.1.0"
    assert settings.environment == "development"
    assert settings.debug is False
    assert settings.anomaly_threshold == 0.65
    assert settings.strict_script_blocking is True
    assert settings.decode_entities_before_scan is True
    assert settings.lab_host == "127.0.0.1"
    assert settings.lab_port == 8081


def test_custom_settings_instantiation() -> None:
    """Verify custom settings overrides operate as expected."""
    custom = Settings(
        app_name="Custom XSS Engine",
        anomaly_threshold=0.8,
        strict_script_blocking=False,
    )
    assert custom.app_name == "Custom XSS Engine"
    assert custom.anomaly_threshold == 0.8
    assert custom.strict_script_blocking is False
