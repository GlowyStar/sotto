import pytest

from sotto.relay.settings import Settings


def test_defaults_listen_on_loopback() -> None:
    settings = Settings.from_env({})

    assert settings == Settings(host="127.0.0.1", port=8765)


def test_host_and_port_come_from_the_environment() -> None:
    settings = Settings.from_env({"RELAY_HOST": "::1", "RELAY_PORT": "9000"})

    assert settings == Settings(host="::1", port=9000)


def test_empty_host_is_rejected() -> None:
    with pytest.raises(ValueError, match="RELAY_HOST"):
        Settings.from_env({"RELAY_HOST": ""})


@pytest.mark.parametrize("port", ["", "http", "-1", "87.65"])
def test_port_that_is_not_a_number_is_rejected(port: str) -> None:
    with pytest.raises(ValueError, match="RELAY_PORT"):
        Settings.from_env({"RELAY_PORT": port})
