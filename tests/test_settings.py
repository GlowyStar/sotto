import pytest

from sotto.relay.settings import Settings


def test_defaults_are_loopback_and_the_values_of_the_protocol() -> None:
    settings = Settings.from_env({})

    assert settings == Settings(
        host="127.0.0.1", port=8765, name="127.0.0.1", login_deadline_seconds=10
    )


def test_every_setting_comes_from_the_environment() -> None:
    settings = Settings.from_env(
        {
            "RELAY_HOST": "::1",
            "RELAY_PORT": "9000",
            "RELAY_NAME": "relay.example.org",
            "RELAY_LOGIN_DEADLINE_SECONDS": "3",
        }
    )

    assert settings == Settings(
        host="::1", port=9000, name="relay.example.org", login_deadline_seconds=3
    )


def test_empty_host_is_rejected() -> None:
    with pytest.raises(ValueError, match="RELAY_HOST"):
        Settings.from_env({"RELAY_HOST": ""})


@pytest.mark.parametrize("port", ["", "http", "-1", "87.65"])
def test_port_that_is_not_a_number_is_rejected(port: str) -> None:
    with pytest.raises(ValueError, match="RELAY_PORT"):
        Settings.from_env({"RELAY_PORT": port})


@pytest.mark.parametrize("name", ["a", "::1", "127.1", "relay_1.example-2.org", "a" * 255])
def test_server_name_that_keeps_rule_4_is_taken(name: str) -> None:
    assert Settings.from_env({"RELAY_NAME": name}).name == name


@pytest.mark.parametrize(
    "name",
    ["", "a" * 256, "Relay.Example.org", "relay example", "%72elay", "[::1]", "a/ws", "a\n"],
)
def test_server_name_that_breaks_rule_4_is_rejected(name: str) -> None:
    with pytest.raises(ValueError, match="RELAY_NAME"):
        Settings.from_env({"RELAY_NAME": name})


@pytest.mark.parametrize("deadline", ["", "0", "-1", "2.5", "ten"])
def test_login_deadline_that_is_no_whole_number_above_0_is_rejected(deadline: str) -> None:
    with pytest.raises(ValueError, match="RELAY_LOGIN_DEADLINE_SECONDS"):
        Settings.from_env({"RELAY_LOGIN_DEADLINE_SECONDS": deadline})
