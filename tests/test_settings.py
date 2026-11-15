from pathlib import Path

import pytest

from sotto.relay.settings import Settings


def test_defaults_are_loopback_and_the_values_of_the_protocol() -> None:
    settings = Settings.from_env({"RELAY_DATABASE": "relay.db"})

    assert settings == Settings(
        database=Path("relay.db"),
        host="127.0.0.1",
        port=8765,
        name="127.0.0.1",
        login_deadline_seconds=10,
        one_time_prekey_cap=100,
        max_pages=262144,
        message_ttl_seconds=2592000,
        sweep_interval_seconds=60,
        queue_max_messages=1000,
        queue_max_bytes=16777216,
        frame_bucket_size=60,
        frame_refill_seconds=1,
        handout_bucket_size=20,
        handout_refill_seconds=300,
        metrics_port=None,
    )


def test_every_setting_comes_from_the_environment() -> None:
    settings = Settings.from_env(
        {
            "RELAY_DATABASE": "/data/relay.db",
            "RELAY_HOST": "::1",
            "RELAY_PORT": "9000",
            "RELAY_NAME": "relay.example.org",
            "RELAY_LOGIN_DEADLINE_SECONDS": "3",
            "RELAY_ONE_TIME_PREKEY_CAP": "7",
            "RELAY_MAX_PAGES": "64",
            "RELAY_MESSAGE_TTL_SECONDS": "600",
            "RELAY_SWEEP_INTERVAL_SECONDS": "5",
            "RELAY_QUEUE_MAX_MESSAGES": "10",
            "RELAY_QUEUE_MAX_BYTES": "4096",
            "RELAY_FRAME_BUCKET_SIZE": "6",
            "RELAY_FRAME_REFILL_SECONDS": "2",
            "RELAY_HANDOUT_BUCKET_SIZE": "4",
            "RELAY_HANDOUT_REFILL_SECONDS": "30",
            "RELAY_METRICS_PORT": "9100",
        }
    )

    assert settings == Settings(
        database=Path("/data/relay.db"),
        host="::1",
        port=9000,
        name="relay.example.org",
        login_deadline_seconds=3,
        one_time_prekey_cap=7,
        max_pages=64,
        message_ttl_seconds=600,
        sweep_interval_seconds=5,
        queue_max_messages=10,
        queue_max_bytes=4096,
        frame_bucket_size=6,
        frame_refill_seconds=2,
        handout_bucket_size=4,
        handout_refill_seconds=30,
        metrics_port=9100,
    )


def test_empty_host_is_rejected() -> None:
    with pytest.raises(ValueError, match="RELAY_HOST"):
        Settings.from_env({"RELAY_DATABASE": "relay.db", "RELAY_HOST": ""})


@pytest.mark.parametrize("port", ["", "http", "-1", "87.65"])
def test_port_that_is_not_a_number_is_rejected(port: str) -> None:
    with pytest.raises(ValueError, match="RELAY_PORT"):
        Settings.from_env({"RELAY_DATABASE": "relay.db", "RELAY_PORT": port})


@pytest.mark.parametrize("port", ["", "http", "-1", "87.65"])
def test_metrics_port_that_is_not_a_number_is_rejected(port: str) -> None:
    with pytest.raises(ValueError, match="RELAY_METRICS_PORT"):
        Settings.from_env({"RELAY_DATABASE": "relay.db", "RELAY_METRICS_PORT": port})


@pytest.mark.parametrize("name", ["a", "::1", "127.1", "relay_1.example-2.org", "a" * 255])
def test_server_name_that_keeps_rule_4_is_taken(name: str) -> None:
    assert Settings.from_env({"RELAY_DATABASE": "relay.db", "RELAY_NAME": name}).name == name


@pytest.mark.parametrize(
    "name",
    ["", "a" * 256, "Relay.Example.org", "relay example", "%72elay", "[::1]", "a/ws", "a\n"],
)
def test_server_name_that_breaks_rule_4_is_rejected(name: str) -> None:
    with pytest.raises(ValueError, match="RELAY_NAME"):
        Settings.from_env({"RELAY_DATABASE": "relay.db", "RELAY_NAME": name})


@pytest.mark.parametrize("deadline", ["", "0", "-1", "2.5", "ten"])
def test_login_deadline_that_is_no_whole_number_above_0_is_rejected(deadline: str) -> None:
    with pytest.raises(ValueError, match="RELAY_LOGIN_DEADLINE_SECONDS"):
        Settings.from_env(
            {"RELAY_DATABASE": "relay.db", "RELAY_LOGIN_DEADLINE_SECONDS": deadline}
        )


@pytest.mark.parametrize("environ", [{}, {"RELAY_DATABASE": ""}])
def test_relay_without_a_database_path_is_rejected(environ: dict[str, str]) -> None:
    with pytest.raises(ValueError, match="RELAY_DATABASE"):
        Settings.from_env(environ)


@pytest.mark.parametrize(
    "name",
    [
        "RELAY_ONE_TIME_PREKEY_CAP",
        "RELAY_MAX_PAGES",
        "RELAY_MESSAGE_TTL_SECONDS",
        "RELAY_SWEEP_INTERVAL_SECONDS",
        "RELAY_QUEUE_MAX_MESSAGES",
        "RELAY_QUEUE_MAX_BYTES",
        "RELAY_FRAME_BUCKET_SIZE",
        "RELAY_FRAME_REFILL_SECONDS",
        "RELAY_HANDOUT_BUCKET_SIZE",
        "RELAY_HANDOUT_REFILL_SECONDS",
    ],
)
@pytest.mark.parametrize("value", ["", "0", "-1", "2.5", "ten"])
def test_limit_that_is_no_whole_number_above_0_is_rejected(name: str, value: str) -> None:
    with pytest.raises(ValueError, match=name):
        Settings.from_env({"RELAY_DATABASE": "relay.db", name: value})
