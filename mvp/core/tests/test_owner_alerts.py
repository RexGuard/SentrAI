"""Alerts reach someone with no setup: each alert lists the Owner and Admin accounts, and the readiness check
counts email to them once a mail server (the company's own or the SentrAI relay) is there."""
from app import ui_readiness
from .conftest import brute_force


def test_each_alert_names_the_owner_accounts(client):
    client.core.account_emails = lambda: ["owner@acme.test", "admin@acme.test"]
    brute_force(client)
    notes = client.get("/notifications").json()
    rows = notes if isinstance(notes, list) else notes.get("notifications", [])
    assert rows and all(n.get("owners") == ["owner@acme.test", "admin@acme.test"] for n in rows)
    client.core.account_emails = lambda: 1 / 0  # a broken accounts file never stops an alert
    assert client.core._owner_emails() == []


def test_readiness_counts_email_to_the_owners():
    off = lambda name: False  # noqa: E731
    assert ui_readiness.alert_channels({"SMTP_HOST": "smtp.x"}, off, 0) == []  # nobody to send to
    assert ui_readiness.alert_channels({"SMTP_HOST": "smtp.x"}, off, 2) == ["email to the Owner and Admin accounts"]
    assert ui_readiness.alert_channels({"SENTRAI_RELAY_SMTP_HOST": "relay.x"}, off, 1) == [
        "email to the Owner and Admin accounts"]
    assert ui_readiness.alert_channels({"SMTP_HOST": "smtp.x", "SENTRAI_ALERT_OWNERS": "off"}, off, 2) == []
    assert ui_readiness.alert_channels({"SMTP_HOST": "smtp.x", "ALERT_EMAIL_TO": "a@x"}, off, 0) == ["email"]
