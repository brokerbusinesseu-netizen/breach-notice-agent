"""Email delivery through Amazon SES v2 (boto3 client "sesv2", operation SendEmail)."""
from __future__ import annotations

import os

import boto3
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError


class MailError(Exception):
    """Raised when a message could not be handed to SES. Carries a safe message."""


class RecipientNotAllowed(MailError):
    pass


def allowed_domains() -> set[str]:
    raw = os.environ.get("ALLOWED_RECIPIENT_DOMAINS", "simulator.amazonses.com")
    return {d.strip().lower() for d in raw.split(",") if d.strip()}


def check_recipient(address: str) -> None:
    domain = address.rpartition("@")[2].lower()
    if domain not in allowed_domains():
        raise RecipientNotAllowed(
            f"recipient domain {domain!r} is not in ALLOWED_RECIPIENT_DOMAINS (demo safety allowlist)"
        )


class SesMailer:
    def __init__(self, client=None, sender: str | None = None, configuration_set: str | None = None):
        self.sender = sender or os.environ.get("SES_FROM", "")
        self.configuration_set = configuration_set or os.environ.get("SES_CONFIGURATION_SET") or None
        self._client = client

    @property
    def client(self):
        if self._client is None:
            region = os.environ.get("AWS_REGION", "eu-central-1")
            self._client = boto3.client(
                "sesv2",
                region_name=region,
                config=Config(retries={"max_attempts": 3, "mode": "standard"}, connect_timeout=5, read_timeout=15),
            )
        return self._client

    def send(self, to: str, subject: str, body_text: str) -> str:
        """Send one plain text email. Returns the SES MessageId."""
        if not self.sender:
            raise MailError("SES_FROM is not configured")
        check_recipient(to)
        params = {
            "FromEmailAddress": self.sender,
            "Destination": {"ToAddresses": [to]},
            "Content": {
                "Simple": {
                    "Subject": {"Data": subject, "Charset": "UTF-8"},
                    "Body": {"Text": {"Data": body_text, "Charset": "UTF-8"}},
                }
            },
        }
        if self.configuration_set:
            params["ConfigurationSetName"] = self.configuration_set
        try:
            resp = self.client.send_email(**params)  # AWS CDS call: Amazon SES v2 SendEmail
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "ClientError")
            raise MailError(f"SES rejected the request: {code}") from exc
        except BotoCoreError as exc:
            raise MailError(f"SES unreachable: {type(exc).__name__}") from exc
        return resp["MessageId"]
