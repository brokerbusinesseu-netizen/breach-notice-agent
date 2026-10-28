# Breach Notice Agent

An agent that takes a data controller from a detected personal data breach to documented notifications inside the
72 hour window of GDPR Art. 33, and always leaves the last word before anything is sent to a human (the Data
Protection Officer).

Built by Broker Business sp. z o.o. (Bialystok, Poland) for the AWS CDS Agentic AI Partner Hackathon.

- Live demo: see the Devpost submission for the URL and the access note.
- Architecture diagram: [`docs/architecture.png`](docs/architecture.png) (source: [`docs/architecture.mmd`](docs/architecture.mmd))
- License: MIT

## Problem

Under GDPR Art. 33 a controller must notify the supervisory authority within 72 hours of becoming aware of a
breach, and under Art. 34 must tell the affected people without undue delay when the risk is high. In practice the
clock runs while people decide whether the breach is notifiable at all, write the notices from scratch and keep
evidence in e-mail threads. Late or missing notifications are one of the most common reasons for supervisory
authority proceedings.

## What it does

1. **Intake.** An incident (JSON or form) starts the 72 hour clock from the moment of awareness.
2. **Risk assessment.** Deterministic, auditable rules structured after EDPB Guidelines 9/2022 (data sensitivity,
   volume, exposure, malicious intent, identifiability, vulnerable people, encryption, short outages). The result is
   one of: no notification (register only, Art. 33(5)), notify the authority (Art. 33), or notify the authority and
   the individuals (Art. 33 and 34). Every point of the score is shown with its legal basis. The Art. 34(3)(b)
   exception is handled. A language model never decides the outcome.
3. **Draft notices.** Authority notification with the Art. 33(3)(a)-(d) content, individual notice with the
   Art. 34(2) content, in Polish and English, plus 160 character SMS texts (drafts only, the SMS channel is not
   wired in this version).
4. **Human approval.** The DPO edits the drafts and approves with a name. The hash of the approved text is stored.
   If the text changes after approval, sending is refused.
5. **Send.** E-mail goes out through **Amazon SES v2**. Individual notices go to the incident's recipients, and a copy
   of the authority notification draft goes to the DPO for filing with the supervisory authority. Failed sends are
   logged and can be retried without duplicating the ones that succeeded.
6. **Evidence.** An append-only JSONL ledger chains every event with SHA-256 (intake, assessment, drafts, approval,
   every send attempt with the SES MessageId or error). Recipients are stored as a salted hash plus domain. The chain
   is verified on every page load and through `GET /api/ledger/verify`.

## AWS Customer Digital Services used

| Service | Where it is called at runtime |
|---|---|
| Amazon SES v2 (`boto3.client("sesv2")`, `SendEmail`) | [`app/mailer.py` line 42 (client) and line 67 (call)](app/mailer.py) |

## How to test it (free, no AWS account needed on your side)

Open the live demo URL from the Devpost page (HTTP Basic credentials are in the submission text if the demo is
protected).

1. On the home page click the sample `public_bucket`, then press **Start 72 hour clock and assess**.
2. Read the assessment: outcome `NOTIFY_AUTHORITY_AND_SUBJECTS`, with every factor and its legal basis.
3. Try to send without approval: the **Send** button does not exist yet, and the API call
   `POST /api/incidents/INC-2026-101/send` returns `409`.
4. Edit a draft if you like, type a name and press **Approve drafts**.
5. Press **Send through Amazon SES**. The deliveries table shows a real SES MessageId per message.
6. Open **view ledger**: every step is chained, and the banner shows `chain intact`.
7. Other samples: `misdirected_email` (assessment: no notification) and `ransomware_clinic`.

Safety allowlist: to keep the public demo from being used to send mail to real people, the app only sends to domains
in `ALLOWED_RECIPIENT_DOMAINS`, which defaults to `simulator.amazonses.com` (the SES mailbox simulator). Sandbox
accounts can only send to verified identities and the simulator anyway. All demo data is synthetic.

## Run it yourself

```bash
python -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
python -m pytest -q                      # 32 tests, no network, SES is stubbed
cp .env.example .env                     # then set SES_FROM to a verified SES identity
export $(grep -v '^#' .env | xargs)
uvicorn app.main:app --port 8000
```

Docker: `docker build -t breach-notice-agent . && docker run -p 8000:8000 --env-file .env -v bna-data:/data breach-notice-agent`.

AWS credentials come from the standard boto3 chain (environment variables or an IAM role). The only permission needed
is `ses:SendEmail` on the verified identity. Region defaults to `eu-central-1` (`AWS_REGION`).

## Tests

`tests/test_risk.py`: 12 synthetic breach scenarios with an expected outcome decided from Art. 33/34 and EDPB 9/2022,
plus the Art. 34(3)(b) downgrade and the 72 hour deadline. `tests/test_ledger.py`: chain verification, edit, deletion
and reorder detection. `tests/test_flow.py`: the whole workflow with a stubbed SES v2 client, covering refusal to
send without approval, tamper detection after approval, the recipient allowlist, SES failure and retry.

## Limitations (stated plainly)

- Delivery events (Delivery, Bounce, Complaint) from SES are not ingested yet. The ledger records the SES MessageId
  and the API result of `SendEmail`, not the final delivery status.
- SMS is drafted but not sent. WhatsApp is not implemented.
- The authority notification is delivered to the DPO as a draft. Filing with the supervisory authority is done by the
  DPO through the authority's own channel.
- No PDF register export and no dashboard in this version. The incident page shows the deadline countdown and the
  per-incident evidence log.
- The risk rules are a conservative decision aid, not legal advice. The DPO owns the decision.
- Amazon Bedrock is not used in this version.

## Pre-existing code

None. The repository was written from scratch during the submission period. The same team has a separate, earlier
project (Breach72, a different hackathon) in the same problem area; no code from it is used here.

## Use of AI assistants

Written with the help of Claude (Anthropic) as a coding assistant, reviewed and tested by the team.
