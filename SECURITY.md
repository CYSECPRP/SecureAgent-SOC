# Security Policy

SecureAgent-SOC is a research prototype built for a university project. It is not meant for production use.

## Supported versions

Only the latest version of the `main` branch gets fixes.

## Reporting a vulnerability

Please report vulnerabilities privately through GitHub: open the **Security** tab of this repository and choose **Report a vulnerability**, or use [this link](https://github.com/CYSECPRP/SecureAgent-SOC/security/advisories/new). Do not open a public issue.

Please include:

- the affected part (for example the ingest API, the sanitizer or an OPA policy),
- the steps to reproduce,
- the impact you expect.

We will reply as soon as we can and credit you in the fix, unless you prefer to stay anonymous.

## Scope

In scope: the backend API, the input sanitizer and taint tracker (SC1), the OPA policies, the data pipeline scripts and the attack simulator.

Findings that bypass the agent defences, such as a prompt injection that gets past SC1 or a tool call that gets past the OPA policies, are especially welcome because they help the research.

## Development defaults

`docker-compose.yml`, `.env.example` and `backend/src/config.py` contain development defaults such as the database password and the secret key. They are public on purpose so the project runs out of the box. Change them before you expose any service beyond your own machine.
