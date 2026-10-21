# Security policy

This repository ships an internet-facing honeypot plus detections and an LLM
triage step. Findings here are handled like any security product: privately, so
a disclosure doesn't teach attackers how to defeat the sensor.

## Reporting a vulnerability

- **Do not open a public issue** for anything that could help attackers evade the
  sensor, the detections, or the triage agent.
- Open a [private security advisory](https://github.com/matt869/ai-soc-pipeline/security/advisories/new)
  on GitHub instead.

What to include: the affected component, a short description of the impact, and
steps to reproduce if you have them. I aim to acknowledge within 72 hours and to
ship a fix as soon as I can.

## Supported versions

Only the latest commit on `main` is supported. There are no tagged releases.

## Deploying safely

- Run the sensor in an isolated VNet/subnet with no route to production
  ([honeypot/README.md](honeypot/README.md)).
- It deliberately accepts weak passwords so bots get a shell. Never give it real
  credentials, and never let it touch production data.
- Treat every byte an attacker sends as hostile and untrusted. The triage prompt
  and the prompt-injection evaluation set are built around that assumption.
