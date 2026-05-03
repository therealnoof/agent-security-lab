# Calypso policy / scanner templates

This folder is the eventual home for **importable F5 AI Guardrails configurations** that match Module 4's walkthrough. As of writing the lab does not ship them yet — the Calypso UI handles configuration interactively, and we don't have a stable export format pinned for the lab tenant version.

For now, learners configure scanners by hand following the Module 4 instructions in [`docs/STUDENT_GUIDE.md`](../docs/STUDENT_GUIDE.md#module-4--prompt-injection--f5-ai-guardrails). Instructors should pre-stage the scanners on the cohort's Agent project before the lab so that Slice B's "turn it on" step is one click rather than a five-minute UI quest.

When templates land, expected layout:

```
policies/
├── README.md                           ← you are here
├── module-04-prompt-injection.json     ← input scanner: detect injection / jailbreak attempts
├── module-04-data-egress.json          ← input scanner: detect PII / data-egress prompts
└── module-04-output-leakage.json       ← output scanner: detect sensitive data leaving the model
```
