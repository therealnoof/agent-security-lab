# Instructor Guide — Agent Security Lab

> **Status: scaffolding.** Most of this guide will fill in as we build out Modules 1–5. For now it points instructors at what already exists.

This guide is for the lab owner / instructor. **Complete all of `SETUP.md` §B before learners arrive.** Students follow [`STUDENT_GUIDE.md`](./STUDENT_GUIDE.md).

---

## Pre-day checklist

The authoritative checklist lives in [`SETUP.md` §B4 "Pre-flight"](../SETUP.md#b4-pre-flight-checklist-morning-of). Walk it on the actual room WiFi the morning of.

## Module-by-module instructor notes

### Module 0 — Setup & first BYOA session

- **Time budget:** 30 min including any per-learner credential issues. Build in slack — first-time docker pulls + Calypso UI wayfinding eat the clock.
- **Common stumble:** the proxy URL footgun. Reinforce verbally that it's the **provider name** in the URL, not the project name. The student guide covers this; learners will still get it wrong. The 404 message reads `{"detail":"Not Found"}` from a curl and `Provider not found` from the Python agent — recognize both.
- **Demo to lead with:** before turning learners loose, run Triage twice live (benign + poisoned alert) and pull both sessions up in the F5 UI side by side. The visual contrast sells the entire lab in 60 seconds.

### Module 1 — The over-privileged agent

> *Notes will be added when Module 1 ships.*

### Modules 2–5

> *Notes will be added as each module ships.*

---

## Quiz / assessment

> *To be added with the modules.* The PRD targets a 10-question post-lab quiz mapped to learning objectives.

---

## After the lab

- Revoke each per-learner CalypsoAI token in the tenant UI.
- Archive interesting sessions from F5 AI Security if you want to reuse them as case studies (per tenant retention policy).
- Capture learner feedback on what worked and what didn't — feed it back to the repo as issues.
