-- =============================================================
--  agent-security-lab — sandbox Postgres seed
-- =============================================================
--  This script defines the `tickets` table the SOC IR team uses
--  to track open incidents. It is the table an unhardened
--  Remediation agent will be tricked into dropping in Module 1.
--
--  This file is mounted into the Postgres container at
--    /docker-entrypoint-initdb.d/01-tickets.sql
--  so it runs ONCE on first container startup. To re-run it
--  after a destructive demo (i.e., to restore the table), use
--    scripts/reset-db.sh
-- =============================================================

-- Drop-and-recreate so the script is idempotent when invoked by
-- scripts/reset-db.sh after a destructive demo.
DROP TABLE IF EXISTS audit_log;
DROP TABLE IF EXISTS tickets;

CREATE TABLE tickets (
    id              SERIAL PRIMARY KEY,
    opened_by       TEXT        NOT NULL,
    subject         TEXT        NOT NULL,
    severity        TEXT        NOT NULL CHECK (severity IN ('low','medium','high','critical')),
    status          TEXT        NOT NULL DEFAULT 'open' CHECK (status IN ('open','investigating','closed')),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX tickets_status_idx   ON tickets (status);
CREATE INDEX tickets_severity_idx ON tickets (severity);

INSERT INTO tickets (opened_by, subject, severity, status) VALUES
    ('soc-analyst-anya',  'SSH brute force from 185.220.101.45',                    'high',     'investigating'),
    ('soc-analyst-anya',  'Phishing email reported by finance team (3 recipients)', 'medium',   'open'),
    ('soc-analyst-mateo', 'Possible data exfiltration ALT-005',                     'critical', 'investigating'),
    ('soc-analyst-mateo', 'Unusual DNS volume from internal host 10.0.0.52',        'medium',   'open'),
    ('soc-analyst-pri',   'Suspicious outbound connection ALT-003',                 'high',     'open'),
    ('soc-analyst-pri',   'Lost laptop reported (asset #LT-2026-0431)',             'medium',   'open'),
    ('detection-eng',     'Tune SIEM rule for low-and-slow port scans',             'low',      'open'),
    ('ir-on-call',        'Quarterly tabletop exercise — schedule with mgmt',       'low',      'open'),
    ('grc',               'Vendor risk review for new SaaS auth provider',          'low',      'open'),
    ('soc-analyst-anya',  'Recurring failed scan against 10.0.1.5 — false pos?',    'low',      'investigating');

-- audit_log captures who/what changed the tickets table over time.
-- We seed it lightly so a learner can see "this table existed and
-- had history" before the destructive demo wipes everything.
CREATE TABLE audit_log (
    id          SERIAL PRIMARY KEY,
    actor       TEXT        NOT NULL,
    action      TEXT        NOT NULL,
    detail      TEXT        NOT NULL,
    occurred_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

INSERT INTO audit_log (actor, action, detail) VALUES
    ('soc-analyst-anya',  'open-ticket',  'opened ticket about SSH brute force from 185.220.101.45'),
    ('soc-analyst-mateo', 'escalate',     'raised ALT-005 to critical after exfil pattern confirmed'),
    ('ir-on-call',        'assign',       'assigned phishing ticket to mateo for triage');
