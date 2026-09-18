-- 0009: MTA-STS policies.
--
-- What this product serves at mta-sts.<domain>/.well-known/mta-sts.txt.
-- MTA-STS is two halves that must agree - a TXT record announcing an id, and
-- a policy file served over HTTPS - and only the first is DNS. This is the
-- second.

CREATE TABLE mta_sts_policies (
    id                  TEXT PRIMARY KEY,
    tenant_id           TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    client_id           TEXT NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    domain_id           TEXT NOT NULL REFERENCES domains(id) ON DELETE CASCADE,

    mode                TEXT NOT NULL DEFAULT 'testing'
                        CHECK (mode IN ('testing','enforce','none')),
    mx_json             TEXT NOT NULL,
    max_age_seconds     INTEGER NOT NULL DEFAULT 604800,
    policy_id           TEXT NOT NULL,

    created_at          TEXT NOT NULL,
    updated_at          TEXT NOT NULL,
    updated_by          TEXT
);

CREATE UNIQUE INDEX ux_mta_sts_domain ON mta_sts_policies(domain_id);
