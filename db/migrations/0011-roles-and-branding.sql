-- Roles within an organisation, customer logins, and white-label branding.
--
-- Roles are Entra groups, like membership: one group per organisation for
-- admins (settings, clients, providers), one for operators (assigning,
-- applying fixes, importing) and one for viewers (read only). The existing
-- entra_group_id is the operator group. A client can name a group of its own:
-- its members see that one client and nothing else, read only, which is the
-- customer login every hosted DMARC product offers.
ALTER TABLE tenants ADD COLUMN admin_group_id TEXT;
ALTER TABLE tenants ADD COLUMN viewer_group_id TEXT;

-- What the organisation looks like: the accent colour and logo in the
-- sidebar, and how it names itself on the reports it sends.
ALTER TABLE tenants ADD COLUMN brand_primary_color TEXT;
ALTER TABLE tenants ADD COLUMN brand_logo TEXT;          -- data: URL, small
ALTER TABLE tenants ADD COLUMN provider_name TEXT;       -- "prepared by ..."
ALTER TABLE tenants ADD COLUMN brand_contact_block TEXT; -- report footer

ALTER TABLE clients ADD COLUMN entra_group_id TEXT;

-- Who did what, for the settings page and for anybody asking afterwards.
-- Not the DNS change trail, which dns_changes already keeps in full; this
-- is the rest: organisations, groups, clients, providers, imports.
CREATE TABLE audit_log (
    id                  INTEGER PRIMARY KEY,
    tenant_id           TEXT,                          -- NULL for platform-wide
    at                  TEXT NOT NULL,
    actor               TEXT NOT NULL,
    action              TEXT NOT NULL,
    detail              TEXT
);

CREATE INDEX ix_audit_tenant_at ON audit_log(tenant_id, at DESC);
