-- Organizations are the tenants table, which every scoped table has carried
-- from the start and nothing ever filtered on. From here on it is filtered
-- on: an organization's people see its clients and domains and nothing else.
--
-- Who belongs to an organization is decided by an Entra security group. The
-- group's object id is recorded here and matched against the groups claim of
-- whoever signs in. A master group, named in configuration rather than here,
-- sees every organization.
ALTER TABLE tenants ADD COLUMN entra_group_id TEXT;
