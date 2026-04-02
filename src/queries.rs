pub const ADMIN: &str = "SELECT key, value FROM access";
pub const POLICIES: &str = "SELECT id, bundle_id, uuid, display FROM access";
pub const ACTIVE_POLICY: &str = "SELECT client, client_type, policy_id FROM access";
pub const ACCESS: &str = "SELECT service, client, client_type, auth_value, auth_reason, auth_version, csreq, policy_id, indirect_object_identifier_type, indirect_object_identifier, indirect_object_code_identity FROM access";
pub const ACCESS_OVERRIDES: &str = "SELECT service FROM access";
pub const EXPIRED: &str = "SELECT service, client, client_type, csreq, last_modified, expored_at FROM access";
