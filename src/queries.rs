pub const ADMIN: &str = "SELECT key, value FROM admin";
pub const POLICIES: &str = "SELECT id, bundle_id, uuid, display FROM policies";
pub const ACTIVE_POLICY: &str = "SELECT client, client_type, policy_id FROM active_policy";
pub const ACCESS: &str = "SELECT service, client, client_type, auth_value, auth_reason, auth_version, csreq, policy_id, indirect_object_identifier_type, indirect_object_identifier, indirect_object_code_identity FROM access";
pub const ACCESS_OVERRIDES: &str = "SELECT service FROM access_overrides";
pub const EXPIRED: &str = "SELECT service, client, client_type, csreq, last_modified, expired_at FROM expired";
