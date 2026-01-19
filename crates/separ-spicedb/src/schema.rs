//! SpiceDB schema definition for Separ

/// The complete Separ authorization schema for SpiceDB
pub const YEKTA_SCHEMA: &str = r#"
definition platform {
    relation admin: user | service_account
    relation member: user | service_account
    
    permission manage = admin
    permission view = admin + member
}

definition tenant {
    relation platform: platform
    relation owner: user | service_account
    relation admin: user | service_account | group#member
    relation member: user | service_account | group#member
    
    permission manage = owner + admin + platform->admin
    permission view = owner + admin + member + platform->admin
    permission create_workspace = owner + admin
    permission manage_users = owner + admin
    permission manage_groups = owner + admin
    permission manage_oauth = owner + admin
    permission view_audit = owner + admin
}

definition workspace {
    relation tenant: tenant
    relation owner: user | service_account
    relation admin: user | service_account | group#member
    relation member: user | service_account | group#member
    relation viewer: user | service_account | group#member
    
    permission manage = owner + admin + tenant->manage
    permission view = owner + admin + member + viewer + tenant->manage
    permission create_application = owner + admin + tenant->manage
    permission manage_members = owner + admin
}

definition application {
    relation workspace: workspace
    relation owner: user | service_account
    relation admin: user | service_account | group#member
    relation developer: user | service_account | group#member
    relation viewer: user | service_account | group#member
    
    permission manage = owner + admin + workspace->manage
    permission deploy = owner + admin + developer + workspace->manage
    permission view = owner + admin + developer + viewer + workspace->view
    permission manage_resources = owner + admin
    permission define_permissions = owner + admin
}

definition resource {
    relation application: application
    relation owner: user | service_account
    relation editor: user | service_account | group#member
    relation viewer: user | service_account | group#member
    
    permission manage = owner + application->manage
    permission edit = owner + editor + application->manage
    permission view = owner + editor + viewer + application->view
    permission delete = owner + application->manage
}

definition user {
    relation self: user
    relation tenant: tenant
    
    permission manage = self + tenant->manage_users
    permission view = self + tenant->view
}

definition group {
    relation tenant: tenant
    relation owner: user | service_account
    relation admin: user | service_account
    relation member: user | service_account | group#member
    
    permission manage = owner + admin + tenant->manage_groups
    permission view = owner + admin + member + tenant->view
    permission add_member = owner + admin
    permission remove_member = owner + admin
}

definition service_account {
    relation tenant: tenant
    relation owner: user
    relation admin: user | group#member
    
    permission manage = owner + admin + tenant->manage
    permission use = owner + admin
    permission rotate_credentials = owner + admin
}

definition api_key {
    relation service_account: service_account
    relation creator: user
    
    permission manage = creator + service_account->manage
    permission use = service_account->use
    permission revoke = creator + service_account->manage
}

definition role {
    relation tenant: tenant
    relation creator: user | service_account
    relation assignee: user | service_account | group#member
    
    permission manage = creator + tenant->manage
    permission assign = creator + tenant->manage
    permission view = creator + assignee + tenant->view
}

definition oauth_provider {
    relation tenant: tenant
    relation admin: user | service_account
    
    permission manage = admin + tenant->manage_oauth
    permission view = admin + tenant->view
    permission configure = admin + tenant->manage_oauth
}

definition sync_config {
    relation tenant: tenant
    relation admin: user | service_account
    
    permission manage = admin + tenant->manage
    permission view = admin + tenant->view
    permission trigger = admin + tenant->manage
}

definition yekta_resource {
    relation tenant: tenant
    relation owner: user | service_account
    relation editor: user | service_account | group#member
    relation viewer: user | service_account | group#member
    
    permission manage = owner + tenant->manage
    permission write = owner + editor + tenant->manage
    permission read = owner + editor + viewer + tenant->view
}
"#;
