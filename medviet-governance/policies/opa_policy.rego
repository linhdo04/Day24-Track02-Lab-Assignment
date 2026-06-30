package medviet.data_access

import future.keywords.if
import future.keywords.in

default allow := false

# A restricted dataset may never be exported outside Vietnam, regardless of role.
restricted_export if {
    input.action == "export"
    input.data_classification == "restricted"
    input.destination_country != "VN"
}

allow if {
    input.user.role == "admin"
    not restricted_export
}

allow if {
    input.user.role == "ml_engineer"
    input.resource in {"training_data", "model_artifacts"}
    input.action in {"read", "write"}
    not restricted_export
}

allow if {
    input.user.role == "data_analyst"
    input.resource == "aggregated_metrics"
    input.action == "read"
    not restricted_export
}

allow if {
    input.user.role == "data_analyst"
    input.resource == "reports"
    input.action == "write"
    not restricted_export
}

allow if {
    input.user.role == "intern"
    input.resource == "sandbox_data"
    input.action in {"read", "write"}
    not restricted_export
}

deny if {
    input.user.role == "ml_engineer"
    input.resource == "production_data"
    input.action == "delete"
}

deny if {
    restricted_export
}
