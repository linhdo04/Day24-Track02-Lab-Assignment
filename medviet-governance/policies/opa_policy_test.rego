package medviet.data_access

test_admin_can_read_raw_data if {
    allow with input as {
        "user": {"role": "admin"},
        "resource": "patient_data",
        "action": "read",
    }
}

test_ml_engineer_cannot_delete_production if {
    not allow with input as {
        "user": {"role": "ml_engineer"},
        "resource": "production_data",
        "action": "delete",
    }
    deny with input as {
        "user": {"role": "ml_engineer"},
        "resource": "production_data",
        "action": "delete",
    }
}

test_analyst_can_read_aggregates if {
    allow with input as {
        "user": {"role": "data_analyst"},
        "resource": "aggregated_metrics",
        "action": "read",
    }
}

test_restricted_export_outside_vietnam_is_denied if {
    not allow with input as {
        "user": {"role": "admin"},
        "resource": "patient_data",
        "action": "export",
        "data_classification": "restricted",
        "destination_country": "US",
    }
    deny with input as {
        "user": {"role": "admin"},
        "resource": "patient_data",
        "action": "export",
        "data_classification": "restricted",
        "destination_country": "US",
    }
}
