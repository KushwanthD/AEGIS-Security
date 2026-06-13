# Users

id
username
email
password_hash
is_active
created_at

# Assets

id
user_id
asset_type
asset_value
verification_status
verification_token_hash
verification_date
is_active
created_at

# Assessments

id
asset_id
assessment_reference
status
requested_at
approved_at
started_at
completed_atx

# AuthorizationTokens

id
assessment_id
token_hash
created_at
expires_at
used
used_at


# AuditLogs

id
user_id
asset_id
assessment_id
event_type
event_details
created_at

# ReconResults

id
assessment_id
recon_execution_id
recon_type
result_data
created_at

# ScanResults

id
assessment_id
scan_execution_id
tool_name
finding_title
finding_category
severity
description
evidence
created_at

# CorrelatedFindings

id
assessment_id
correlation_title
risk_level
correlation_reason
recommended_action
created_at

# Approvals

id
assessment_id
requested_by
approved_by
decision
comments
created_at
