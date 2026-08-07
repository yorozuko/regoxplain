# METADATA
# title: Shared helpers
# description: Cross-package helper rules used by the terraform gate policies.
package lib

import rego.v1

# bucket_iam_is_public: a google_storage_bucket_iam_member binding grants
# access to allUsers or allAuthenticatedUsers.
bucket_iam_is_public(rc) if {
	rc.type == "google_storage_bucket_iam_member"
	rc.change.after.member in {"allUsers", "allAuthenticatedUsers"}
}

# firewall_is_open: a google_compute_firewall ingress rule admits the world.
firewall_is_open(rc) if {
	rc.type == "google_compute_firewall"
	some range in rc.change.after.source_ranges
	range == "0.0.0.0/0"
}

# any_open_firewall: the plan contains at least one world-open firewall.
# No-arg rule referencing input directly — callers inherit its input refs
# as indirect evidence.
any_open_firewall if {
	some rc in input.resource_changes
	firewall_is_open(rc)
}
