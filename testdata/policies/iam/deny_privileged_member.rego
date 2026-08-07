# METADATA
# title: Project IAM privilege
# description: Blocks owner/editor grants to non-exempt members. Consults the exemptions data document.
package terraform.iam

import rego.v1

deny contains msg if {
	some rc in input.resource_changes
	rc.type == "google_project_iam_member"
	rc.change.after.role in {"roles/owner", "roles/editor"}
	not exempt(rc.change.after.member)
	msg := sprintf("privileged role grant: %s gets %s", [rc.change.after.member, rc.change.after.role])
}

exempt(member) if {
	member in data.exemptions.members
}
