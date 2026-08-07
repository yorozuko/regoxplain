# Per-resource-mode policy shape: input is ONE resource_changes entry,
# not the whole plan (CI styles that iterate resources).
package terraform.rc

import rego.v1

deny contains msg if {
	input.type == "google_compute_firewall"
	some r in input.change.after.source_ranges
	r == "0.0.0.0/0"
	msg := sprintf("open firewall: %s", [input.address])
}
