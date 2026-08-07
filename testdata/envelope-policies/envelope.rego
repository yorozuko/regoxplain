# Mirrors the real-world convention where CI nests the terraform plan under
# input.plan — policies import it as tfplan. Requires input_mode envelope:plan.
package terraform.envelope

import input.plan as tfplan
import rego.v1

approved_regions := {"northamerica-northeast1", "northamerica-northeast2"}

deny contains msg if {
	some r in tfplan.resource_changes
	r.type == "google_sql_database_instance"
	after := object.get(object.get(r, "change", {}), "after", {})
	region := object.get(after, "region", "")
	region == ""
	msg := sprintf("Cloud SQL region must be set to one of %v — missing on %v", [sort(approved_regions), r.address])
}

deny contains msg if {
	some r in tfplan.resource_changes
	r.type == "google_sql_database_instance"
	after := object.get(object.get(r, "change", {}), "after", {})
	region := object.get(after, "region", "")
	region != ""
	not approved_regions[region]
	msg := sprintf("Cloud SQL region %v is not approved for %v", [region, r.address])
}
