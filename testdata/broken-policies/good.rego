package terraform.storage

import rego.v1

deny contains msg if {
	some rc in input.resource_changes
	rc.type == "google_storage_bucket"
	rc.change.after.public_access_prevention == "inherited"
	msg := sprintf("bucket weakens public_access_prevention: %s", [rc.address])
}
