# METADATA
# title: Storage bucket exposure
# description: Blocks public GCS bucket IAM bindings and weakened public access prevention.
package terraform.storage

import rego.v1

import data.lib

# Body 1: public IAM member binding on a bucket.
deny contains msg if {
	some rc in input.resource_changes
	lib.bucket_iam_is_public(rc)
	msg := sprintf("public bucket IAM binding: %s", [rc.address])
}

# Body 2: bucket with public_access_prevention weakened from enforced.
deny contains msg if {
	some rc in input.resource_changes
	rc.type == "google_storage_bucket"
	rc.change.after.public_access_prevention == "inherited"
	msg := sprintf("bucket weakens public_access_prevention: %s", [rc.address])
}

# Buckets without uniform bucket-level access are detected but not blocked.
warn contains msg if {
	some rc in input.resource_changes
	rc.type == "google_storage_bucket"
	rc.change.after.uniform_bucket_level_access == false
	msg := sprintf("bucket without uniform_bucket_level_access: %s", [rc.address])
}
