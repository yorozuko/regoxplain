# Complete rule producing a scalar value — exercises the fired-detection
# default branch (deny := "msg" is defined-non-false, therefore fired).
package terraform.scalar

import rego.v1

deny := "pubsub topics are forbidden in this project" if {
	some rc in input.resource_changes
	rc.type == "google_pubsub_topic"
}
