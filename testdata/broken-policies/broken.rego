package terraform.broken

import rego.v1

deny contains msg if {
	some rc in input.resource_changes
	rc.type ==
	msg := "this file does not parse"
