# METADATA
# title: Network ingress
# description: Blocks firewall rules open to the internet.
package terraform.network

import rego.v1

import data.lib

deny contains msg if {
	some rc in input.resource_changes
	lib.firewall_is_open(rc)
	msg := sprintf("firewall open to 0.0.0.0/0: %s", [rc.address])
}

warn contains msg if {
	lib.any_open_firewall
	msg := "plan opens at least one firewall to the internet"
}
