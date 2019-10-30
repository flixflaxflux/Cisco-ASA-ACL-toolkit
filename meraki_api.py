#!/usr/bin/python

from meraki_sdk.meraki_sdk_client import MerakiSdkClient
from meraki_sdk.exceptions.api_exception import APIException

x_cisco_meraki_api_key = '15da0c6ffff295f16267f88f98694cf29a86ed87'

meraki = MerakiSdkClient(x_cisco_meraki_api_key)
mx_l3_firewall_controller = meraki.mx_l3_firewall

orgs = meraki.organizations.get_organizations()
print(orgs[0]["id"])

id = orgs[0]["id"]

result = meraki.organizations.get_organization_inventory(id)
print(result)
for line in result:
    print(line["networkId"])
    l3_rules = mx_l3_firewall_controller.get_network_l3_firewall_rules(line["networkId"])
    print(l3_rules)
