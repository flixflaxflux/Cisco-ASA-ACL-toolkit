#!/usr/bin/python

from meraki_sdk.meraki_sdk_client import MerakiSdkClient
from meraki_sdk.exceptions.api_exception import APIException
from meraki_sdk.models.policy_enum import PolicyEnum
from meraki_sdk.models.rule_model import RuleModel
from meraki_sdk.models.update_network_l3_firewall_rules_model import UpdateNetworkL3FirewallRulesModel

x_cisco_meraki_api_key = ''
meraki = MerakiSdkClient(x_cisco_meraki_api_key)

mx_l3_firewall_controller = meraki.mx_l3_firewall
networks_controller = meraki.networks

orgs = meraki.organizations.get_organizations()

print(orgs)

id = orgs[0]["id"]

collect = {}
collect['organization_id'] = id
nets = networks_controller.get_organization_networks(collect)
print(nets)

for line in nets:
    print(line["id"])
    l3_rules = mx_l3_firewall_controller.get_network_l3_firewall_rules(line["id"])
    print(l3_rules)

collect = {}
network_id = 'N_596726950626606580'
collect['network_id'] = network_id

update_network_l_3_firewall_rules = UpdateNetworkL3FirewallRulesModel()
update_network_l_3_firewall_rules.rules = []

update_network_l_3_firewall_rules.rules.append(RuleModel())
update_network_l_3_firewall_rules.rules[0].comment = 'Allow TCP traffic to subnet with HTTP servers.'
update_network_l_3_firewall_rules.rules[0].policy = 'deny'
update_network_l_3_firewall_rules.rules[0].protocol = 'tcp'
update_network_l_3_firewall_rules.rules[0].src_port = 'any'
update_network_l_3_firewall_rules.rules[0].src_cidr = 'any'
update_network_l_3_firewall_rules.rules[0].dest_port = '443'
update_network_l_3_firewall_rules.rules[0].dest_cidr = '192.168.1.0/24'
update_network_l_3_firewall_rules.rules[0].syslog_enabled = False

update_network_l_3_firewall_rules.rules.append(RuleModel())
update_network_l_3_firewall_rules.rules[1].comment = 'Allow TCP traffic to subnet with HTTP servers.'
update_network_l_3_firewall_rules.rules[1].policy = 'allow'
update_network_l_3_firewall_rules.rules[1].protocol = 'tcp'
update_network_l_3_firewall_rules.rules[1].src_port = 'any'
update_network_l_3_firewall_rules.rules[1].src_cidr = 'any'
update_network_l_3_firewall_rules.rules[1].dest_port = '443'
update_network_l_3_firewall_rules.rules[1].dest_cidr = '192.168.1.0/24'
update_network_l_3_firewall_rules.rules[1].syslog_enabled = False
update_network_l_3_firewall_rules.syslog_default_rule = False

collect['update_network_l3_firewall_rules'] = update_network_l_3_firewall_rules


result = mx_l3_firewall_controller.update_network_l3_firewall_rules(collect)
print(result)
