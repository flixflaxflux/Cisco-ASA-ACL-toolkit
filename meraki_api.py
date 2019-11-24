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

id = orgs[1]["id"]

collect = {}
collect['organization_id'] = id
nets = networks_controller.get_organization_networks(collect)
print(nets)

#get rules
#for line in nets:
#    print(line["id"])
#    l3_rules = mx_l3_firewall_controller.get_network_l3_firewall_rules(line["id"])
#    print(l3_rules)

collect = {}
network_id = 'N_679480593779539752'
collect['network_id'] = network_id

def set_meraki_rule(Rules):

    i = 0

    update_network_l_3_firewall_rules = UpdateNetworkL3FirewallRulesModel()
    update_network_l_3_firewall_rules.rules = []
    update_network_l_3_firewall_rules.syslog_default_rule = False

    for rule in Rules:
        update_network_l_3_firewall_rules.rules.append(RuleModel())
        update_network_l_3_firewall_rules.rules[i].comment = rule["comment"]
        update_network_l_3_firewall_rules.rules[i].policy = "allow" if "permit" in rule["policy"] else "deny"
        update_network_l_3_firewall_rules.rules[i].protocol = "any" if "ip" in rule["protocol"] else rule["protocol"]
        update_network_l_3_firewall_rules.rules[i].src_port = 'any'
        update_network_l_3_firewall_rules.rules[i].src_cidr = "any" if "0.0.0.0/0" in rule["srcCidr"] else rule["srcCidr"]
        update_network_l_3_firewall_rules.rules[i].dest_port = "any" if " " in rule["destPort"] else rule["destPort"]
        update_network_l_3_firewall_rules.rules[i].dest_cidr = "any" if "0.0.0.0/0" in rule["destCidr"] else rule["destCidr"]
        update_network_l_3_firewall_rules.rules[i].syslog_enabled = False

        i = i + 1

    collect['update_network_l3_firewall_rules'] = update_network_l_3_firewall_rules
    print(collect)
    result = mx_l3_firewall_controller.update_network_l3_firewall_rules(collect)
    print(result)
