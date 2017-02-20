#!/usr/bin/python

import string
import argparse
import re
import sys
#import pprint

try:
	import netaddr
except ImportError:
	print >>sys.stderr, 'ERROR: netaddr module not found.'
	sys.exit(1)


def cidr2str(addr):
	tmp = netaddr.IPNetwork(addr)
	return ' '.join([str(tmp.ip),str(tmp.netmask)])

def str2cidr(addr):
	return str(netaddr.IPNetwork(re.sub(' ','/',addr)))

def net2name(net):
	ip,mask=str2cidr(net).split('/')
	if '32' in mask: return 'h-'+ip
	else: return 'n-'+ip+'_'+mask

class PRule:
	'Class for a rule prototype'

	re_any=re.compile('^any$', re.IGNORECASE)
	re_dig=re.compile('^\d')
	re_nondig=re.compile('^\D')


	def __init__(self,line,):
		self.line=line.strip()
		self.parse()




	def check_arr(self,arr):
		if not len(arr):
			print >>sys.stderr, self.line
			print >>sys.stderr, "Too few fields in the policy."
			sys.exit(1)

	def parse_addr(self,arr):
		if 'any' in  arr[0]:
			addr='any'
			del arr[0]
		elif not ',' in arr[0]:
			if '/' in arr[0]:
				addr = cidr2str(arr[0])
				del arr[0]
			else:
				addr = ' '.join(arr[0:2])
				del arr[0:2]
		else:
			addr = [cidr2str(x) for x in arr[0].split(',')]
			addr.sort()
			del arr[0]
		return addr

	def parse_addr_args(self,addr):
		if '/' in addr:
			return cidr2str(addr)
		elif self.re_any.search(addr):
			return 'any'
		elif self.re_nondig.match(addr):
			return "object-group "+addr
		elif ' ' in addr:
			return addr
		else: return addr+' 255.255.255.255'

	def parse(self):

		addr1=''
		addr2=''

		arr=line.split()

		# Get the first address
		addr1=self.parse_addr(arr)
		self.check_arr(arr)

		if self.re_dig.match(arr[0]) or 'any' in arr[0] or 'host' in arr[0]:
			addr2=self.parse_addr(arr)
			self.check_arr(arr)

		if not ',' in arr[0]:
#			self.proto = self.protocol(arr[0])
#			self.srv = self.port(arr[0])
			self.srv=arr[0]
		else:
			self.proto = ''
			self.srv = [ x for x in arr[0].split(',')]
		del arr[0]

		if len(arr): self.action = arr[0]
		elif not args.deny: self.action = 'permit'
		else: self.action = 'deny'

		if addr2:
			self.src = addr1
			self.dst = addr2
		elif args.src:
			self.src = self.parse_addr_args(args.src)
			self.dst = addr1
		elif args.dst:
			self.src = addr1
			self.dst = self.parse_addr_args(args.dst)
		else:
			print >>sys.stderr, self.line
			print >>sys.stderr, "Either too few fields or define either --src IP or --dst IP"
			sys.exit(1)

class FW():
	'General Firewall Class'
	devtype='' #Device type

	def fw_netobj_print(self,netobj):
		pass

	def fw_srvobj_print(self,srvobj):
		pass

	def netobj_add(self,netobj,rule):
		pass

	def srvobj_add(self,srvobj,rule):
		pass

class FGT(FW):
	'FortiGate specific class'
	devtype='fgt'
	vdom = ''
	srcintf = ''
	dstintf = ''
	rulenum = 0

	def __init__(self,vdom='root',srcintf='any',dstintf='any',rulenum=10000):
		self.vdom = vdom
		self.srcintf = srcintf
		self.dstintf = dstintf
		self.rulenum=10000

	def upnum(self):
		self.rulenum += 1

	def rprint(self,rule):
		print self.rulenum, self.type
		self.rulenum += 1

	def fw_netobj_print(self,netobj):
		print 'config firewall address'
		for obj in netobj:
			print ' edit '+ netobj[obj]
			print '  set subnet ' + obj
			print ' next\n'
		print 'end'

	def fw_srvobj_print(self,srvobj):
		print 'config firewall service custom'
		for obj in srvobj:
			proto,ports = obj.split(':')
			print ' edit ' + srvobj[obj]
			if 'udp' in proto or 'tcp' in proto:
				print '  set protocol TCP/UDP/SCTP'
				print '  set ' + proto + '-portrange ' + ports
			elif 'icmp' in proto:
				print '  set protocol ICMP'
				if ports:
					print '  set icmptype ' + ports
			elif 'ip' in proto:
				if ports:
					print '  set protocol IP'
					print '  set protocol-number ' + ports
			print ' next'
		print 'end'

	def netobj_add(self,netobj,rule):
		for addrs in rule.src,rule.dst:
			# Convert a single IP-address to a list
			if not type(addrs) is list: addrs=[addrs]
			for addr in addrs:
				if addr not in netobj:
					netobj[addr] = net2name(addr)

	def srvobj_add(self,srvobj,rule):
		services = rule.srv
		if not type(services) is list: services=[services]
		for srv in services:
			if srv not in srvobj:
				if '*' in srv:
					srvobj[srv] = 'ALL'
				else:
					srvobj[srv]=re.sub(':','-',srv)



class ASA(FW):
	'ASA specific class'
	devtype='asa'
	aclname='' #ACL name

	def __init__(self,aclname='Test_ACL'):
		self.aclname=aclname

	def rprint(self,rule):
		print  " ".join(["access-list", self.aclname, "extended", self.protocol(rule.srv), rule.src, rule.dst, self.port(rule.srv)])


	def protocol(self,service):
		if "*" in service:
			return "ip"
		elif ":" in service:
			tmp = service.split(":")
			return tmp[0]
		else:
			return service

	def port(self,service):
		if ":" in service:
			tmp = service.split(":")
			if "-" in tmp[1]:
				low,high = tmp[1].split("-")
				if int(low) == 1:
					return "lt " +high
				elif int(high) == 65535:
					return "gt " +low
				else:
					return "range "+low+" "+high
			elif "icmp" not in tmp[0]:
				return "eq "+tmp[1]
			else:
				return tmp[1]
		else:
			return ''




class Policy(PRule):
	'Class for the whole policy'
	netobj = {} # { '10.0.1.0 255.255.255.0': 'n-10.0.1.0_24' }
	srvobj = {} # { 'tcp:20-23': 'TCP-20-23' }
	netgrp = {}	# { 'net-group1: }network-groups
	srvgrp = {}	# service-groups
	policy = [] # global policy
	device = '' # 'ASA' or 'FGT' class object

	def __init__(self,dev):
		self.device = dev

	def getdev(self):
		return self.device

	def addrule(self,rule):
		self.policy.append(rule)

	def getpol(self):
		return self.policy

	def rprint(self):
		for rule in self.policy:
			dev.rprint(rule)



parser = argparse.ArgumentParser()
parser.add_argument('pol', default="-", nargs='?', help="Firewall policy or \"-\" to read from the console")
sd = parser.add_mutually_exclusive_group()
sd.add_argument('-s','--src', default=False, help="Source IP-address/netmask or object name")
sd.add_argument('-d','--dst', default=False, help="Destination IP-address/netmasks or object name")
parser.add_argument('--deny', help="Use deny by default instead of permit", action="store_true")
parser.add_argument('--acl', default="Test_ACL", nargs='?', help="ACL name for ASA. Default=Test_ACL")
parser.add_argument('--dev', default="asa", help="Type of device: asa (default) or fgt")
parser.add_argument('--vdom', default="root", help="VDOM name for FortiGate. Default - root")
parser.add_argument('--si', default="any", help="Source interface for FortiGate. Default - any")
parser.add_argument('--di', default="any", help="Destination interface for FortiGate. Default - any")
parser.add_argument('--rn', default=10000, help="Starting rule number for Fortigate. Default - 10000")
args = parser.parse_args()



f=sys.stdin if "-" == args.pol else open (args.pol,"r")

if 'asa' in args.dev:
	dev=ASA(args.acl)
elif 'fgt' in args.dev:
	dev=FGT(args.vdom, args.si, args.di, args.rn)
else:
	print >>sys.stderr, dev, "- not supported device. It should be asa (Cisco ASA) or fgt (FortiGate)"
	sys.exit(1)

policy = Policy(dev)

for line in f:
	r=PRule(line)
	policy.addrule(r)

policy.rprint()
