#!/usr/bin/env python3

import dns.zone
import dns.name
import dns.message
import dns.rdatatype
import dns.rdataclass
import dns.renderer
import dns.rcode
import dns.flags
import dns.namedict

import socket
import select

import sys
import traceback
import binascii

import logging


class zone:
	def __init__(self, name, fname):
		self.zone = dns.zone.from_file(fname, name, relativize=False)
		self.zone.check_origin()
		self.allnames = set()
		for name in self.zone.nodes.keys():
			while len(name.labels) > len(self.zone.origin.labels):
				self.allnames.add(name)
				name = name.parent()
		self.allnames.add(self.zone.origin)
		
	def reply(self, query):
		return reply_from_zone(self.zone, query, self.allnames)

def reply_from_zone(zone, query, allnames):
	name = query.question[0].name
	rtype = query.question[0].rdtype
	rclass = query.question[0].rdclass

	if not name.is_subdomain(zone.origin):
		return gen_refused(query)

	# qname is below delegation -> referral to the delegation
	t = name
	while len(t.labels) > len(zone.origin.labels):
		r = zone.get_rrset(t, dns.rdatatype.NS)
		if r:
			return gen_referral(zone, query, r)
		t = t.parent()

	# find exact match to qname & qtype
	r = zone.get_rrset(name, rtype)
	if r:
		return gen_answer(zone, query, (r,))

	# try CNAME
	r = zone.get_rrset(name, dns.rdatatype.CNAME)
	if r:
		return gen_answer(zone, query, (r,))
	# try ANY
	if rtype == dns.rdatatype.ANY:
		r = zone.get_node(name)
		rrsets = []
		if r:
			rrsets = []
			for rdataset in r.rdatasets:
				rrsets.append(dns.rrset.from_rdata_list(name,
					rdataset.ttl, rdataset))
			return gen_answer(zone, query, rrsets)

	# TODO: try DNAME, wildcard,...

	# NODATA
	# 1. rrset not found for qname
	#   (we have A record only for qname but qtype is AAAA)
	# 2. empty non-terminal
	
	if name in allnames:
		return gen_nxdomain_nodata(zone, query, nxdomain=False)

	# generate NXDOMAIN
	return gen_nxdomain_nodata(zone, query, nxdomain=True)

def gen_answer(zone, query, rrsets):
	r = dns.message.make_response(query, our_payload=4096)
	r.flags |= dns.flags.AA
	r.flags &= ~dns.flags.RD

	# create answer section
	for rrset in rrsets:
		rrset_to_be_create = r.get_rrset(r.answer, rrset.name,
			rrset.rdclass, rrset.rdtype, create=True)
		rrset_to_be_create.ttl = rrset.ttl
		rrset_to_be_create.rdclass = rrset.rdclass
		for rdata in rrset:
			rrset_to_be_create.add(rdata)

	# create authority section - take NS records from zone apex
	rrset = zone.get_rrset(zone.origin, dns.rdatatype.NS)
	if rrset:
		rrset_to_be_create = r.get_rrset(r.authority, rrset.name,
				rrset.rdclass, rrset.rdtype, create=True)
		rrset_to_be_create.ttl = rrset.ttl
		rrset_to_be_create.rdclass = rrset.rdclass
		for rdata in rrset:
			rrset_to_be_create.add(rdata)

	# contruct additional section
	for rrset in r.answer + r.authority:
		for rd in rrset:
			for addrtype in (dns.rdatatype.A, dns.rdatatype.AAAA):
				add = None
				if rrset.rdtype == dns.rdatatype.NS:
					name = rd.target
					add = zone.get_rrset(name, addrtype)
				elif rrset.rdtype == dns.rdatatype.MX:
					name = rd.exchange
					add = zone.get_rrset(name, addrtype)
				if add:
					rrset_to_be_create = r.get_rrset(r.additional,
						name, add.rdclass, add.rdtype, create=True)
					rrset_to_be_create.ttl = add.ttl
					rrset_to_be_create.rdclass = add.rdclass
					for rdata in add:
						rrset_to_be_create.add(rdata)
	
	return r
	

def gen_referral(zone, query, rrset):

	r = dns.message.make_response(query, our_payload=4096)
	r.flags &= ~dns.flags.RD
	rrset_to_be_create = r.get_rrset(r.authority, rrset.name,
		rrset.rdclass, rrset.rdtype, create=True)
	rrset_to_be_create.ttl = rrset.ttl
	rrset_to_be_create.rdclass = rrset.rdclass
	for rdata in rrset:
		rrset_to_be_create.add(rdata)

	# construct additional section
	for rd in rrset:
		for addrtype in (dns.rdatatype.A, dns.rdatatype.AAAA):
			add = zone.get_rrset(rd.target, addrtype)
			if add:
				rrset_to_be_create = r.get_rrset(r.additional,
					rd.target, add.rdclass, add.rdtype, create=True)
				rrset_to_be_create.ttl = add.ttl
				rrset_to_be_create.rdclass = add.rdclass
				for rdata in add:
					rrset_to_be_create.add(rdata)

	return r


def gen_nxdomain_nodata(zone, query, nxdomain=True):

	r = dns.message.make_response(query, our_payload=4096)
	r.flags &= ~dns.flags.RD
	if nxdomain:
		r.set_rcode(dns.rcode.NXDOMAIN)
	else:
		r.set_rcode(dns.rcode.NOERROR)
	rrset = zone.get_rrset(zone.origin, dns.rdatatype.SOA)
	if rrset:
		rrset_to_be_create = r.get_rrset(r.authority, rrset.name,
			rrset.rdclass, rrset.rdtype, create=True)
		rrset_to_be_create.ttl = rrset.ttl
		rrset_to_be_create.rdclass = rrset.rdclass
		for rdata in rrset:
			rrset_to_be_create.add(rdata)
		return r
	return gen_servfail(zone, query)

def gen_refused(query):
	r = dns.message.make_response(query, our_payload=4096)
	r.set_rcode(dns.rcode.REFUSED)
	r.flags &= ~dns.flags.RD
	return r

def gen_servfail(query):
	r = dns.message.make_response(query, our_payload=4096)
	r.set_rcode(dns.rcode.SERVFAIL)
	r.flags &= ~dns.flags.RD
	return r

class server:
	def __init__(self, views, port=53):
		self.views = views
		self.port = port
		self.socket = []
		s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		s.bind(("", self.port))
		self.socket.append(s)
		s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
		try:
			s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
		except:
			traceback.print_exc()
		s.bind(("", self.port))
		self.socket.append(s)
	def run(self):
		while True:
			s = select.select(self.socket, [], [])
			for t in s[0]:
				self._process(t)

	def _process(self, sock):
		try:
			msg, addr = sock.recvfrom(4096)
			query = dns.message.from_wire(msg)
			self._check(query)
			target_zone = None
			target_view = None
			zones = None
			qname = query.question[0].name
			rtype = query.question[0].rdtype
			rclass = query.question[0].rdclass
			logging.info("incoming query: %s %s %s %s", addr, qname,
				dns.rdataclass.to_text(rclass), dns.rdatatype.to_text(rtype))

			for edns in query.options:
				if edns.otype == 65230:
					target_zone, counter = dns.name.from_wire(edns.data,0)
					logging.info("EDNS OPT Target ZONE %s", target_zone.to_text())
				elif edns.otype == 65231:
					target_view, counter = dns.name.from_wire(edns.data,0)
					logging.info("EDNS OPT Target Host %s", target_view.to_text())
				else:
					logging.info("EDNS OPT %d %s", edns.otype, binascii.hexlify(edns.data))
					

			if target_view:
				zones = self.views.get(target_view)
			if not zones:
				zones = self.views.get(dns.name.from_text('.'))
				if target_view:
					logging.info("NOT found target host %s, using default host", target_view)
			else:
				logging.info("found target host %s", target_view)
			z = None
			if target_zone:
				z = zones.get(target_zone)
			if not z:
				if target_zone:
					logging.info("NOT found target zone %s, using default zone selection algorithm", target_zone)
				try:
					key, z = zones.get_deepest_match(qname)
				except:
					pass
			else:
				logging.info("found target zone %s", target_zone)
			if not z:
				r = gen_refused(query)
			else:
				r = z.reply(query)
			logging.debug("replying msg:\n%s", r)
			sock.sendto(r.to_wire(), addr)
		except:
			traceback.print_exc()

	def _check(self, query):
		pass

def run():
	import configparser
	config = configparser.ConfigParser()
	config.read(sys.argv[1])
	port = 53
	view = dns.namedict.NameDict()
	logging.basicConfig(level=logging.INFO,
		format =  '%(asctime)s : %(levelname)s : %(message)s')

	for section in config.sections():
		if section == 'global':
			p = config[section].getint('port')
			if p:
				port = p 
			logfile = config[section].get('logfile')
			if logfile:
				logging.basicConfig(level=logging.INFO,
					filename = logfile,
					format =  '%(asctime)s : %(levelname)s : %(message)s')
		else:
			if section == 'default':
				viewname = dns.name.from_text('.')
			else:
				viewname = dns.name.from_text(section)
			view[viewname] = dns.namedict.NameDict()
			for z in config[section]:
				view[viewname][dns.name.from_text(z)] = zone(z, config[section][z])
				if viewname.to_text() == '.':
					hostname = '(default)'
				else:
					hostname = viewname
				logging.info("loaded: hostname %s, zone %s", hostname, z)

	s = server(view, port)
	s.run()

if __name__ == "__main__":
	run()


