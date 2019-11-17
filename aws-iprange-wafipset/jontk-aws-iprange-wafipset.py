# -*- coding: utf-8 -*-

# 
# The AWS IP Range for WAF IPSet program 
# implements adding an IP list to a WAF rule using the 
# official Amazon link 
# (https://ip-ranges.amazonaws.com/ip-ranges.json) 
# 
# Sometimes you will need to perform performance tests 
# such as BlazeMeter. In such cases, you will need to 
# create temporary firewall or WAF rules with the Amazon 
# IP range. With this program, this setup will be done 
# in minutes.
# 
# https://git.rnp.br/gsc-projetos/rnp-toolkit/aws/rnptk_config_aws_whitelist_ips_sg.git
#
# @author  Jonas Lopes
# @version 1.0
# @since   2019-11-11
# 
# Copyright 2019 Jonas Lopes 
# http://www.apache.org/licenses/LICENSE-2.0
# 

import boto3
import json
import sys
import getpass
import ConfigParser
from array import *
from botocore.exceptions import ClientError

AWS_ACCESS_KEY_ID = ''
AWS_SECRET_ACCESS_KEY = ''
ACTION = '' 
IP_SET_ID = ''

print 

try:
	# GET AWS CREDENCIAL
	if '--credential-file' not in sys.argv:
		AWS_ACCESS_KEY_ID = getpass.getpass(prompt='Please, enter your AWS Access Key ID: ')
		AWS_SECRET_ACCESS_KEY = getpass.getpass(prompt='Please, enter your AWS Secret Key: ')
	else:
		credential = ConfigParser.ConfigParser()
		idx_argv_credential_path = sys.argv.index('--credential-file') + 1
		credential.read(sys.argv[idx_argv_credential_path])

		print "There are the following sessions in your credentials file:"
		section_dic = {}
		idx = 0
		sections = credential.sections()
		for section in sections:
			idx += 1
			section_dic[idx] = section
			print "[%i] %s" % (idx, section)
		
		print
		
		session_number = 0
		while session_number < 1 or session_number > idx:
			session_number = int(input("Please enter Session number [1...%i]: " % idx))

		print "Session %s selected!" % section_dic[session_number]
		print

		AWS_ACCESS_KEY_ID = credential.get(section_dic[session_number], "AWS_ACCESS_KEY_ID")
		AWS_SECRET_ACCESS_KEY = credential.get(section_dic[session_number], "AWS_SECRET_ACCESS_KEY")

	# GET ACTION
	if '--action' not in sys.argv:
		print "No Action found. The Default Action will be set (INSERT)."
		ACTION = 'INSERT'
	else:
		idx_argv_action = sys.argv.index('--action') + 1
		if sys.argv[idx_argv_action] == 'INSERT' or sys.argv[idx_argv_action] == 'DELETE':
			ACTION = sys.argv[idx_argv_action]
		else:
			print "Unknow Action. the application will be terminated!"
			exit(0)
	print 

	# AWS Connection
	client = boto3.client(
		'waf',
		aws_access_key_id=AWS_ACCESS_KEY_ID,
		aws_secret_access_key=AWS_SECRET_ACCESS_KEY
	)

	# GET IPSET ID
	if '--ipset-id' not in sys.argv:
		print "No IPSET ID found!"

		ipset_response = client.list_ip_sets(
			Limit=100
		)
		ipset_arr = ipset_response.get('IPSets', [{}]) # vpc_id = response.get('Vpcs', [{}])[0].get('VpcId', '')

		print "There are the following VPCs in your region:"
		ipset_dic = {}
		idx = 0
		for ipset in ipset_arr:
			idx += 1
			ipset_dic[idx] = [ipset.get('IPSetId'), ipset.get('Name')]
			print "[%i] ID: %s | NAME: %s" % (idx, ipset.get('IPSetId'), ipset.get('Name'))

		print 
		ipset_number = -1
		while ipset_number < 0 or ipset_number > idx:
			ipset_number = int(input("Please enter IPSet number or 0 (zero) for new [1...%i or 0]: " % idx))

		if ipset_number > 0:
			print "IPSet %s (%s) selected!" % (ipset_dic[ipset_number][1], ipset_dic[ipset_number][0])
			IP_SET_ID = ipset_dic[ipset_number][0]
		else:
			new_ipset_name = raw_input("Please enter new IPSet Name [jontk-aws-ipset-new]: ")
			if len(new_ipset_name) <= 0:
				new_ipset_name = 'jontk-aws-ipset-new'

			print "An IPSet will be created named %s..." % new_ipset_name

			res_token = client.get_change_token()

			new_ipset_response = client.create_ip_set(
				Name=new_ipset_name,
				ChangeToken=res_token['ChangeToken'],
			)

			IP_SET_ID = new_ipset_response['IPSet']['IPSetId']
			print("IPSet Created %s (%s)." % (new_ipset_response['IPSet']['Name'], IP_SET_ID))

		print

	else:
		idx_argv_ipset_id = sys.argv.index('--ipset-id') + 1
		IP_SET_ID = sys.argv[idx_argv_ipset_id]

	print
	print "Action: %s" % ACTION
	print "IPSET ID: %s" % IP_SET_ID
	print 

	continue_run = raw_input("Continue running the program? [Y or N] ")
	if continue_run.lower() != 'y':
		print
		print 'Bye!'
		print
		exit(0)

	print
	print "Configuring IPs on IPSET %s by performing %s action" % (IP_SET_ID, ACTION)
	print

	jdata = json.loads( open('ip-ranges.json').read() )

	for c in jdata['prefixes']:
		if c.get('region') == 'sa-east-1':

			res_token = client.get_change_token()
			
			# Add ip_set
			print "Executing ip_set  => {\"Action\": \"%s\", \"IPSetDescriptor\": {\"Value\": \"%s\", \"Type\": \"IPV4\"}}" % (ACTION, c.get('ip_prefix', 'No Value'))
			
			res_update_ip_set = client.update_ip_set(
				IPSetId=IP_SET_ID,
				ChangeToken=res_token['ChangeToken'],
				Updates=[
					{
						'Action': ACTION,
						'IPSetDescriptor': {
							'Type': 'IPV4',
							'Value': c.get('ip_prefix')
						}
					},
				]
			)
except ClientError as e:
	print(e)

print
print "Done!"
