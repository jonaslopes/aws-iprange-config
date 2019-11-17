# -*- coding: utf-8 -*-

# 
# The AWS IP Range for Security Group program 
# implements the creation of a Security Group in a VPC  
# and adds IPs from a region using the official 
# Amazon link or file 
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
REGION_NAME = '' 
ACTION = '' 
VPC_ID = '' 
SECURITY_GROUP_NAME = '' 
DESCRIPTION = '' 

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


	# GET REGION NAME
	if '--region-name' not in sys.argv:
		print "No Region Name found. The Default Region will be set (sa-east-1)."
		REGION_NAME = 'sa-east-1'
	else:
		idx_argv_region_name = sys.argv.index('--region-name') + 1
		REGION_NAME = sys.argv[idx_argv_region_name]

	print

	# GET AWS IP RAGE 
	url_ip_ranges = 'https://ip-ranges.amazonaws.com/ip-ranges.json'
	file_ip_ranges = 'ip-ranges.json'
	jdata = json.loads( open(file_ip_ranges).read() )

	service_ports = [80, 443]
	ip_protocol = 'tcp'
	ip_permissions = []
	ip_permissions_group = []

	# Control do Add a maximun of 60 IPs
	idx = 1
	for c in jdata['prefixes']:
		if c.get('region') == 'sa-east-1':
			for p in service_ports:
				ip_permissions.append({	
					'IpProtocol': ip_protocol,
					'FromPort': p,
					'ToPort': p,
					'IpRanges': [{'CidrIp': c.get('ip_prefix')}]
				})

				idx += 1
				if idx > 60:
					ip_permissions_group.append(ip_permissions)
					ip_permissions = []
					idx = 1
	# Add last IPs
	if len(ip_permissions) > 0:
		ip_permissions_group.append(ip_permissions)
		ip_permissions = []

	# Ec2 connection to get Security Group
	ec2 = boto3.client(
		'ec2',
		region_name=REGION_NAME,
		aws_access_key_id=AWS_ACCESS_KEY_ID,
		aws_secret_access_key=AWS_SECRET_ACCESS_KEY
	)

	# Get VPCs
	response = ec2.describe_vpcs()
	vpc_arr = response.get('Vpcs', [{}]) # vpc_id = response.get('Vpcs', [{}])[0].get('VpcId', '')

	# GET VPC ID
	print "There are the following VPCs in your region:"
	vpc_dic = {}
	idx = 0
	for vpc in vpc_arr:
		idx += 1
		vpc_dic[idx] = vpc.get('VpcId')
		print "[%i] %s" % (idx, vpc.get('VpcId'))

	print 
	vpc_number = 0
	while vpc_number < 1 or vpc_number > idx:
		vpc_number = int(input("Please enter VPC number [1...%i]: " % idx))

	VPC_ID = vpc_dic[vpc_number]

	print "VPC %s selected!" % vpc_dic[vpc_number]
	print

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

	SECURITY_GROUP_NAME = raw_input("Please enter Security Group Name to add IPs [seg-new]: ")
	if len(SECURITY_GROUP_NAME) <= 0:
		SECURITY_GROUP_NAME = 'seg-new'

	print 

	DESCRIPTION = raw_input("Please enter Security Group Description to add IPs [New Security Group]: ")
	if len(DESCRIPTION) <= 0:
		DESCRIPTION = 'New Security Group'

	print
	print "Region Name: %s" % REGION_NAME
	print "Action: %s" % ACTION
	print "VPC ID %s" % VPC_ID
	print "Security Group Name: %s" % SECURITY_GROUP_NAME
	print "Security Group Description: %s" % DESCRIPTION 
	print 

	continue_run = raw_input("Continue running the program? [Y or N] ")
	if continue_run.lower() != 'y':
		print
		print 'Bye!'
		print
		exit(0)

	print
	print "Creating Security Group %s on VPC %s by performing %s action on region %s" % (SECURITY_GROUP_NAME, VPC_ID, ACTION, REGION_NAME)
	print

	for vpc in vpc_arr:
		if vpc.get('VpcId') == VPC_ID:
			id_group = 0
			for ippg in ip_permissions_group:
				id_group += 1
				
				print str(len(ippg)) + "IPs will be added to the group named " + SECURITY_GROUP_NAME+'-'+ str(id_group).zfill(3)

				# Create new security group
				response = ec2.create_security_group( 
					GroupName=SECURITY_GROUP_NAME+'-'+ str(id_group).zfill(3),
					Description=DESCRIPTION,
					VpcId=VPC_ID
				)
				security_group_id = response['GroupId']
				print('Security Group Created %s in vpc %s.' % (security_group_id, VPC_ID))

				# Add new ingress rule
				ips = []
				for ipp in ippg:
					for p in service_ports:
						IpRangesAndPort = ipp['IpRanges'][0]['CidrIp']+'-'+str(p) # Replication control
						if IpRangesAndPort not in ips:
							# Add IP to Rule
							data = ec2.authorize_security_group_ingress(
								GroupId=security_group_id,
								IpPermissions=[{	
									'IpProtocol': ip_protocol,
									'FromPort': p,
									'ToPort': p,
									'IpRanges': ipp['IpRanges']
								}]
							)
							ips.append( ipp['IpRanges'][0]['CidrIp']+'-'+str(p) ) # Replication control

			print('Ingress Successfully Set %s' % data)
except ClientError as e:
	print(e)

print
print "Done!"
print