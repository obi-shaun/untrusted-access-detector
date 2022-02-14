import argparse
from detectors import IAMRoleDetector
import json

parser = argparse.ArgumentParser(description='detect untrusted access to your AWS account')
parser.add_argument('--resource', type=str, help='AWS resource type. Currently, only the follow types are supported: "iamrole"', required=True)
args = parser.parse_args()

if args.resource == 'iamrole':

	role_detector = IAMRoleDetector()
	print(f'\nLooking for untrusted access granted to IAM Roles in {role_detector.account}.\n')
	results = role_detector.detect_untrusted_access()

	if results:
		print(f'Found {len(results)} IAM Roles that grant access to principals in untrusted accounts!')
		print(json.dumps(results, indent=4, sort_keys=True))
	else:
		print('No IAM Roles with untrusted access found.')