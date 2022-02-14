import boto3
import json
import re


class IAMRoleDetector:

	def __init__(self, trusted_accounts=None, trusted_orgs=None):
		#TODO: Add support for org ids and lists of accounts
		self.account = boto3.client('sts').get_caller_identity().get('Account')


	def detect_untrusted_access(self):
		client = boto3.client('iam')
		response = client.list_roles()
		roles = response['Roles']
		results = []

		for role in roles:
			principal = ''
			policy = role['AssumeRolePolicyDocument']
			untrusted_principals= []

			for statement in policy['Statement']:
				try:
					self._collect_untrusted_principals(json.dumps(statement['Principal']['AWS']), untrusted_principals)
				except KeyError as e:
					continue

			if untrusted_principals:
				result_obj = {
					'role_name': role['RoleName'],
					'arn': role['Arn'],
					'untrusted_principals': untrusted_principals
				}
				results.append(result_obj)

		return results


	def _collect_untrusted_principals(self, principal_obj, untrusted_principals):
		principal_obj = json.loads(principal_obj)

		if isinstance(principal_obj, list):
			for principal in principal_obj:
				if self.account not in str(principal) and str(principal) not in untrusted_principals:
					untrusted_principals.append(principal)
		elif self.account not in str(principal_obj) and str(principal_obj) not in untrusted_principals:
			untrusted_principals.append(principal_obj)



