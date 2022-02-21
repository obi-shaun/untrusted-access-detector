import boto3
import json
import re


class IAMRoleDetector:

	def __init__(self):
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

			self._collect_untrusted_principals(policy, untrusted_principals)

			if untrusted_principals:
				result_obj = {
					'arn': role['Arn'],
					'untrusted_principals': untrusted_principals
				}
				results.append(result_obj)

		return results


	def _collect_untrusted_principals(self, policy, untrusted_principals):
		for statement in policy['Statement']:
			if statement['Effect'] == 'Allow':

				try:
					principal_obj = json.loads(json.dumps(statement['Principal']['AWS']))

					if isinstance(principal_obj, list):
						for principal in principal_obj:
							if self.account not in str(principal) and str(principal) not in untrusted_principals:
								untrusted_principals.append(principal)

					elif self.account not in str(principal_obj) and str(principal_obj) not in untrusted_principals:
						untrusted_principals.append(principal_obj)

				except KeyError as e:
					continue
