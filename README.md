# untrusted-access-detector

Detecting untrusted access to AWS resources in your account. 

It only supports IAM Roles, but I'd like to add detectors for other resources in the future. It defaults to trusting the account of the AWS credentials you have configured in your environment. It also defaults to trusting any AWS managed service principals. 

In the future, I'd like to add detectors for additional resource types and support for providing a list of trusted Organization Ids or a list of trusted accounts.

It has a CLI. See the example below. 

```
$ python3 untrusted_access_detector.py --resource iamrole

Looking for untrusted access granted to IAM Roles in 012345678912.

Found 2 IAM Roles that grant access to principals in untrusted accounts!
[
    {
        "arn": "arn:aws:iam::012345678912:role/CloudBerry",
        "role_name": "privilegedaccessrole",
        "untrusted_principals": [
            "arn:aws:iam::555555555555:root",
            "arn:aws:iam::222222222222:root",
            "*"
        ]
    },
    {
        "arn": "arn:aws:iam::012345678912:role/cross-account-test-role",
        "role_name": "cross-account-test-role",
        "untrusted_principals": [
            "arn:aws:iam::333333333333:root"
        ]
    }
]
```

The IAMRoleDetector inspected the assume role policy of the IAM Roles in 012345678912 to see if any untrusted principals were granted access. It found two roles that grant access to untrusted principals, including one that granted access to '*' (that means any authenticated principal can assume it!).
