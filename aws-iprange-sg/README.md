# JON Toolkit - AWS IP Range for Security Group

The AWS IP Range for Security Group program implements the creation of a Security Group in a particular VPC and adds IPs from a particular Region using the official Amazon link or file (https://ip-ranges.amazonaws.com/ip-ranges.json).

#### Parameters:

 - **--credential-file:** AWS credential file name.
 - **--vpc-id:** VPC ID where Security Group will be created.
 - **--action:** Action that will be executed.
 - **--region-name:** Region Name where Security Group will be created.
 - **--action:** Action that will be executed.

#### Call example:

```
python jontk-aws-iprange-sg.py --credential-file ./credential --vpc-id vpc-10101010
```