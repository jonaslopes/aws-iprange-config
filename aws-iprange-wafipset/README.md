# JON Toolkit - AWS IP Range for WAF IPSet

The AWS IP Range for WAF IPSet program implements adding an IP list to a WAF rule using the official Amazon link (https://ip-ranges.amazonaws.com/ip-ranges.json).

#### Parameters:

 - **--credential-file:** AWS credential file name.
 - **--ipset-id:** IPSet ID where IPs will be added.
 - **--action:** Action that will be executed.
 
#### Call example:

```
python jontk-aws-iprange-wafipset.py --credential-file ./credential --ipset-id 0101c001-0101-01b1-a01c-q1w2e3r4t5
```