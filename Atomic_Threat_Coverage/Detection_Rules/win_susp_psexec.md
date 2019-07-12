| Title                | Suspicious PsExec execution                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | detects execution of psexec or paexec with renamed service name, this rule helps to filter out the noise if psexec is used for legit purposes or if attacker uses a different psexec client other than sysinternal one                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0008: Lateral Movement](https://attack.mitre.org/tactics/TA0008)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1077: Windows Admin Shares](https://attack.mitre.org/techniques/T1077)</li></ul>  |
| Data Needed          | <ul><li>[DN_0032_5145_network_share_object_was_accessed_detailed](../Data_Needed/DN_0032_5145_network_share_object_was_accessed_detailed.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1077: Windows Admin Shares](../Triggers/T1077.md)</li></ul>  |
| Severity Level       | high |
| False Positives      | <ul><li>nothing observed so far</li></ul>  |
| Development Status   |  Development Status wasn't defined for this Detection Rule yet  |
| References           | <ul><li>[https://blog.menasec.net/2019/02/threat-hunting-3-detecting-psexec.html](https://blog.menasec.net/2019/02/threat-hunting-3-detecting-psexec.html)</li></ul>  |
| Author               | Samir Bousseaden |


## Detection Rules

### Sigma rule

```
title: Suspicious PsExec execution
description: detects execution of psexec or paexec with renamed service name, this rule helps to filter out the noise if psexec is used for legit purposes or if attacker uses a different psexec client other than sysinternal one
author: Samir Bousseaden
references:
    - https://blog.menasec.net/2019/02/threat-hunting-3-detecting-psexec.html
tags:
    - attack.lateral_movement
    - attack.t1077
logsource:
    product: windows
    service: security
    description: 'The advanced audit policy setting "Object Access > Audit Detailed File Share" must be configured for Success/Failure'
detection:
    selection1:
        EventID: 5145
        ShareName: \\*\IPC$
        RelativeTargetName:
         - '*-stdin'
         - '*-stdout'
         - '*-stderr'
    selection2:
        EventID: 5145
        ShareName: \\*\IPC$
        RelativeTargetName: 'PSEXESVC*'
    condition: selection1 and not selection2
falsepositives: 
    - nothing observed so far
level: high

```





### es-qs
    
```
((EventID:"5145" AND ShareName:"\\\\*\\\\IPC$" AND RelativeTargetName.keyword:(*\\-stdin *\\-stdout *\\-stderr)) AND (NOT (EventID:"5145" AND ShareName:"\\\\*\\\\IPC$" AND RelativeTargetName.keyword:PSEXESVC*)))
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/Suspicious-PsExec-execution <<EOF\n{\n  "metadata": {\n    "title": "Suspicious PsExec execution",\n    "description": "detects execution of psexec or paexec with renamed service name, this rule helps to filter out the noise if psexec is used for legit purposes or if attacker uses a different psexec client other than sysinternal one",\n    "tags": [\n      "attack.lateral_movement",\n      "attack.t1077"\n    ],\n    "query": "((EventID:\\"5145\\" AND ShareName:\\"\\\\\\\\*\\\\\\\\IPC$\\" AND RelativeTargetName.keyword:(*\\\\-stdin *\\\\-stdout *\\\\-stderr)) AND (NOT (EventID:\\"5145\\" AND ShareName:\\"\\\\\\\\*\\\\\\\\IPC$\\" AND RelativeTargetName.keyword:PSEXESVC*)))"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "((EventID:\\"5145\\" AND ShareName:\\"\\\\\\\\*\\\\\\\\IPC$\\" AND RelativeTargetName.keyword:(*\\\\-stdin *\\\\-stdout *\\\\-stderr)) AND (NOT (EventID:\\"5145\\" AND ShareName:\\"\\\\\\\\*\\\\\\\\IPC$\\" AND RelativeTargetName.keyword:PSEXESVC*)))",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Suspicious PsExec execution\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
((EventID:"5145" AND ShareName:"\\\\*\\\\IPC$" AND RelativeTargetName:("*\\-stdin" "*\\-stdout" "*\\-stderr")) AND NOT (EventID:"5145" AND ShareName:"\\\\*\\\\IPC$" AND RelativeTargetName:"PSEXESVC*"))
```


### splunk
    
```
((EventID="5145" ShareName="\\\\*\\\\IPC$" (RelativeTargetName="*-stdin" OR RelativeTargetName="*-stdout" OR RelativeTargetName="*-stderr")) NOT (EventID="5145" ShareName="\\\\*\\\\IPC$" RelativeTargetName="PSEXESVC*"))
```


### logpoint
    
```
((EventID="5145" ShareName="\\\\*\\\\IPC$" RelativeTargetName IN ["*-stdin", "*-stdout", "*-stderr"])  -(EventID="5145" ShareName="\\\\*\\\\IPC$" RelativeTargetName="PSEXESVC*"))
```


### grep
    
```
grep -P '^(?:.*(?=.*(?:.*(?=.*5145)(?=.*\\\\.*\\IPC\\$)(?=.*(?:.*.*-stdin|.*.*-stdout|.*.*-stderr))))(?=.*(?!.*(?:.*(?=.*5145)(?=.*\\\\.*\\IPC\\$)(?=.*PSEXESVC.*)))))'
```



