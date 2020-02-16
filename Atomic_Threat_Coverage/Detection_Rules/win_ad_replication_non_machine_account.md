| Title                | T1003 Active Directory Replication from Non Machine Account                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects potential abuse of Active Directory Replication Service (ADRS) from a non machine account to request credentials.                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0006: Credential Access](https://attack.mitre.org/tactics/TA0006)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1003: Credential Dumping](https://attack.mitre.org/techniques/T1003)</li></ul>  |
| Data Needed          | <ul><li>[DN_0030_4662_operation_was_performed_on_an_object](../Data_Needed/DN_0030_4662_operation_was_performed_on_an_object.md)</li></ul>  |
| Trigger              | <ul><li>[T1003: Credential Dumping](../Triggers/T1003.md)</li></ul>  |
| Severity Level       | critical |
| False Positives      | <ul><li>Unknown</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[https://github.com/Cyb3rWard0g/ThreatHunter-Playbook/tree/master/playbooks/windows/06_credential_access/T1003_credential_dumping/ad_replication_non_machine_account.md](https://github.com/Cyb3rWard0g/ThreatHunter-Playbook/tree/master/playbooks/windows/06_credential_access/T1003_credential_dumping/ad_replication_non_machine_account.md)</li></ul>  |
| Author               | Roberto Rodriguez @Cyb3rWard0g |


## Detection Rules

### Sigma rule

```
title: T1003 Active Directory Replication from Non Machine Account
id: 17d619c1-e020-4347-957e-1d1207455c93
description: Detects potential abuse of Active Directory Replication Service (ADRS) from a non machine account to request credentials.
status: experimental
date: 2019/07/26
modified: 2019/11/10
author: Roberto Rodriguez @Cyb3rWard0g
references:
    - https://github.com/Cyb3rWard0g/ThreatHunter-Playbook/tree/master/playbooks/windows/06_credential_access/T1003_credential_dumping/ad_replication_non_machine_account.md
tags:
    - attack.credential_access
    - attack.t1003
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4662
        AccessMask: '0x100'
        Properties|contains:
            - '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2'
            - '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2'
            - '89e95b76-444d-4c62-991a-0facbeda640c'
    filter:
        SubjectUserName|endswith: '$'
    condition: selection and not filter
falsepositives:
    - Unknown
level: critical
```





### es-qs
    
```
((EventID:"4662" AND AccessMask:"0x100" AND Properties.keyword:(*1131f6aa\\-9c07\\-11d1\\-f79f\\-00c04fc2dcd2* OR *1131f6ad\\-9c07\\-11d1\\-f79f\\-00c04fc2dcd2* OR *89e95b76\\-444d\\-4c62\\-991a\\-0facbeda640c*)) AND (NOT (SubjectUserName.keyword:*$)))
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/T1003-Active-Directory-Replication-from-Non-Machine-Account <<EOF\n{\n  "metadata": {\n    "title": "T1003 Active Directory Replication from Non Machine Account",\n    "description": "Detects potential abuse of Active Directory Replication Service (ADRS) from a non machine account to request credentials.",\n    "tags": [\n      "attack.credential_access",\n      "attack.t1003"\n    ],\n    "query": "((EventID:\\"4662\\" AND AccessMask:\\"0x100\\" AND Properties.keyword:(*1131f6aa\\\\-9c07\\\\-11d1\\\\-f79f\\\\-00c04fc2dcd2* OR *1131f6ad\\\\-9c07\\\\-11d1\\\\-f79f\\\\-00c04fc2dcd2* OR *89e95b76\\\\-444d\\\\-4c62\\\\-991a\\\\-0facbeda640c*)) AND (NOT (SubjectUserName.keyword:*$)))"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "((EventID:\\"4662\\" AND AccessMask:\\"0x100\\" AND Properties.keyword:(*1131f6aa\\\\-9c07\\\\-11d1\\\\-f79f\\\\-00c04fc2dcd2* OR *1131f6ad\\\\-9c07\\\\-11d1\\\\-f79f\\\\-00c04fc2dcd2* OR *89e95b76\\\\-444d\\\\-4c62\\\\-991a\\\\-0facbeda640c*)) AND (NOT (SubjectUserName.keyword:*$)))",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'T1003 Active Directory Replication from Non Machine Account\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
((EventID:"4662" AND AccessMask:"0x100" AND Properties.keyword:(*1131f6aa\\-9c07\\-11d1\\-f79f\\-00c04fc2dcd2* *1131f6ad\\-9c07\\-11d1\\-f79f\\-00c04fc2dcd2* *89e95b76\\-444d\\-4c62\\-991a\\-0facbeda640c*)) AND (NOT (SubjectUserName.keyword:*$)))
```


### splunk
    
```
((EventID="4662" AccessMask="0x100" (Properties="*1131f6aa-9c07-11d1-f79f-00c04fc2dcd2*" OR Properties="*1131f6ad-9c07-11d1-f79f-00c04fc2dcd2*" OR Properties="*89e95b76-444d-4c62-991a-0facbeda640c*")) NOT (SubjectUserName="*$"))
```


### logpoint
    
```
(event_source="Microsoft-Windows-Security-Auditing" (event_id="4662" AccessMask="0x100" Properties IN ["*1131f6aa-9c07-11d1-f79f-00c04fc2dcd2*", "*1131f6ad-9c07-11d1-f79f-00c04fc2dcd2*", "*89e95b76-444d-4c62-991a-0facbeda640c*"])  -(SubjectUserName="*$"))
```


### grep
    
```
grep -P '^(?:.*(?=.*(?:.*(?=.*4662)(?=.*0x100)(?=.*(?:.*.*1131f6aa-9c07-11d1-f79f-00c04fc2dcd2.*|.*.*1131f6ad-9c07-11d1-f79f-00c04fc2dcd2.*|.*.*89e95b76-444d-4c62-991a-0facbeda640c.*))))(?=.*(?!.*(?:.*(?=.*.*\\$)))))'
```



