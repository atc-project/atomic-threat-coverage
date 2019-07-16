| Title                | Disabling Windows Event Auditing                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects scenarios where system auditing (ie: windows event log auditing) is disabled. This may be used in a scenario where an entity would want to bypass local logging to evade detection when windows event logging is enabled and reviewed. Also, it is recommended to turn off "Local Group Policy Object Processing" via GPO, which will make sure that Active Directory GPOs take precedence over local/edited computer policies via something such as "gpedit.msc". Please note, that disabling "Local Group Policy Object Processing" may cause an issue in scenarios of one off specific GPO modifications -- however it is recommended to perform these modifications in Active Directory anyways.                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1054: Indicator Blocking](https://attack.mitre.org/techniques/T1054)</li></ul>  |
| Data Needed          | <ul><li>[DN_0067_4719_system_audit_policy_was_changed](../Data_Needed/DN_0067_4719_system_audit_policy_was_changed.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1054: Indicator Blocking](../Triggers/T1054.md)</li></ul>  |
| Severity Level       | high |
| False Positives      | <ul><li>Unknown</li></ul>  |
| Development Status   |  Development Status wasn't defined for this Detection Rule yet  |
| References           | <ul><li>[https://bit.ly/WinLogsZero2Hero](https://bit.ly/WinLogsZero2Hero)</li></ul>  |
| Author               | @neu5ron |


## Detection Rules

### Sigma rule

```
title: Disabling Windows Event Auditing
description: 'Detects scenarios where system auditing (ie: windows event log auditing) is disabled. This may be used in a scenario
    where an entity would want to bypass local logging to evade detection when windows event logging is enabled and
    reviewed. Also, it is recommended to turn off "Local Group Policy Object Processing" via GPO, which will make sure
    that Active Directory GPOs take precedence over local/edited computer policies via something such as "gpedit.msc".
    Please note, that disabling "Local Group Policy Object Processing" may cause an issue in scenarios of one off
    specific GPO modifications -- however it is recommended to perform these modifications in Active Directory anyways.'
references:
    - https://bit.ly/WinLogsZero2Hero
tags:
    - attack.defense_evasion
    - attack.t1054
author: '@neu5ron'
logsource:
    product: windows
    service: security
    definition: 'Requirements: Audit Policy : Computer Management > Audit Policy Configuration, Group Policy : Computer Configuration\Windows Settings\Security Settings\Advanced Audit Policy Configuration\Audit Policies\Policy Change\Audit Authorization Policy Change'
detection:
    selection:
        EventID: 4719
        AuditPolicyChanges: 'removed'
    condition: selection
falsepositives: 
    - Unknown
level: high

```





### es-qs
    
```
(EventID:"4719" AND AuditPolicyChanges:"removed")
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/Disabling-Windows-Event-Auditing <<EOF\n{\n  "metadata": {\n    "title": "Disabling Windows Event Auditing",\n    "description": "Detects scenarios where system auditing (ie: windows event log auditing) is disabled. This may be used in a scenario where an entity would want to bypass local logging to evade detection when windows event logging is enabled and reviewed. Also, it is recommended to turn off \\"Local Group Policy Object Processing\\" via GPO, which will make sure that Active Directory GPOs take precedence over local/edited computer policies via something such as \\"gpedit.msc\\". Please note, that disabling \\"Local Group Policy Object Processing\\" may cause an issue in scenarios of one off specific GPO modifications -- however it is recommended to perform these modifications in Active Directory anyways.",\n    "tags": [\n      "attack.defense_evasion",\n      "attack.t1054"\n    ],\n    "query": "(EventID:\\"4719\\" AND AuditPolicyChanges:\\"removed\\")"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "(EventID:\\"4719\\" AND AuditPolicyChanges:\\"removed\\")",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Disabling Windows Event Auditing\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
(EventID:"4719" AND AuditPolicyChanges:"removed")
```


### splunk
    
```
(EventID="4719" AuditPolicyChanges="removed")
```


### logpoint
    
```
(EventID="4719" AuditPolicyChanges="removed")
```


### grep
    
```
grep -P '^(?:.*(?=.*4719)(?=.*removed))'
```



