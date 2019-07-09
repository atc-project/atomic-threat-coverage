| Title                | Password Change on Directory Service Restore Mode (DSRM) Account                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | The Directory Service Restore Mode (DSRM) account is a local administrator account on Domain Controllers. Attackers may change the password to gain persistence.                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0003: Persistence](https://attack.mitre.org/tactics/TA0003)</li><li>[TA0004: Privilege Escalation](https://attack.mitre.org/tactics/TA0004)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1098: Account Manipulation](https://attack.mitre.org/techniques/T1098)</li></ul>  |
| Data Needed          | <ul><li>[DN_0028_4794_directory_services_restore_mode_admin_password_set](../Data_Needed/DN_0028_4794_directory_services_restore_mode_admin_password_set.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1098: Account Manipulation](../Triggers/T1098.md)</li></ul>  |
| Severity Level       | high |
| False Positives      | <ul><li>Initial installation of a domain controller</li></ul>  |
| Development Status   | stable |
| References           | <ul><li>[https://adsecurity.org/?p=1714](https://adsecurity.org/?p=1714)</li></ul>  |
| Author               | Thomas Patzke |


## Detection Rules

### Sigma rule

```
title: Password Change on Directory Service Restore Mode (DSRM) Account
status: stable
description: The Directory Service Restore Mode (DSRM) account is a local administrator account on Domain Controllers. Attackers may change the password to gain persistence.
references:
    - https://adsecurity.org/?p=1714
author: Thomas Patzke
tags:
    - attack.persistence
    - attack.privilege_escalation
    - attack.t1098
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4794
    condition: selection
falsepositives:
    - Initial installation of a domain controller
level: high

```





### es-qs
    
```
EventID:"4794"
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/Password-Change-on-Directory-Service-Restore-Mode-DSRM-Account <<EOF\n{\n  "metadata": {\n    "title": "Password Change on Directory Service Restore Mode (DSRM) Account",\n    "description": "The Directory Service Restore Mode (DSRM) account is a local administrator account on Domain Controllers. Attackers may change the password to gain persistence.",\n    "tags": [\n      "attack.persistence",\n      "attack.privilege_escalation",\n      "attack.t1098"\n    ],\n    "query": "EventID:\\"4794\\""\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "EventID:\\"4794\\"",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Password Change on Directory Service Restore Mode (DSRM) Account\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
EventID:"4794"
```


### splunk
    
```
EventID="4794"
```


### logpoint
    
```
EventID="4794"
```


### grep
    
```
grep -P '^4794'
```



