| Title                | DPAPI Domain Master Key Backup Attempt                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects anyone attempting a backup for the DPAPI Master Key. This events gets generated at the source and not the Domain Controller.                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0006: Credential Access](https://attack.mitre.org/tactics/TA0006)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1003: Credential Dumping](https://attack.mitre.org/techniques/T1003)</li></ul>  |
| Data Needed          |  There is no documented Data Needed for this Detection Rule yet  |
| Trigger              | <ul><li>[T1003: Credential Dumping](../Triggers/T1003.md)</li></ul>  |
| Severity Level       | critical |
| False Positives      | <ul><li>Unknown</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[https://github.com/Cyb3rWard0g/ThreatHunter-Playbook/tree/master/playbooks/windows/06_credential_access/T1003_credential_dumping/domain_dpapi_backupkey_extraction.md](https://github.com/Cyb3rWard0g/ThreatHunter-Playbook/tree/master/playbooks/windows/06_credential_access/T1003_credential_dumping/domain_dpapi_backupkey_extraction.md)</li></ul>  |
| Author               | Roberto Rodriguez @Cyb3rWard0g |


## Detection Rules

### Sigma rule

```
title: DPAPI Domain Master Key Backup Attempt
id: 39a94fd1-8c9a-4ff6-bf22-c058762f8014
description: Detects anyone attempting a backup for the DPAPI Master Key. This events gets generated at the source and not the Domain Controller.
status: experimental
date: 2019/08/10
author: Roberto Rodriguez @Cyb3rWard0g
references:
    - https://github.com/Cyb3rWard0g/ThreatHunter-Playbook/tree/master/playbooks/windows/06_credential_access/T1003_credential_dumping/domain_dpapi_backupkey_extraction.md
tags:
    - attack.credential_access
    - attack.t1003
logsource:
    product: windows
    service: security
detection:
    selection: 
        EventID: 4692
    condition: selection
fields:
    - ComputerName
    - SubjectDomainName
    - SubjectUserName
falsepositives:
    - Unknown
level: critical

```





### es-qs
    
```
EventID:"4692"
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/39a94fd1-8c9a-4ff6-bf22-c058762f8014 <<EOF\n{\n  "metadata": {\n    "title": "DPAPI Domain Master Key Backup Attempt",\n    "description": "Detects anyone attempting a backup for the DPAPI Master Key. This events gets generated at the source and not the Domain Controller.",\n    "tags": [\n      "attack.credential_access",\n      "attack.t1003"\n    ],\n    "query": "EventID:\\"4692\\""\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "EventID:\\"4692\\"",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'DPAPI Domain Master Key Backup Attempt\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}Hit on {{_source.@timestamp}}:\\n     ComputerName = {{_source.ComputerName}}\\nSubjectDomainName = {{_source.SubjectDomainName}}\\n  SubjectUserName = {{_source.SubjectUserName}}================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
EventID:"4692"
```


### splunk
    
```
EventID="4692" | table ComputerName,SubjectDomainName,SubjectUserName
```


### logpoint
    
```
(event_source="Microsoft-Windows-Security-Auditing" event_id="4692")
```


### grep
    
```
grep -P '^4692'
```



