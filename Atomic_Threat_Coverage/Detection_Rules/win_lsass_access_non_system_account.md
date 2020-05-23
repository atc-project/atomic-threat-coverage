| Title                    | LSASS Access from Non System Account       |
|:-------------------------|:------------------|
| **Description**          | Detects potential mimikatz-like tools accessing LSASS from non system account |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0006: Credential Access](https://attack.mitre.org/tactics/TA0006)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1003: Credential Dumping](https://attack.mitre.org/techniques/T1003)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0058_4656_handle_to_an_object_was_requested](../Data_Needed/DN_0058_4656_handle_to_an_object_was_requested.md)</li><li>[DN_0062_4663_attempt_was_made_to_access_an_object](../Data_Needed/DN_0062_4663_attempt_was_made_to_access_an_object.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1003: Credential Dumping](../Triggers/T1003.md)</li></ul>  |
| **Severity Level**       | critical |
| **False Positives**      | <ul><li>Unknown</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://github.com/Cyb3rWard0g/ThreatHunter-Playbook/tree/master/playbooks/windows/06_credential_access/T1003_credential_dumping/lsass_access_non_system_account.md](https://github.com/Cyb3rWard0g/ThreatHunter-Playbook/tree/master/playbooks/windows/06_credential_access/T1003_credential_dumping/lsass_access_non_system_account.md)</li></ul>  |
| **Author**               | Roberto Rodriguez @Cyb3rWard0g |


## Detection Rules

### Sigma rule

```
title: LSASS Access from Non System Account
id: 962fe167-e48d-4fd6-9974-11e5b9a5d6d1
description: Detects potential mimikatz-like tools accessing LSASS from non system account
status: experimental
date: 2019/06/20
modified: 2019/11/10
author: Roberto Rodriguez @Cyb3rWard0g
references:
    - https://github.com/Cyb3rWard0g/ThreatHunter-Playbook/tree/master/playbooks/windows/06_credential_access/T1003_credential_dumping/lsass_access_non_system_account.md
tags:
    - attack.credential_access
    - attack.t1003
logsource:
    product: windows
    service: security
detection:
    selection: 
        EventID:
            - 4663
            - 4656
        ObjectType: 'Process'
        ObjectName|endswith: '\lsass.exe'
    filter:
        SubjectUserName|endswith: '$'
    condition: selection and not filter
fields:
    - ComputerName
    - ObjectName
    - SubjectUserName
    - ProcessName
falsepositives:
    - Unknown
level: critical

```





### powershell
    
```
Get-WinEvent -LogName Security | where {((($_.ID -eq "4663" -or $_.ID -eq "4656") -and $_.message -match "ObjectType.*Process" -and $_.message -match "ObjectName.*.*\\\\lsass.exe") -and  -not ($_.message -match "SubjectUserName.*.*$")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.channel:"Security" AND (winlog.event_id:("4663" OR "4656") AND winlog.event_data.ObjectType:"Process" AND winlog.event_data.ObjectName.keyword:*\\\\lsass.exe) AND (NOT (winlog.event_data.SubjectUserName.keyword:*$)))
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/962fe167-e48d-4fd6-9974-11e5b9a5d6d1 <<EOF\n{\n  "metadata": {\n    "title": "LSASS Access from Non System Account",\n    "description": "Detects potential mimikatz-like tools accessing LSASS from non system account",\n    "tags": [\n      "attack.credential_access",\n      "attack.t1003"\n    ],\n    "query": "(winlog.channel:\\"Security\\" AND (winlog.event_id:(\\"4663\\" OR \\"4656\\") AND winlog.event_data.ObjectType:\\"Process\\" AND winlog.event_data.ObjectName.keyword:*\\\\\\\\lsass.exe) AND (NOT (winlog.event_data.SubjectUserName.keyword:*$)))"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "(winlog.channel:\\"Security\\" AND (winlog.event_id:(\\"4663\\" OR \\"4656\\") AND winlog.event_data.ObjectType:\\"Process\\" AND winlog.event_data.ObjectName.keyword:*\\\\\\\\lsass.exe) AND (NOT (winlog.event_data.SubjectUserName.keyword:*$)))",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": [\n          "winlogbeat-*"\n        ]\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'LSASS Access from Non System Account\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}Hit on {{_source.@timestamp}}:\\n   ComputerName = {{_source.ComputerName}}\\n     ObjectName = {{_source.ObjectName}}\\nSubjectUserName = {{_source.SubjectUserName}}\\n    ProcessName = {{_source.ProcessName}}================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
((EventID:("4663" "4656") AND ObjectType:"Process" AND ObjectName.keyword:*\\\\lsass.exe) AND (NOT (SubjectUserName.keyword:*$)))
```


### splunk
    
```
(source="WinEventLog:Security" ((EventCode="4663" OR EventCode="4656") ObjectType="Process" ObjectName="*\\\\lsass.exe") NOT (SubjectUserName="*$")) | table ComputerName,ObjectName,SubjectUserName,ProcessName
```


### logpoint
    
```
(event_source="Microsoft-Windows-Security-Auditing" (event_id IN ["4663", "4656"] ObjectType="Process" ObjectName="*\\\\lsass.exe")  -(SubjectUserName="*$"))
```


### grep
    
```
grep -P '^(?:.*(?=.*(?:.*(?=.*(?:.*4663|.*4656))(?=.*Process)(?=.*.*\\lsass\\.exe)))(?=.*(?!.*(?:.*(?=.*.*\\$)))))'
```



