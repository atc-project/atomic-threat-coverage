| Title                    | SAM Registry Hive Handle Request       |
|:-------------------------|:------------------|
| **Description**          | Detects handles requested to SAM registry hive |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0007: Discovery](https://attack.mitre.org/tactics/TA0007)</li><li>[TA0006: Credential Access](https://attack.mitre.org/tactics/TA0006)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1012: Query Registry](https://attack.mitre.org/techniques/T1012)</li><li>[T1552.002: Credentials in Registry](https://attack.mitre.org/techniques/T1552/002)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0058_4656_handle_to_an_object_was_requested](../Data_Needed/DN_0058_4656_handle_to_an_object_was_requested.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1012: Query Registry](../Triggers/T1012.md)</li><li>[T1552.002: Credentials in Registry](../Triggers/T1552.002.md)</li></ul>  |
| **Severity Level**       | critical |
| **False Positives**      | <ul><li>Unknown</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://github.com/Cyb3rWard0g/ThreatHunter-Playbook/tree/master/playbooks/windows/07_discovery/T1012_query_registry/sam_registry_hive_access.md](https://github.com/Cyb3rWard0g/ThreatHunter-Playbook/tree/master/playbooks/windows/07_discovery/T1012_query_registry/sam_registry_hive_access.md)</li></ul>  |
| **Author**               | Roberto Rodriguez @Cyb3rWard0g |


## Detection Rules

### Sigma rule

```
title: SAM Registry Hive Handle Request
id: f8748f2c-89dc-4d95-afb0-5a2dfdbad332
description: Detects handles requested to SAM registry hive
status: experimental
date: 2019/08/12
modified: 2020/08/23
author: Roberto Rodriguez @Cyb3rWard0g
references:
    - https://github.com/Cyb3rWard0g/ThreatHunter-Playbook/tree/master/playbooks/windows/07_discovery/T1012_query_registry/sam_registry_hive_access.md
tags:
    - attack.discovery
    - attack.t1012
    - attack.credential_access
    - attack.t1552.002
logsource:
    product: windows
    service: security
detection:
    selection: 
        EventID: 4656
        ObjectType: 'Key'
        ObjectName|endswith: '\SAM'
    condition: selection
fields:
    - ComputerName
    - SubjectDomainName
    - SubjectUserName
    - ProcessName
    - ObjectName
falsepositives:
    - Unknown
level: critical

```





### powershell
    
```
Get-WinEvent -LogName Security | where {($_.ID -eq "4656" -and $_.message -match "ObjectType.*Key" -and $_.message -match "ObjectName.*.*\\\\SAM") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.channel:"Security" AND winlog.event_id:"4656" AND winlog.event_data.ObjectType:"Key" AND winlog.event_data.ObjectName.keyword:*\\\\SAM)
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/f8748f2c-89dc-4d95-afb0-5a2dfdbad332 <<EOF\n{\n  "metadata": {\n    "title": "SAM Registry Hive Handle Request",\n    "description": "Detects handles requested to SAM registry hive",\n    "tags": [\n      "attack.discovery",\n      "attack.t1012",\n      "attack.credential_access",\n      "attack.t1552.002"\n    ],\n    "query": "(winlog.channel:\\"Security\\" AND winlog.event_id:\\"4656\\" AND winlog.event_data.ObjectType:\\"Key\\" AND winlog.event_data.ObjectName.keyword:*\\\\\\\\SAM)"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "(winlog.channel:\\"Security\\" AND winlog.event_id:\\"4656\\" AND winlog.event_data.ObjectType:\\"Key\\" AND winlog.event_data.ObjectName.keyword:*\\\\\\\\SAM)",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": [\n          "winlogbeat-*"\n        ]\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "throttle_period": "15m",\n      "email": {\n        "profile": "standard",\n        "from": "root@localhost",\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'SAM Registry Hive Handle Request\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}Hit on {{_source.@timestamp}}:\\n     ComputerName = {{_source.ComputerName}}\\nSubjectDomainName = {{_source.SubjectDomainName}}\\n  SubjectUserName = {{_source.SubjectUserName}}\\n      ProcessName = {{_source.ProcessName}}\\n       ObjectName = {{_source.ObjectName}}================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
(EventID:"4656" AND ObjectType:"Key" AND ObjectName.keyword:*\\\\SAM)
```


### splunk
    
```
(source="WinEventLog:Security" EventCode="4656" ObjectType="Key" ObjectName="*\\\\SAM") | table ComputerName,SubjectDomainName,SubjectUserName,ProcessName,ObjectName
```


### logpoint
    
```
(event_source="Microsoft-Windows-Security-Auditing" event_id="4656" ObjectType="Key" ObjectName="*\\\\SAM")
```


### grep
    
```
grep -P '^(?:.*(?=.*4656)(?=.*Key)(?=.*.*\\SAM))'
```



