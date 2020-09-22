| Title                    | Suspicious Access to Sensitive File Extensions       |
|:-------------------------|:------------------|
| **Description**          | Detects known sensitive file extensions accessed on a network share |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0009: Collection](https://attack.mitre.org/tactics/TA0009)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1039: Data from Network Shared Drive](https://attack.mitre.org/techniques/T1039)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0032_5145_network_share_object_was_accessed_detailed](../Data_Needed/DN_0032_5145_network_share_object_was_accessed_detailed.md)</li></ul>  |
| **Trigger**              |  There is no documented Trigger for this Detection Rule yet  |
| **Severity Level**       | medium |
| **False Positives**      | <ul><li>Help Desk operator doing backup or re-imaging end user machine or pentest or backup software</li><li>Users working with these data types or exchanging message files</li></ul>  |
| **Development Status**   |  Development Status wasn't defined for this Detection Rule yet  |
| **References**           |  There are no documented References for this Detection Rule yet  |
| **Author**               | Samir Bousseaden |


## Detection Rules

### Sigma rule

```
title: Suspicious Access to Sensitive File Extensions
id: 91c945bc-2ad1-4799-a591-4d00198a1215
description: Detects known sensitive file extensions accessed on a network share
author: Samir Bousseaden
date: 2019/04/03
modified: 2020/08/23
tags:
    - attack.collection
    - attack.t1039
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID:
            - 5145
        RelativeTargetName:
            - '*.pst'
            - '*.ost'
            - '*.msg'
            - '*.nst'
            - '*.oab'
            - '*.edb'
            - '*.nsf'
            - '*.bak'
            - '*.dmp'
            - '*.kirbi'
            - '*\groups.xml'
            - '*.rdp'
    condition: selection
fields:
    - ComputerName
    - SubjectDomainName
    - SubjectUserName
    - RelativeTargetName
falsepositives:
    - Help Desk operator doing backup or re-imaging end user machine or pentest or backup software
    - Users working with these data types or exchanging message files
level: medium

```





### powershell
    
```
Get-WinEvent -LogName Security | where {(($_.ID -eq "5145") -and ($_.message -match "RelativeTargetName.*.*.pst" -or $_.message -match "RelativeTargetName.*.*.ost" -or $_.message -match "RelativeTargetName.*.*.msg" -or $_.message -match "RelativeTargetName.*.*.nst" -or $_.message -match "RelativeTargetName.*.*.oab" -or $_.message -match "RelativeTargetName.*.*.edb" -or $_.message -match "RelativeTargetName.*.*.nsf" -or $_.message -match "RelativeTargetName.*.*.bak" -or $_.message -match "RelativeTargetName.*.*.dmp" -or $_.message -match "RelativeTargetName.*.*.kirbi" -or $_.message -match "RelativeTargetName.*.*\\\\groups.xml" -or $_.message -match "RelativeTargetName.*.*.rdp")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.channel:"Security" AND winlog.event_id:("5145") AND RelativeTargetName.keyword:(*.pst OR *.ost OR *.msg OR *.nst OR *.oab OR *.edb OR *.nsf OR *.bak OR *.dmp OR *.kirbi OR *\\\\groups.xml OR *.rdp))
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/91c945bc-2ad1-4799-a591-4d00198a1215 <<EOF\n{\n  "metadata": {\n    "title": "Suspicious Access to Sensitive File Extensions",\n    "description": "Detects known sensitive file extensions accessed on a network share",\n    "tags": [\n      "attack.collection",\n      "attack.t1039"\n    ],\n    "query": "(winlog.channel:\\"Security\\" AND winlog.event_id:(\\"5145\\") AND RelativeTargetName.keyword:(*.pst OR *.ost OR *.msg OR *.nst OR *.oab OR *.edb OR *.nsf OR *.bak OR *.dmp OR *.kirbi OR *\\\\\\\\groups.xml OR *.rdp))"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "(winlog.channel:\\"Security\\" AND winlog.event_id:(\\"5145\\") AND RelativeTargetName.keyword:(*.pst OR *.ost OR *.msg OR *.nst OR *.oab OR *.edb OR *.nsf OR *.bak OR *.dmp OR *.kirbi OR *\\\\\\\\groups.xml OR *.rdp))",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": [\n          "winlogbeat-*"\n        ]\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "throttle_period": "15m",\n      "email": {\n        "profile": "standard",\n        "from": "root@localhost",\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Suspicious Access to Sensitive File Extensions\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}Hit on {{_source.@timestamp}}:\\n      ComputerName = {{_source.ComputerName}}\\n SubjectDomainName = {{_source.SubjectDomainName}}\\n   SubjectUserName = {{_source.SubjectUserName}}\\nRelativeTargetName = {{_source.RelativeTargetName}}================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
(EventID:("5145") AND RelativeTargetName.keyword:(*.pst *.ost *.msg *.nst *.oab *.edb *.nsf *.bak *.dmp *.kirbi *\\\\groups.xml *.rdp))
```


### splunk
    
```
(source="WinEventLog:Security" (EventCode="5145") (RelativeTargetName="*.pst" OR RelativeTargetName="*.ost" OR RelativeTargetName="*.msg" OR RelativeTargetName="*.nst" OR RelativeTargetName="*.oab" OR RelativeTargetName="*.edb" OR RelativeTargetName="*.nsf" OR RelativeTargetName="*.bak" OR RelativeTargetName="*.dmp" OR RelativeTargetName="*.kirbi" OR RelativeTargetName="*\\\\groups.xml" OR RelativeTargetName="*.rdp")) | table ComputerName,SubjectDomainName,SubjectUserName,RelativeTargetName
```


### logpoint
    
```
(event_source="Microsoft-Windows-Security-Auditing" event_id IN ["5145"] RelativeTargetName IN ["*.pst", "*.ost", "*.msg", "*.nst", "*.oab", "*.edb", "*.nsf", "*.bak", "*.dmp", "*.kirbi", "*\\\\groups.xml", "*.rdp"])
```


### grep
    
```
grep -P '^(?:.*(?=.*(?:.*5145))(?=.*(?:.*.*\\.pst|.*.*\\.ost|.*.*\\.msg|.*.*\\.nst|.*.*\\.oab|.*.*\\.edb|.*.*\\.nsf|.*.*\\.bak|.*.*\\.dmp|.*.*\\.kirbi|.*.*\\groups\\.xml|.*.*\\.rdp)))'
```



