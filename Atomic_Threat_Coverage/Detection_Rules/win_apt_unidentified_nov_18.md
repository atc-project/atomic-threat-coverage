| Title                    | Unidentified Attacker November 2018       |
|:-------------------------|:------------------|
| **Description**          | A sigma rule detecting an unidetefied attacker who used phishing emails to target high profile orgs on November 2018. The Actor shares some TTPs with YYTRIUM/APT29 campaign in 2016. |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1218.011: Rundll32](https://attack.mitre.org/techniques/T1218.011)</li><li>[T1085: Rundll32](https://attack.mitre.org/techniques/T1085)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li><li>[DN_0015_11_windows_sysmon_FileCreate](../Data_Needed/DN_0015_11_windows_sysmon_FileCreate.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1218.011: Rundll32](../Triggers/T1218.011.md)</li></ul>  |
| **Severity Level**       | high |
| **False Positives**      |  There are no documented False Positives for this Detection Rule yet  |
| **Development Status**   | stable |
| **References**           | <ul><li>[https://twitter.com/DrunkBinary/status/1063075530180886529](https://twitter.com/DrunkBinary/status/1063075530180886529)</li></ul>  |
| **Author**               | @41thexplorer, Microsoft Defender ATP |


## Detection Rules

### Sigma rule

```
action: global
title: Unidentified Attacker November 2018
id: 7453575c-a747-40b9-839b-125a0aae324b
status: stable
description: A sigma rule detecting an unidetefied attacker who used phishing emails to target high profile orgs on November 2018. The Actor shares some TTPs with
    YYTRIUM/APT29 campaign in 2016.
references:
    - https://twitter.com/DrunkBinary/status/1063075530180886529
author: '@41thexplorer, Microsoft Defender ATP'
date: 2018/11/20
modified: 2020/08/26
tags:
    - attack.execution
    - attack.t1218.011
    - attack.t1085  # an old one
detection:
    condition: 1 of them
level: high
---
logsource:
    category: process_creation
    product: windows
detection:
    selection1:
        CommandLine: '*cyzfc.dat, PointFunctionCall'
---
# Sysmon: File Creation (ID 11)
logsource:
    product: windows
    service: sysmon
detection:
    selection2:
        EventID: 11
        TargetFilename: 
            - '*ds7002.lnk*' 
```





### powershell
    
```
Get-WinEvent | where {$_.message -match "CommandLine.*.*cyzfc.dat, PointFunctionCall" } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message\nGet-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "11" -and ($_.message -match "TargetFilename.*.*ds7002.lnk.*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
winlog.event_data.CommandLine.keyword:*cyzfc.dat,\\ PointFunctionCall\n(winlog.channel:"Microsoft\\-Windows\\-Sysmon\\/Operational" AND winlog.event_id:"11" AND winlog.event_data.TargetFilename.keyword:(*ds7002.lnk*))
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/7453575c-a747-40b9-839b-125a0aae324b <<EOF\n{\n  "metadata": {\n    "title": "Unidentified Attacker November 2018",\n    "description": "A sigma rule detecting an unidetefied attacker who used phishing emails to target high profile orgs on November 2018. The Actor shares some TTPs with YYTRIUM/APT29 campaign in 2016.",\n    "tags": [\n      "attack.execution",\n      "attack.t1218.011",\n      "attack.t1085"\n    ],\n    "query": "winlog.event_data.CommandLine.keyword:*cyzfc.dat,\\\\ PointFunctionCall"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "winlog.event_data.CommandLine.keyword:*cyzfc.dat,\\\\ PointFunctionCall",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": [\n          "winlogbeat-*"\n        ]\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "throttle_period": "15m",\n      "email": {\n        "profile": "standard",\n        "from": "root@localhost",\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Unidentified Attacker November 2018\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\ncurl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/7453575c-a747-40b9-839b-125a0aae324b-2 <<EOF\n{\n  "metadata": {\n    "title": "Unidentified Attacker November 2018",\n    "description": "A sigma rule detecting an unidetefied attacker who used phishing emails to target high profile orgs on November 2018. The Actor shares some TTPs with YYTRIUM/APT29 campaign in 2016.",\n    "tags": [\n      "attack.execution",\n      "attack.t1218.011",\n      "attack.t1085"\n    ],\n    "query": "(winlog.channel:\\"Microsoft\\\\-Windows\\\\-Sysmon\\\\/Operational\\" AND winlog.event_id:\\"11\\" AND winlog.event_data.TargetFilename.keyword:(*ds7002.lnk*))"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "(winlog.channel:\\"Microsoft\\\\-Windows\\\\-Sysmon\\\\/Operational\\" AND winlog.event_id:\\"11\\" AND winlog.event_data.TargetFilename.keyword:(*ds7002.lnk*))",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": [\n          "winlogbeat-*"\n        ]\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "throttle_period": "15m",\n      "email": {\n        "profile": "standard",\n        "from": "root@localhost",\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Unidentified Attacker November 2018\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
CommandLine.keyword:*cyzfc.dat, PointFunctionCall\n(EventID:"11" AND TargetFilename.keyword:(*ds7002.lnk*))
```


### splunk
    
```
CommandLine="*cyzfc.dat, PointFunctionCall"\n(source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode="11" (TargetFilename="*ds7002.lnk*"))
```


### logpoint
    
```
CommandLine="*cyzfc.dat, PointFunctionCall"\n(event_id="11" TargetFilename IN ["*ds7002.lnk*"])
```


### grep
    
```
grep -P '^.*cyzfc\\.dat, PointFunctionCall'\ngrep -P '^(?:.*(?=.*11)(?=.*(?:.*.*ds7002\\.lnk.*)))'
```



