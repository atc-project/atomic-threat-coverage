| Title                    | Octopus Scanner Malware       |
|:-------------------------|:------------------|
| **Description**          | Detects Octopus Scanner Malware. |
| **ATT&amp;CK Tactic**    |   This Detection Rule wasn't mapped to ATT&amp;CK Tactic yet  |
| **ATT&amp;CK Technique** | <ul><li>[T1195: Supply Chain Compromise](https://attack.mitre.org/techniques/T1195)</li><li>[T1195.001: Compromise Software Dependencies and Development Tools](https://attack.mitre.org/techniques/T1195/001)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0015_11_windows_sysmon_FileCreate](../Data_Needed/DN_0015_11_windows_sysmon_FileCreate.md)</li></ul>  |
| **Trigger**              |  There is no documented Trigger for this Detection Rule yet  |
| **Severity Level**       | high |
| **False Positives**      | <ul><li>Unknown</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://securitylab.github.com/research/octopus-scanner-malware-open-source-supply-chain](https://securitylab.github.com/research/octopus-scanner-malware-open-source-supply-chain)</li></ul>  |
| **Author**               | NVISO |


## Detection Rules

### Sigma rule

```
title: Octopus Scanner Malware
id: 805c55d9-31e6-4846-9878-c34c75054fe9
status: experimental
description: Detects Octopus Scanner Malware.
references:
  - https://securitylab.github.com/research/octopus-scanner-malware-open-source-supply-chain
tags:
  - attack.t1195
  - attack.t1195.001
author: NVISO
date: 2020/06/09
logsource:
  product: windows
  service: sysmon
detection:
  filecreate:
    EventID: 11
  selection:
    TargetFilename|endswith:
      - '\AppData\Local\Microsoft\Cache134.dat'
      - '\AppData\Local\Microsoft\ExplorerSync.db'
  condition: filecreate and selection
falsepositives:
  - Unknown
level: high
```





### powershell
    
```
Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "11" -and ($_.message -match "TargetFilename.*.*\\\\AppData\\\\Local\\\\Microsoft\\\\Cache134.dat" -or $_.message -match "TargetFilename.*.*\\\\AppData\\\\Local\\\\Microsoft\\\\ExplorerSync.db")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.channel:"Microsoft\\-Windows\\-Sysmon\\/Operational" AND winlog.event_id:"11" AND winlog.event_data.TargetFilename.keyword:(*\\\\AppData\\\\Local\\\\Microsoft\\\\Cache134.dat OR *\\\\AppData\\\\Local\\\\Microsoft\\\\ExplorerSync.db))
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/805c55d9-31e6-4846-9878-c34c75054fe9 <<EOF\n{\n  "metadata": {\n    "title": "Octopus Scanner Malware",\n    "description": "Detects Octopus Scanner Malware.",\n    "tags": [\n      "attack.t1195",\n      "attack.t1195.001"\n    ],\n    "query": "(winlog.channel:\\"Microsoft\\\\-Windows\\\\-Sysmon\\\\/Operational\\" AND winlog.event_id:\\"11\\" AND winlog.event_data.TargetFilename.keyword:(*\\\\\\\\AppData\\\\\\\\Local\\\\\\\\Microsoft\\\\\\\\Cache134.dat OR *\\\\\\\\AppData\\\\\\\\Local\\\\\\\\Microsoft\\\\\\\\ExplorerSync.db))"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "(winlog.channel:\\"Microsoft\\\\-Windows\\\\-Sysmon\\\\/Operational\\" AND winlog.event_id:\\"11\\" AND winlog.event_data.TargetFilename.keyword:(*\\\\\\\\AppData\\\\\\\\Local\\\\\\\\Microsoft\\\\\\\\Cache134.dat OR *\\\\\\\\AppData\\\\\\\\Local\\\\\\\\Microsoft\\\\\\\\ExplorerSync.db))",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": [\n          "winlogbeat-*"\n        ]\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "throttle_period": "15m",\n      "email": {\n        "profile": "standard",\n        "from": "root@localhost",\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Octopus Scanner Malware\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
(EventID:"11" AND TargetFilename.keyword:(*\\\\AppData\\\\Local\\\\Microsoft\\\\Cache134.dat *\\\\AppData\\\\Local\\\\Microsoft\\\\ExplorerSync.db))
```


### splunk
    
```
(source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode="11" (TargetFilename="*\\\\AppData\\\\Local\\\\Microsoft\\\\Cache134.dat" OR TargetFilename="*\\\\AppData\\\\Local\\\\Microsoft\\\\ExplorerSync.db"))
```


### logpoint
    
```
(event_id="11" TargetFilename IN ["*\\\\AppData\\\\Local\\\\Microsoft\\\\Cache134.dat", "*\\\\AppData\\\\Local\\\\Microsoft\\\\ExplorerSync.db"])
```


### grep
    
```
grep -P '^(?:.*(?=.*11)(?=.*(?:.*.*\\AppData\\Local\\Microsoft\\Cache134\\.dat|.*.*\\AppData\\Local\\Microsoft\\ExplorerSync\\.db)))'
```



