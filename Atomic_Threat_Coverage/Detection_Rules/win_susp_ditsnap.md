| Title                    | DIT Snapshot Viewer Use       |
|:-------------------------|:------------------|
| **Description**          | Detects the use of Ditsnap tool. Seems to be a tool for ransomware groups. |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0006: Credential Access](https://attack.mitre.org/tactics/TA0006)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1003.003: NTDS](https://attack.mitre.org/techniques/T1003.003)</li><li>[T1003: OS Credential Dumping](https://attack.mitre.org/techniques/T1003)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1003.003: NTDS](../Triggers/T1003.003.md)</li><li>[T1003: OS Credential Dumping](../Triggers/T1003.md)</li></ul>  |
| **Severity Level**       | high |
| **False Positives**      | <ul><li>Legitimate admin usage</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://thedfirreport.com/2020/06/21/snatch-ransomware/](https://thedfirreport.com/2020/06/21/snatch-ransomware/)</li><li>[https://github.com/yosqueoy/ditsnap](https://github.com/yosqueoy/ditsnap)</li></ul>  |
| **Author**               | Furkan Caliskan (@caliskanfurkan_) |


## Detection Rules

### Sigma rule

```
title: DIT Snapshot Viewer Use
id: d3b70aad-097e-409c-9df2-450f80dc476b
status: experimental
description: Detects the use of Ditsnap tool. Seems to be a tool for ransomware groups.
references:
    - https://thedfirreport.com/2020/06/21/snatch-ransomware/
    - https://github.com/yosqueoy/ditsnap
author: 'Furkan Caliskan (@caliskanfurkan_)'
date: 2020/07/04
tags:
    - attack.credential_access
    - attack.t1003.003
    - attack.t1003 # an old one
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith:
            - '\ditsnap.exe'
    selection2:
        CommandLine|contains:
            - 'ditsnap.exe'
    condition: selection or selection2
falsepositives:
    - Legitimate admin usage
level: high

```





### powershell
    
```
Get-WinEvent | where {(($_.message -match "Image.*.*\\\\ditsnap.exe") -or ($_.message -match "CommandLine.*.*ditsnap.exe.*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.event_data.Image.keyword:(*\\\\ditsnap.exe) OR winlog.event_data.CommandLine.keyword:(*ditsnap.exe*))
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/d3b70aad-097e-409c-9df2-450f80dc476b <<EOF\n{\n  "metadata": {\n    "title": "DIT Snapshot Viewer Use",\n    "description": "Detects the use of Ditsnap tool. Seems to be a tool for ransomware groups.",\n    "tags": [\n      "attack.credential_access",\n      "attack.t1003.003",\n      "attack.t1003"\n    ],\n    "query": "(winlog.event_data.Image.keyword:(*\\\\\\\\ditsnap.exe) OR winlog.event_data.CommandLine.keyword:(*ditsnap.exe*))"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "(winlog.event_data.Image.keyword:(*\\\\\\\\ditsnap.exe) OR winlog.event_data.CommandLine.keyword:(*ditsnap.exe*))",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": [\n          "winlogbeat-*"\n        ]\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "throttle_period": "15m",\n      "email": {\n        "profile": "standard",\n        "from": "root@localhost",\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'DIT Snapshot Viewer Use\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
(Image.keyword:(*\\\\ditsnap.exe) OR CommandLine.keyword:(*ditsnap.exe*))
```


### splunk
    
```
((Image="*\\\\ditsnap.exe") OR (CommandLine="*ditsnap.exe*"))
```


### logpoint
    
```
(Image IN ["*\\\\ditsnap.exe"] OR CommandLine IN ["*ditsnap.exe*"])
```


### grep
    
```
grep -P '^(?:.*(?:.*(?:.*.*\\ditsnap\\.exe)|.*(?:.*.*ditsnap\\.exe.*)))'
```



