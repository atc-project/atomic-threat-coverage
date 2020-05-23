| Title                    | Suspicious Call by Ordinal       |
|:-------------------------|:------------------|
| **Description**          | Detects suspicious calls of DLLs in rundll32.dll exports by ordinal |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1085: Rundll32](https://attack.mitre.org/techniques/T1085)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1085: Rundll32](../Triggers/T1085.md)</li></ul>  |
| **Severity Level**       | high |
| **False Positives**      | <ul><li>False positives depend on scripts and administrative tools used in the monitored environment</li><li>Windows contol panel elements have been identified as source (mmc)</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://techtalk.pcmatic.com/2017/11/30/running-dll-files-malware-analysis/](https://techtalk.pcmatic.com/2017/11/30/running-dll-files-malware-analysis/)</li><li>[https://github.com/Neo23x0/DLLRunner](https://github.com/Neo23x0/DLLRunner)</li><li>[https://twitter.com/cyb3rops/status/1186631731543236608](https://twitter.com/cyb3rops/status/1186631731543236608)</li></ul>  |
| **Author**               | Florian Roth |


## Detection Rules

### Sigma rule

```
title: Suspicious Call by Ordinal
id: e79a9e79-eb72-4e78-a628-0e7e8f59e89c
description: Detects suspicious calls of DLLs in rundll32.dll exports by ordinal
status: experimental
references:
    - https://techtalk.pcmatic.com/2017/11/30/running-dll-files-malware-analysis/
    - https://github.com/Neo23x0/DLLRunner
    - https://twitter.com/cyb3rops/status/1186631731543236608
tags:
    - attack.defense_evasion
    - attack.execution
    - attack.t1085
author: Florian Roth
date: 2019/10/22
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine: '*\rundll32.exe *,#*'
    condition: selection
falsepositives:
    - False positives depend on scripts and administrative tools used in the monitored environment
    - Windows contol panel elements have been identified as source (mmc)
level: high

```





### powershell
    
```
Get-WinEvent | where {$_.message -match "CommandLine.*.*\\\\rundll32.exe .*,#.*" } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
winlog.event_data.CommandLine.keyword:*\\\\rundll32.exe\\ *,#*
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/e79a9e79-eb72-4e78-a628-0e7e8f59e89c <<EOF\n{\n  "metadata": {\n    "title": "Suspicious Call by Ordinal",\n    "description": "Detects suspicious calls of DLLs in rundll32.dll exports by ordinal",\n    "tags": [\n      "attack.defense_evasion",\n      "attack.execution",\n      "attack.t1085"\n    ],\n    "query": "winlog.event_data.CommandLine.keyword:*\\\\\\\\rundll32.exe\\\\ *,#*"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "winlog.event_data.CommandLine.keyword:*\\\\\\\\rundll32.exe\\\\ *,#*",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": [\n          "winlogbeat-*"\n        ]\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Suspicious Call by Ordinal\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
CommandLine.keyword:*\\\\rundll32.exe *,#*
```


### splunk
    
```
CommandLine="*\\\\rundll32.exe *,#*"
```


### logpoint
    
```
CommandLine="*\\\\rundll32.exe *,#*"
```


### grep
    
```
grep -P '^.*\\rundll32\\.exe .*,#.*'
```



