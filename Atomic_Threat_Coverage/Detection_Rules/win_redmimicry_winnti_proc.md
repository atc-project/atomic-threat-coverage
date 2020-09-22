| Title                    | RedMimicry Winnti Playbook Execute       |
|:-------------------------|:------------------|
| **Description**          | Detects actions caused by the RedMimicry Winnti playbook |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1059: Command and Scripting Interpreter](https://attack.mitre.org/techniques/T1059)</li><li>[T1106: Native API](https://attack.mitre.org/techniques/T1106)</li><li>[T1059.003: Windows Command Shell](https://attack.mitre.org/techniques/T1059.003)</li><li>[T1218.011: Rundll32](https://attack.mitre.org/techniques/T1218.011)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1106: Native API](../Triggers/T1106.md)</li><li>[T1059.003: Windows Command Shell](../Triggers/T1059.003.md)</li><li>[T1218.011: Rundll32](../Triggers/T1218.011.md)</li></ul>  |
| **Severity Level**       | high |
| **False Positives**      | <ul><li>Unknown</li></ul>  |
| **Development Status**   |  Development Status wasn't defined for this Detection Rule yet  |
| **References**           | <ul><li>[https://redmimicry.com](https://redmimicry.com)</li></ul>  |
| **Author**               | Alexander Rausch |


## Detection Rules

### Sigma rule

```
title: RedMimicry Winnti Playbook Execute
id: 95022b85-ff2a-49fa-939a-d7b8f56eeb9b
description: Detects actions caused by the RedMimicry Winnti playbook
references:
    - https://redmimicry.com
author: Alexander Rausch
date: 2020/06/24
modified: 2020/09/06
tags:
    - attack.execution
    - attack.defense_evasion
    - attack.t1059 # an old one
    - attack.t1106
    - attack.t1059.003
    - attack.t1218.011    
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        Image|contains:
            - rundll32.exe
            - cmd.exe
        CommandLine|contains:
            - gthread-3.6.dll
            - \Windows\Temp\tmp.bat
            - sigcmm-2.4.dll
    condition: selection
falsepositives:
    - Unknown
level: high

```





### powershell
    
```
Get-WinEvent | where {(($_.message -match "Image.*.*rundll32.exe.*" -or $_.message -match "Image.*.*cmd.exe.*") -and ($_.message -match "CommandLine.*.*gthread-3.6.dll.*" -or $_.message -match "CommandLine.*.*\\\\Windows\\\\Temp\\\\tmp.bat.*" -or $_.message -match "CommandLine.*.*sigcmm-2.4.dll.*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.event_data.Image.keyword:(*rundll32.exe* OR *cmd.exe*) AND winlog.event_data.CommandLine.keyword:(*gthread\\-3.6.dll* OR *\\\\Windows\\\\Temp\\\\tmp.bat* OR *sigcmm\\-2.4.dll*))
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/95022b85-ff2a-49fa-939a-d7b8f56eeb9b <<EOF\n{\n  "metadata": {\n    "title": "RedMimicry Winnti Playbook Execute",\n    "description": "Detects actions caused by the RedMimicry Winnti playbook",\n    "tags": [\n      "attack.execution",\n      "attack.defense_evasion",\n      "attack.t1059",\n      "attack.t1106",\n      "attack.t1059.003",\n      "attack.t1218.011"\n    ],\n    "query": "(winlog.event_data.Image.keyword:(*rundll32.exe* OR *cmd.exe*) AND winlog.event_data.CommandLine.keyword:(*gthread\\\\-3.6.dll* OR *\\\\\\\\Windows\\\\\\\\Temp\\\\\\\\tmp.bat* OR *sigcmm\\\\-2.4.dll*))"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "(winlog.event_data.Image.keyword:(*rundll32.exe* OR *cmd.exe*) AND winlog.event_data.CommandLine.keyword:(*gthread\\\\-3.6.dll* OR *\\\\\\\\Windows\\\\\\\\Temp\\\\\\\\tmp.bat* OR *sigcmm\\\\-2.4.dll*))",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": [\n          "winlogbeat-*"\n        ]\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "throttle_period": "15m",\n      "email": {\n        "profile": "standard",\n        "from": "root@localhost",\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'RedMimicry Winnti Playbook Execute\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
(Image.keyword:(*rundll32.exe* *cmd.exe*) AND CommandLine.keyword:(*gthread\\-3.6.dll* *\\\\Windows\\\\Temp\\\\tmp.bat* *sigcmm\\-2.4.dll*))
```


### splunk
    
```
((Image="*rundll32.exe*" OR Image="*cmd.exe*") (CommandLine="*gthread-3.6.dll*" OR CommandLine="*\\\\Windows\\\\Temp\\\\tmp.bat*" OR CommandLine="*sigcmm-2.4.dll*"))
```


### logpoint
    
```
(Image IN ["*rundll32.exe*", "*cmd.exe*"] CommandLine IN ["*gthread-3.6.dll*", "*\\\\Windows\\\\Temp\\\\tmp.bat*", "*sigcmm-2.4.dll*"])
```


### grep
    
```
grep -P '^(?:.*(?=.*(?:.*.*rundll32\\.exe.*|.*.*cmd\\.exe.*))(?=.*(?:.*.*gthread-3\\.6\\.dll.*|.*.*\\Windows\\Temp\\tmp\\.bat.*|.*.*sigcmm-2\\.4\\.dll.*)))'
```



