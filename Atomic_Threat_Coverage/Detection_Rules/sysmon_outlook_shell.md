| Title                | Microsoft Outlook Spawning Windows Shell                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects a Windows command line executable started from Microsoft Outlook                                                                                                                                           |
| ATT&amp;CK Tactic    | <ul></ul>  |
| ATT&amp;CK Technique | <ul></ul>                             |
| Data Needed          | <ul><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>                                                         |
| Trigger              |  There is no Trigger for this technique yet.  |
| Severity Level       | high                                                                                                                                                 |
| False Positives      | <ul><li>False positives are possible, depends on organisation and processes</li></ul>                                                                  |
| Development Status   | experimental                                                                                                                                                |
| References           | <ul><li>[https://www2.cybereason.com/asset/60:research-cobalt-kitty-attack-lifecycle](https://www2.cybereason.com/asset/60:research-cobalt-kitty-attack-lifecycle)</li></ul>                                                          |
| Author               | Florian Roth                                                                                                                                                |


## Detection Rules

### Sigma rule

```
title: Microsoft Outlook Spawning Windows Shell
status: experimental
description: Detects a Windows command line executable started from Microsoft Outlook
references:
    - https://www2.cybereason.com/asset/60:research-cobalt-kitty-attack-lifecycle
author: Florian Roth
date: 2018/03/06
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        EventID: 1
        ParentImage:
            - '*\OUTLOOK.EXE'
        Image:
            - '*\cmd.exe'
            - '*\powershell.exe'
            - '*\wscript.exe'
            - '*\cscript.exe'
            - '*\sh.exe'
            - '*\bash.exe'
            - '*\schtasks.exe'
    condition: selection
fields:
    - CommandLine
    - ParentCommandLine
falsepositives:
    - False positives are possible, depends on organisation and processes
level: high


```





### Kibana query

```
(EventID:"1" AND ParentImage.keyword:(*\\\\OUTLOOK.EXE) AND Image.keyword:(*\\\\cmd.exe *\\\\powershell.exe *\\\\wscript.exe *\\\\cscript.exe *\\\\sh.exe *\\\\bash.exe *\\\\schtasks.exe))
```





### X-Pack Watcher

```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_xpack/watcher/watch/Microsoft-Outlook-Spawning-Windows-Shell <<EOF\n{\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "query_string": {\n              "query": "(EventID:\\"1\\" AND ParentImage.keyword:(*\\\\\\\\OUTLOOK.EXE) AND Image.keyword:(*\\\\\\\\cmd.exe *\\\\\\\\powershell.exe *\\\\\\\\wscript.exe *\\\\\\\\cscript.exe *\\\\\\\\sh.exe *\\\\\\\\bash.exe *\\\\\\\\schtasks.exe))",\n              "analyze_wildcard": true\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": null,\n        "subject": "Sigma Rule \'Microsoft Outlook Spawning Windows Shell\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}Hit on {{_source.@timestamp}}:\\n      CommandLine = {{_source.CommandLine}}\\nParentCommandLine = {{_source.ParentCommandLine}}================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```





### Graylog

```
(EventID:"1" AND ParentImage:("*\\\\OUTLOOK.EXE") AND Image:("*\\\\cmd.exe" "*\\\\powershell.exe" "*\\\\wscript.exe" "*\\\\cscript.exe" "*\\\\sh.exe" "*\\\\bash.exe" "*\\\\schtasks.exe"))
```





### Splunk

```
(EventID="1" (ParentImage="*\\\\OUTLOOK.EXE") (Image="*\\\\cmd.exe" OR Image="*\\\\powershell.exe" OR Image="*\\\\wscript.exe" OR Image="*\\\\cscript.exe" OR Image="*\\\\sh.exe" OR Image="*\\\\bash.exe" OR Image="*\\\\schtasks.exe")) | table CommandLine,ParentCommandLine
```





### Logpoint

```
(EventID="1" ParentImage IN ["*\\\\OUTLOOK.EXE"] Image IN ["*\\\\cmd.exe", "*\\\\powershell.exe", "*\\\\wscript.exe", "*\\\\cscript.exe", "*\\\\sh.exe", "*\\\\bash.exe", "*\\\\schtasks.exe"])
```





### Grep

```
grep -P '^(?:.*(?=.*1)(?=.*(?:.*.*\\OUTLOOK\\.EXE))(?=.*(?:.*.*\\cmd\\.exe|.*.*\\powershell\\.exe|.*.*\\wscript\\.exe|.*.*\\cscript\\.exe|.*.*\\sh\\.exe|.*.*\\bash\\.exe|.*.*\\schtasks\\.exe)))'
```





### Fieldlist

```
EventID\nImage\nParentImage
```

