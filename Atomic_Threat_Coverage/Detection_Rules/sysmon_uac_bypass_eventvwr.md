| Title                | UAC Bypass via Event Viewer                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects UAC bypass method using Windows event viewer                                                                                                                                           |
| ATT&amp;CK Tactic    | <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1088](https://attack.mitre.org/tactics/T1088)</li></ul>                             |
| Data Needed          | <ul><li>[DN_0017_13_windows_sysmon_RegistryEvent](../Data_Needed/DN_0017_13_windows_sysmon_RegistryEvent.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>                                                         |
| Trigger              | <ul><li>[T1088](../Triggering/T1088.md)</li></ul>  |
| Severity Level       | critical                                                                                                                                                 |
| False Positives      | <ul><li>unknown</li></ul>                                                                  |
| Development Status   | experimental                                                                                                                                                |
| References           | <ul><li>[https://enigma0x3.net/2016/08/15/fileless-uac-bypass-using-eventvwr-exe-and-registry-hijacking/](https://enigma0x3.net/2016/08/15/fileless-uac-bypass-using-eventvwr-exe-and-registry-hijacking/)</li><li>[https://www.hybrid-analysis.com/sample/e122bc8bf291f15cab182a5d2d27b8db1e7019e4e96bb5cdbd1dfe7446f3f51f?environmentId=100](https://www.hybrid-analysis.com/sample/e122bc8bf291f15cab182a5d2d27b8db1e7019e4e96bb5cdbd1dfe7446f3f51f?environmentId=100)</li></ul>                                                          |
| Author               | Florian Roth                                                                                                                                                |
| Other Tags           | <ul><li>attack.privilege_escalation</li></ul> | 

## Detection Rules

### Sigma rule

```
title: UAC Bypass via Event Viewer
status: experimental
description: Detects UAC bypass method using Windows event viewer
references:
    - https://enigma0x3.net/2016/08/15/fileless-uac-bypass-using-eventvwr-exe-and-registry-hijacking/
    - https://www.hybrid-analysis.com/sample/e122bc8bf291f15cab182a5d2d27b8db1e7019e4e96bb5cdbd1dfe7446f3f51f?environmentId=100
author: Florian Roth
logsource:
    product: windows
    service: sysmon
detection:
    methregistry:
        EventID: 13
        TargetObject: 'HKEY_USERS\*\mscfile\shell\open\command'
    methprocess:
        EventID: 1
        ParentImage: '*\eventvwr.exe'
    filterprocess:
        Image: '*\mmc.exe'
    condition: methregistry or ( methprocess and not filterprocess )
fields:
    - CommandLine
    - ParentCommandLine
tags:
    - attack.defense_evasion
    - attack.privilege_escalation
    - attack.t1088
falsepositives:
    - unknown
level: critical



```





### Kibana query

```
((EventID:"13" AND TargetObject:"HKEY_USERS\\*\\\\mscfile\\\\shell\\\\open\\\\command") OR ((EventID:"1" AND ParentImage:"*\\\\eventvwr.exe") AND NOT (Image:"*\\\\mmc.exe")))
```





### X-Pack Watcher

```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_xpack/watcher/watch/UAC-Bypass-via-Event-Viewer <<EOF\n{\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "query_string": {\n              "query": "((EventID:\\"13\\" AND TargetObject:\\"HKEY_USERS\\\\*\\\\\\\\mscfile\\\\\\\\shell\\\\\\\\open\\\\\\\\command\\") OR ((EventID:\\"1\\" AND ParentImage:\\"*\\\\\\\\eventvwr.exe\\") AND NOT (Image:\\"*\\\\\\\\mmc.exe\\")))",\n              "analyze_wildcard": true\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": null,\n        "subject": "Sigma Rule \'UAC Bypass via Event Viewer\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}Hit on {{_source.@timestamp}}:\\n      CommandLine = {{_source.CommandLine}}\\nParentCommandLine = {{_source.ParentCommandLine}}================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```





### Graylog

```
((EventID:"13" AND TargetObject:"HKEY_USERS\\*\\\\mscfile\\\\shell\\\\open\\\\command") OR ((EventID:"1" AND ParentImage:"*\\\\eventvwr.exe") AND NOT (Image:"*\\\\mmc.exe")))
```

