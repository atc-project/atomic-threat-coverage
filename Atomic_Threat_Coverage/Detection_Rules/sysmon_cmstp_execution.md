| Title                | CMSTP Execution                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects various indicators of Microsoft Connection Manager Profile Installer execution                                                                                                                                           |
| ATT&amp;CK Tactic    | <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1191: CMSTP](https://attack.mitre.org/techniques/T1191)</li></ul>                             |
| Data Needed          | <ul><li>[DN_0016_12_windows_sysmon_RegistryEvent](../Data_Needed/DN_0016_12_windows_sysmon_RegistryEvent.md)</li><li>[DN_0017_13_windows_sysmon_RegistryEvent](../Data_Needed/DN_0017_13_windows_sysmon_RegistryEvent.md)</li><li>[DN_0014_10_windows_sysmon_ProcessAccess](../Data_Needed/DN_0014_10_windows_sysmon_ProcessAccess.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>                                                         |
| Trigger              | <ul><li>[T1191: CMSTP](../Triggers/T1191.md)</li></ul>  |
| Severity Level       | high                                                                                                                                                 |
| False Positives      | <ul><li>Legitimate CMSTP use (unlikely in modern enterprise environments)</li></ul>                                                                  |
| Development Status   | stable                                                                                                                                                |
| References           | <ul><li>[http://www.endurant.io/cmstp/detecting-cmstp-enabled-code-execution-and-uac-bypass-with-sysmon/](http://www.endurant.io/cmstp/detecting-cmstp-enabled-code-execution-and-uac-bypass-with-sysmon/)</li></ul>                                                          |
| Author               | Nik Seetharaman                                                                                                                                                |
| Other Tags           | <ul><li>attack.g0069</li><li>attack.g0069</li></ul> | 

## Detection Rules

### Sigma rule

```
title: CMSTP Execution
status: stable
description: Detects various indicators of Microsoft Connection Manager Profile Installer execution
tags:
    - attack.defense_evasion
    - attack.execution
    - attack.t1191
    - attack.g0069
author: Nik Seetharaman
references:
    - http://www.endurant.io/cmstp/detecting-cmstp-enabled-code-execution-and-uac-bypass-with-sysmon/
logsource:
    product: windows
    service: sysmon
detection:
    # CMSTP Spawning Child Process
    selection1:
        EventID: 1
        ParentImage: '*\cmstp.exe'
    # Registry Object Add
    selection2:
        EventID: 12
        TargetObject: '*\cmmgr32.exe*'
    # Registry Object Value Set
    selection3:
        EventID: 13
        TargetObject: '*\cmmgr32.exe*'
    # Process Access Call Trace
    selection4:
        EventID: 10
        CallTrace: '*cmlua.dll*'
    condition: 1 of them
fields:
    - CommandLine
    - ParentCommandLine
    - Details
falsepositives:
    - Legitimate CMSTP use (unlikely in modern enterprise environments)
level: high

```





### Kibana query

```
((EventID:"1" AND ParentImage.keyword:*\\\\cmstp.exe) OR (EventID:"12" AND TargetObject.keyword:*\\\\cmmgr32.exe*) OR (EventID:"13" AND TargetObject.keyword:*\\\\cmmgr32.exe*) OR (EventID:"10" AND CallTrace.keyword:*cmlua.dll*))
```





### X-Pack Watcher

```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_xpack/watcher/watch/CMSTP-Execution <<EOF\n{\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "query_string": {\n              "query": "((EventID:\\"1\\" AND ParentImage.keyword:*\\\\\\\\cmstp.exe) OR (EventID:\\"12\\" AND TargetObject.keyword:*\\\\\\\\cmmgr32.exe*) OR (EventID:\\"13\\" AND TargetObject.keyword:*\\\\\\\\cmmgr32.exe*) OR (EventID:\\"10\\" AND CallTrace.keyword:*cmlua.dll*))",\n              "analyze_wildcard": true\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": null,\n        "subject": "Sigma Rule \'CMSTP Execution\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}Hit on {{_source.@timestamp}}:\\n      CommandLine = {{_source.CommandLine}}\\nParentCommandLine = {{_source.ParentCommandLine}}\\n          Details = {{_source.Details}}================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```





### Graylog

```
((EventID:"1" AND ParentImage:"*\\\\cmstp.exe") OR (EventID:"12" AND TargetObject:"*\\\\cmmgr32.exe*") OR (EventID:"13" AND TargetObject:"*\\\\cmmgr32.exe*") OR (EventID:"10" AND CallTrace:"*cmlua.dll*"))
```

