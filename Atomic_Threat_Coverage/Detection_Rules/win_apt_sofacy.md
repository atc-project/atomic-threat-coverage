| Title                    | Sofacy Trojan Loader Activity       |
|:-------------------------|:------------------|
| **Description**          | Detects Trojan loader acitivty as used by APT28 |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1059: Command and Scripting Interpreter](https://attack.mitre.org/techniques/T1059)</li><li>[T1059.003: Windows Command Shell](https://attack.mitre.org/techniques/T1059.003)</li><li>[T1085: Rundll32](https://attack.mitre.org/techniques/T1085)</li><li>[T1218.011: Rundll32](https://attack.mitre.org/techniques/T1218.011)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1059.003: Windows Command Shell](../Triggers/T1059.003.md)</li><li>[T1218.011: Rundll32](../Triggers/T1218.011.md)</li></ul>  |
| **Severity Level**       | critical |
| **False Positives**      | <ul><li>Unknown</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://researchcenter.paloaltonetworks.com/2018/02/unit42-sofacy-attacks-multiple-government-entities/](https://researchcenter.paloaltonetworks.com/2018/02/unit42-sofacy-attacks-multiple-government-entities/)</li><li>[https://www.reverse.it/sample/e3399d4802f9e6d6d539e3ae57e7ea9a54610a7c4155a6541df8e94d67af086e?environmentId=100](https://www.reverse.it/sample/e3399d4802f9e6d6d539e3ae57e7ea9a54610a7c4155a6541df8e94d67af086e?environmentId=100)</li><li>[https://twitter.com/ClearskySec/status/960924755355369472](https://twitter.com/ClearskySec/status/960924755355369472)</li></ul>  |
| **Author**               | Florian Roth |
| Other Tags           | <ul><li>attack.g0007</li><li>car.2013-10-002</li></ul> | 

## Detection Rules

### Sigma rule

```
title: Sofacy Trojan Loader Activity
id: ba778144-5e3d-40cf-8af9-e28fb1df1e20
author: Florian Roth
status: experimental
date: 2018/03/01
modified: 2020/08/27
description: Detects Trojan loader acitivty as used by APT28
references:
    - https://researchcenter.paloaltonetworks.com/2018/02/unit42-sofacy-attacks-multiple-government-entities/
    - https://www.reverse.it/sample/e3399d4802f9e6d6d539e3ae57e7ea9a54610a7c4155a6541df8e94d67af086e?environmentId=100
    - https://twitter.com/ClearskySec/status/960924755355369472
tags:
    - attack.g0007
    - attack.execution
    - attack.t1059 # an old one
    - attack.t1059.003
    - attack.defense_evasion
    - attack.t1085 # an old one
    - car.2013-10-002
    - attack.t1218.011
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine:
            - 'rundll32.exe %APPDATA%\\*.dat",*'
            - 'rundll32.exe %APPDATA%\\*.dll",#1'
    condition: selection
falsepositives:
    - Unknown
level: critical

```





### powershell
    
```
Get-WinEvent | where {($_.message -match "CommandLine.*rundll32.exe %APPDATA%\\\\.*.dat\\",.*" -or $_.message -match "CommandLine.*rundll32.exe %APPDATA%\\\\.*.dll\\",#1") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
winlog.event_data.CommandLine.keyword:(rundll32.exe\\ %APPDATA%\\\\*.dat\\",* OR rundll32.exe\\ %APPDATA%\\\\*.dll\\",#1)
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/ba778144-5e3d-40cf-8af9-e28fb1df1e20 <<EOF\n{\n  "metadata": {\n    "title": "Sofacy Trojan Loader Activity",\n    "description": "Detects Trojan loader acitivty as used by APT28",\n    "tags": [\n      "attack.g0007",\n      "attack.execution",\n      "attack.t1059",\n      "attack.t1059.003",\n      "attack.defense_evasion",\n      "attack.t1085",\n      "car.2013-10-002",\n      "attack.t1218.011"\n    ],\n    "query": "winlog.event_data.CommandLine.keyword:(rundll32.exe\\\\ %APPDATA%\\\\\\\\*.dat\\\\\\",* OR rundll32.exe\\\\ %APPDATA%\\\\\\\\*.dll\\\\\\",#1)"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "winlog.event_data.CommandLine.keyword:(rundll32.exe\\\\ %APPDATA%\\\\\\\\*.dat\\\\\\",* OR rundll32.exe\\\\ %APPDATA%\\\\\\\\*.dll\\\\\\",#1)",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": [\n          "winlogbeat-*"\n        ]\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "throttle_period": "15m",\n      "email": {\n        "profile": "standard",\n        "from": "root@localhost",\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Sofacy Trojan Loader Activity\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
CommandLine.keyword:(rundll32.exe %APPDATA%\\\\*.dat\\",* rundll32.exe %APPDATA%\\\\*.dll\\",#1)
```


### splunk
    
```
(CommandLine="rundll32.exe %APPDATA%\\\\*.dat\\",*" OR CommandLine="rundll32.exe %APPDATA%\\\\*.dll\\",#1")
```


### logpoint
    
```
CommandLine IN ["rundll32.exe %APPDATA%\\\\*.dat\\",*", "rundll32.exe %APPDATA%\\\\*.dll\\",#1"]
```


### grep
    
```
grep -P \'^(?:.*rundll32\\.exe %APPDATA%\\\\.*\\.dat",.*|.*rundll32\\.exe %APPDATA%\\\\.*\\.dll",#1)\'
```



