| Title                | Meterpreter or Cobalt Strike getsystem service installation                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects the use of getsystem Meterpreter/Cobalt Strike command by detecting a specific service installation                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0004: Privilege Escalation](https://attack.mitre.org/tactics/TA0004)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1134: Access Token Manipulation](https://attack.mitre.org/techniques/T1134)</li></ul>  |
| Data Needed          | <ul><li>[DN_0005_7045_windows_service_insatalled](../Data_Needed/DN_0005_7045_windows_service_insatalled.md)</li><li>[DN_0010_6_windows_sysmon_driver_loaded](../Data_Needed/DN_0010_6_windows_sysmon_driver_loaded.md)</li><li>[DN_0063_4697_service_was_installed_in_the_system](../Data_Needed/DN_0063_4697_service_was_installed_in_the_system.md)</li></ul>  |
| Trigger              | <ul><li>[T1134: Access Token Manipulation](../Triggers/T1134.md)</li></ul>  |
| Severity Level       | critical |
| False Positives      | <ul><li>Highly unlikely</li></ul>  |
| Development Status   |  Development Status wasn't defined for this Detection Rule yet  |
| References           | <ul><li>[https://speakerdeck.com/heirhabarov/hunting-for-privilege-escalation-in-windows-environment](https://speakerdeck.com/heirhabarov/hunting-for-privilege-escalation-in-windows-environment)</li><li>[https://blog.cobaltstrike.com/2014/04/02/what-happens-when-i-type-getsystem/](https://blog.cobaltstrike.com/2014/04/02/what-happens-when-i-type-getsystem/)</li></ul>  |
| Author               | Teymur Kheirkhabarov |


## Detection Rules

### Sigma rule

```
action: global
title: Meterpreter or Cobalt Strike getsystem service installation
id: 843544a7-56e0-4dcc-a44f-5cc266dd97d6
description: Detects the use of getsystem Meterpreter/Cobalt Strike command by detecting a specific service installation
author: Teymur Kheirkhabarov
date: 2019/10/26
modified: 2019/11/11
references:
    - https://speakerdeck.com/heirhabarov/hunting-for-privilege-escalation-in-windows-environment
    - https://blog.cobaltstrike.com/2014/04/02/what-happens-when-i-type-getsystem/
tags:
    - attack.privilege_escalation
    - attack.t1134
detection:
    selection:
        - ServiceFileName|contains:
            - 'cmd'
            - 'comspec'
        # meterpreter getsystem technique 1: cmd.exe /c echo 559891bb017 > \\.\pipe\5e120a
        - ServiceFileName|contains|all:
            - 'cmd'
            - '/c'
            - 'echo'
            - '\pipe\'
        # cobaltstrike getsystem technique 1: %COMSPEC% /c echo 559891bb017 > \\.\pipe\5e120a
        - ServiceFileName|contains|all:
            - '%COMSPEC%'
            - '/c'
            - 'echo'
            - '\pipe\'
        # meterpreter getsystem technique 2: rundll32.exe C:\Users\test\AppData\Local\Temp\tmexsn.dll,a /p:tmexsn
        - ServiceFileName|contains|all:
            - 'rundll32'
            - '.dll,a'
            - '/p:'
    condition: selection
fields:
    - ServiceFileName
falsepositives:
    - Highly unlikely
level: critical
---
logsource:
    product: windows
    service: system
detection:
    selection:
        EventID: 7045
---
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        EventID: 6
---
 logsource:
     product: windows
     service: security
 detection:
     selection:
         EventID: 4697

```





### es-qs
    
```
(ServiceFileName.keyword:(*cmd* OR *comspec*) OR (ServiceFileName.keyword:*cmd* AND ServiceFileName.keyword:*\\/c* AND ServiceFileName.keyword:*echo* AND ServiceFileName.keyword:*\\\\pipe\\*) OR (ServiceFileName.keyword:*%COMSPEC%* AND ServiceFileName.keyword:*\\/c* AND ServiceFileName.keyword:*echo* AND ServiceFileName.keyword:*\\\\pipe\\*) OR (ServiceFileName.keyword:*rundll32* AND ServiceFileName.keyword:*.dll,a* AND ServiceFileName.keyword:*\\/p\\:*))\n(ServiceFileName.keyword:(*cmd* OR *comspec*) OR (ServiceFileName.keyword:*cmd* AND ServiceFileName.keyword:*\\/c* AND ServiceFileName.keyword:*echo* AND ServiceFileName.keyword:*\\\\pipe\\*) OR (ServiceFileName.keyword:*%COMSPEC%* AND ServiceFileName.keyword:*\\/c* AND ServiceFileName.keyword:*echo* AND ServiceFileName.keyword:*\\\\pipe\\*) OR (ServiceFileName.keyword:*rundll32* AND ServiceFileName.keyword:*.dll,a* AND ServiceFileName.keyword:*\\/p\\:*))\n(ServiceFileName.keyword:(*cmd* OR *comspec*) OR (ServiceFileName.keyword:*cmd* AND ServiceFileName.keyword:*\\/c* AND ServiceFileName.keyword:*echo* AND ServiceFileName.keyword:*\\\\pipe\\*) OR (ServiceFileName.keyword:*%COMSPEC%* AND ServiceFileName.keyword:*\\/c* AND ServiceFileName.keyword:*echo* AND ServiceFileName.keyword:*\\\\pipe\\*) OR (ServiceFileName.keyword:*rundll32* AND ServiceFileName.keyword:*.dll,a* AND ServiceFileName.keyword:*\\/p\\:*))
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/Meterpreter-or-Cobalt-Strike-getsystem-service-installation <<EOF\n{\n  "metadata": {\n    "title": "Meterpreter or Cobalt Strike getsystem service installation",\n    "description": "Detects the use of getsystem Meterpreter/Cobalt Strike command by detecting a specific service installation",\n    "tags": [\n      "attack.privilege_escalation",\n      "attack.t1134"\n    ],\n    "query": "(ServiceFileName.keyword:(*cmd* OR *comspec*) OR (ServiceFileName.keyword:*cmd* AND ServiceFileName.keyword:*\\\\/c* AND ServiceFileName.keyword:*echo* AND ServiceFileName.keyword:*\\\\\\\\pipe\\\\*) OR (ServiceFileName.keyword:*%COMSPEC%* AND ServiceFileName.keyword:*\\\\/c* AND ServiceFileName.keyword:*echo* AND ServiceFileName.keyword:*\\\\\\\\pipe\\\\*) OR (ServiceFileName.keyword:*rundll32* AND ServiceFileName.keyword:*.dll,a* AND ServiceFileName.keyword:*\\\\/p\\\\:*))"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "(ServiceFileName.keyword:(*cmd* OR *comspec*) OR (ServiceFileName.keyword:*cmd* AND ServiceFileName.keyword:*\\\\/c* AND ServiceFileName.keyword:*echo* AND ServiceFileName.keyword:*\\\\\\\\pipe\\\\*) OR (ServiceFileName.keyword:*%COMSPEC%* AND ServiceFileName.keyword:*\\\\/c* AND ServiceFileName.keyword:*echo* AND ServiceFileName.keyword:*\\\\\\\\pipe\\\\*) OR (ServiceFileName.keyword:*rundll32* AND ServiceFileName.keyword:*.dll,a* AND ServiceFileName.keyword:*\\\\/p\\\\:*))",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Meterpreter or Cobalt Strike getsystem service installation\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}Hit on {{_source.@timestamp}}:\\nServiceFileName = {{_source.ServiceFileName}}================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\ncurl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/Meterpreter-or-Cobalt-Strike-getsystem-service-installation-2 <<EOF\n{\n  "metadata": {\n    "title": "Meterpreter or Cobalt Strike getsystem service installation",\n    "description": "Detects the use of getsystem Meterpreter/Cobalt Strike command by detecting a specific service installation",\n    "tags": [\n      "attack.privilege_escalation",\n      "attack.t1134"\n    ],\n    "query": "(ServiceFileName.keyword:(*cmd* OR *comspec*) OR (ServiceFileName.keyword:*cmd* AND ServiceFileName.keyword:*\\\\/c* AND ServiceFileName.keyword:*echo* AND ServiceFileName.keyword:*\\\\\\\\pipe\\\\*) OR (ServiceFileName.keyword:*%COMSPEC%* AND ServiceFileName.keyword:*\\\\/c* AND ServiceFileName.keyword:*echo* AND ServiceFileName.keyword:*\\\\\\\\pipe\\\\*) OR (ServiceFileName.keyword:*rundll32* AND ServiceFileName.keyword:*.dll,a* AND ServiceFileName.keyword:*\\\\/p\\\\:*))"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "(ServiceFileName.keyword:(*cmd* OR *comspec*) OR (ServiceFileName.keyword:*cmd* AND ServiceFileName.keyword:*\\\\/c* AND ServiceFileName.keyword:*echo* AND ServiceFileName.keyword:*\\\\\\\\pipe\\\\*) OR (ServiceFileName.keyword:*%COMSPEC%* AND ServiceFileName.keyword:*\\\\/c* AND ServiceFileName.keyword:*echo* AND ServiceFileName.keyword:*\\\\\\\\pipe\\\\*) OR (ServiceFileName.keyword:*rundll32* AND ServiceFileName.keyword:*.dll,a* AND ServiceFileName.keyword:*\\\\/p\\\\:*))",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Meterpreter or Cobalt Strike getsystem service installation\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}Hit on {{_source.@timestamp}}:\\nServiceFileName = {{_source.ServiceFileName}}================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\ncurl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/Meterpreter-or-Cobalt-Strike-getsystem-service-installation-3 <<EOF\n{\n  "metadata": {\n    "title": "Meterpreter or Cobalt Strike getsystem service installation",\n    "description": "Detects the use of getsystem Meterpreter/Cobalt Strike command by detecting a specific service installation",\n    "tags": [\n      "attack.privilege_escalation",\n      "attack.t1134"\n    ],\n    "query": "(ServiceFileName.keyword:(*cmd* OR *comspec*) OR (ServiceFileName.keyword:*cmd* AND ServiceFileName.keyword:*\\\\/c* AND ServiceFileName.keyword:*echo* AND ServiceFileName.keyword:*\\\\\\\\pipe\\\\*) OR (ServiceFileName.keyword:*%COMSPEC%* AND ServiceFileName.keyword:*\\\\/c* AND ServiceFileName.keyword:*echo* AND ServiceFileName.keyword:*\\\\\\\\pipe\\\\*) OR (ServiceFileName.keyword:*rundll32* AND ServiceFileName.keyword:*.dll,a* AND ServiceFileName.keyword:*\\\\/p\\\\:*))"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "(ServiceFileName.keyword:(*cmd* OR *comspec*) OR (ServiceFileName.keyword:*cmd* AND ServiceFileName.keyword:*\\\\/c* AND ServiceFileName.keyword:*echo* AND ServiceFileName.keyword:*\\\\\\\\pipe\\\\*) OR (ServiceFileName.keyword:*%COMSPEC%* AND ServiceFileName.keyword:*\\\\/c* AND ServiceFileName.keyword:*echo* AND ServiceFileName.keyword:*\\\\\\\\pipe\\\\*) OR (ServiceFileName.keyword:*rundll32* AND ServiceFileName.keyword:*.dll,a* AND ServiceFileName.keyword:*\\\\/p\\\\:*))",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Meterpreter or Cobalt Strike getsystem service installation\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}Hit on {{_source.@timestamp}}:\\nServiceFileName = {{_source.ServiceFileName}}================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
(ServiceFileName.keyword:(*cmd* *comspec*) OR (ServiceFileName.keyword:*cmd* AND ServiceFileName.keyword:*\\/c* AND ServiceFileName.keyword:*echo* AND ServiceFileName.keyword:*\\\\pipe\\*) OR (ServiceFileName.keyword:*%COMSPEC%* AND ServiceFileName.keyword:*\\/c* AND ServiceFileName.keyword:*echo* AND ServiceFileName.keyword:*\\\\pipe\\*) OR (ServiceFileName.keyword:*rundll32* AND ServiceFileName.keyword:*.dll,a* AND ServiceFileName.keyword:*\\/p\\:*))\n(ServiceFileName.keyword:(*cmd* *comspec*) OR (ServiceFileName.keyword:*cmd* AND ServiceFileName.keyword:*\\/c* AND ServiceFileName.keyword:*echo* AND ServiceFileName.keyword:*\\\\pipe\\*) OR (ServiceFileName.keyword:*%COMSPEC%* AND ServiceFileName.keyword:*\\/c* AND ServiceFileName.keyword:*echo* AND ServiceFileName.keyword:*\\\\pipe\\*) OR (ServiceFileName.keyword:*rundll32* AND ServiceFileName.keyword:*.dll,a* AND ServiceFileName.keyword:*\\/p\\:*))\n(ServiceFileName.keyword:(*cmd* *comspec*) OR (ServiceFileName.keyword:*cmd* AND ServiceFileName.keyword:*\\/c* AND ServiceFileName.keyword:*echo* AND ServiceFileName.keyword:*\\\\pipe\\*) OR (ServiceFileName.keyword:*%COMSPEC%* AND ServiceFileName.keyword:*\\/c* AND ServiceFileName.keyword:*echo* AND ServiceFileName.keyword:*\\\\pipe\\*) OR (ServiceFileName.keyword:*rundll32* AND ServiceFileName.keyword:*.dll,a* AND ServiceFileName.keyword:*\\/p\\:*))
```


### splunk
    
```
((ServiceFileName="*cmd*" OR ServiceFileName="*comspec*") OR (ServiceFileName="*cmd*" ServiceFileName="*/c*" ServiceFileName="*echo*" ServiceFileName="*\\\\pipe\\*") OR (ServiceFileName="*%COMSPEC%*" ServiceFileName="*/c*" ServiceFileName="*echo*" ServiceFileName="*\\\\pipe\\*") OR (ServiceFileName="*rundll32*" ServiceFileName="*.dll,a*" ServiceFileName="*/p:*")) | table ServiceFileName\n((ServiceFileName="*cmd*" OR ServiceFileName="*comspec*") OR (ServiceFileName="*cmd*" ServiceFileName="*/c*" ServiceFileName="*echo*" ServiceFileName="*\\\\pipe\\*") OR (ServiceFileName="*%COMSPEC%*" ServiceFileName="*/c*" ServiceFileName="*echo*" ServiceFileName="*\\\\pipe\\*") OR (ServiceFileName="*rundll32*" ServiceFileName="*.dll,a*" ServiceFileName="*/p:*")) | table ServiceFileName\n((ServiceFileName="*cmd*" OR ServiceFileName="*comspec*") OR (ServiceFileName="*cmd*" ServiceFileName="*/c*" ServiceFileName="*echo*" ServiceFileName="*\\\\pipe\\*") OR (ServiceFileName="*%COMSPEC%*" ServiceFileName="*/c*" ServiceFileName="*echo*" ServiceFileName="*\\\\pipe\\*") OR (ServiceFileName="*rundll32*" ServiceFileName="*.dll,a*" ServiceFileName="*/p:*")) | table ServiceFileName
```


### logpoint
    
```
(event_source="Microsoft-Windows-Security-Auditing" (ServiceFileName IN ["*cmd*", "*comspec*"] OR (ServiceFileName="*cmd*" ServiceFileName="*/c*" ServiceFileName="*echo*" ServiceFileName="*\\\\pipe\\*") OR (ServiceFileName="*%COMSPEC%*" ServiceFileName="*/c*" ServiceFileName="*echo*" ServiceFileName="*\\\\pipe\\*") OR (ServiceFileName="*rundll32*" ServiceFileName="*.dll,a*" ServiceFileName="*/p:*")))\n(ServiceFileName IN ["*cmd*", "*comspec*"] OR (ServiceFileName="*cmd*" ServiceFileName="*/c*" ServiceFileName="*echo*" ServiceFileName="*\\\\pipe\\*") OR (ServiceFileName="*%COMSPEC%*" ServiceFileName="*/c*" ServiceFileName="*echo*" ServiceFileName="*\\\\pipe\\*") OR (ServiceFileName="*rundll32*" ServiceFileName="*.dll,a*" ServiceFileName="*/p:*"))\n(event_source="Microsoft-Windows-Security-Auditing" (ServiceFileName IN ["*cmd*", "*comspec*"] OR (ServiceFileName="*cmd*" ServiceFileName="*/c*" ServiceFileName="*echo*" ServiceFileName="*\\\\pipe\\*") OR (ServiceFileName="*%COMSPEC%*" ServiceFileName="*/c*" ServiceFileName="*echo*" ServiceFileName="*\\\\pipe\\*") OR (ServiceFileName="*rundll32*" ServiceFileName="*.dll,a*" ServiceFileName="*/p:*")))
```


### grep
    
```
grep -P '^(?:.*(?:.*(?:.*.*cmd.*|.*.*comspec.*)|.*(?:.*(?=.*.*cmd.*)(?=.*.*/c.*)(?=.*.*echo.*)(?=.*.*\\pipe\\.*))|.*(?:.*(?=.*.*%COMSPEC%.*)(?=.*.*/c.*)(?=.*.*echo.*)(?=.*.*\\pipe\\.*))|.*(?:.*(?=.*.*rundll32.*)(?=.*.*\\.dll,a.*)(?=.*.*/p:.*))))'\ngrep -P '^(?:.*(?:.*(?:.*.*cmd.*|.*.*comspec.*)|.*(?:.*(?=.*.*cmd.*)(?=.*.*/c.*)(?=.*.*echo.*)(?=.*.*\\pipe\\.*))|.*(?:.*(?=.*.*%COMSPEC%.*)(?=.*.*/c.*)(?=.*.*echo.*)(?=.*.*\\pipe\\.*))|.*(?:.*(?=.*.*rundll32.*)(?=.*.*\\.dll,a.*)(?=.*.*/p:.*))))'\ngrep -P '^(?:.*(?:.*(?:.*.*cmd.*|.*.*comspec.*)|.*(?:.*(?=.*.*cmd.*)(?=.*.*/c.*)(?=.*.*echo.*)(?=.*.*\\pipe\\.*))|.*(?:.*(?=.*.*%COMSPEC%.*)(?=.*.*/c.*)(?=.*.*echo.*)(?=.*.*\\pipe\\.*))|.*(?:.*(?=.*.*rundll32.*)(?=.*.*\\.dll,a.*)(?=.*.*/p:.*))))'
```



