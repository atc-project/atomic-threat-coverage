| Title                | Sticky Key Like Backdoor Usage                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects the usage and installation of a backdoor that uses an option to register a malicious debugger for built-in tools that are accessible in the login screen                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0004: Privilege Escalation](https://attack.mitre.org/tactics/TA0004)</li><li>[TA0003: Persistence](https://attack.mitre.org/tactics/TA0003)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1015: Accessibility Features](https://attack.mitre.org/techniques/T1015)</li></ul>  |
| Data Needed          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li><li>[DN_0017_13_windows_sysmon_RegistryEvent](../Data_Needed/DN_0017_13_windows_sysmon_RegistryEvent.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1015: Accessibility Features](../Triggers/T1015.md)</li></ul>  |
| Severity Level       | critical |
| False Positives      | <ul><li>Unlikely</li></ul>  |
| Development Status   |  Development Status wasn't defined for this Detection Rule yet  |
| References           | <ul><li>[https://blogs.technet.microsoft.com/jonathantrull/2016/10/03/detecting-sticky-key-backdoors/](https://blogs.technet.microsoft.com/jonathantrull/2016/10/03/detecting-sticky-key-backdoors/)</li></ul>  |
| Author               | Florian Roth, @twjackomo |
| Other Tags           | <ul><li>car.2014-11-003</li><li>car.2014-11-003</li><li>car.2014-11-008</li><li>car.2014-11-008</li></ul> | 

## Detection Rules

### Sigma rule

```
---
action: global
title: Sticky Key Like Backdoor Usage
description: Detects the usage and installation of a backdoor that uses an option to register a malicious debugger for built-in tools that are accessible in the login screen
references:
    - https://blogs.technet.microsoft.com/jonathantrull/2016/10/03/detecting-sticky-key-backdoors/
tags:
    - attack.privilege_escalation
    - attack.persistence
    - attack.t1015
    - car.2014-11-003
    - car.2014-11-008
author: Florian Roth, @twjackomo
date: 2018/03/15
detection:
    condition: 1 of them
falsepositives:
    - Unlikely
level: critical
---
logsource:
    product: windows
    service: sysmon
detection:
    selection_registry:
        EventID: 13
        TargetObject: 
            - '*\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe\Debugger'
            - '*\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\utilman.exe\Debugger'
            - '*\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\osk.exe\Debugger'
            - '*\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\Magnify.exe\Debugger'
            - '*\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\Narrator.exe\Debugger'
            - '*\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\DisplaySwitch.exe\Debugger'
        EventType: 'SetValue'
---
logsource:
    category: process_creation
    product: windows
detection:
    selection_process:
        ParentImage:
            - '*\winlogon.exe'
        CommandLine:
            - '*cmd.exe sethc.exe *'
            - '*cmd.exe utilman.exe *'
            - '*cmd.exe osk.exe *'
            - '*cmd.exe Magnify.exe *'
            - '*cmd.exe Narrator.exe *'
            - '*cmd.exe DisplaySwitch.exe *'

```





### es-qs
    
```
(EventID:"13" AND TargetObject.keyword:(*\\\\SOFTWARE\\\\Microsoft\\\\Windows\\ NT\\\\CurrentVersion\\\\Image\\ File\\ Execution\\ Options\\\\sethc.exe\\\\Debugger *\\\\SOFTWARE\\\\Microsoft\\\\Windows\\ NT\\\\CurrentVersion\\\\Image\\ File\\ Execution\\ Options\\\\utilman.exe\\\\Debugger *\\\\SOFTWARE\\\\Microsoft\\\\Windows\\ NT\\\\CurrentVersion\\\\Image\\ File\\ Execution\\ Options\\\\osk.exe\\\\Debugger *\\\\SOFTWARE\\\\Microsoft\\\\Windows\\ NT\\\\CurrentVersion\\\\Image\\ File\\ Execution\\ Options\\\\Magnify.exe\\\\Debugger *\\\\SOFTWARE\\\\Microsoft\\\\Windows\\ NT\\\\CurrentVersion\\\\Image\\ File\\ Execution\\ Options\\\\Narrator.exe\\\\Debugger *\\\\SOFTWARE\\\\Microsoft\\\\Windows\\ NT\\\\CurrentVersion\\\\Image\\ File\\ Execution\\ Options\\\\DisplaySwitch.exe\\\\Debugger) AND EventType:"SetValue")\n(ParentImage.keyword:(*\\\\winlogon.exe) AND CommandLine.keyword:(*cmd.exe\\ sethc.exe\\ * *cmd.exe\\ utilman.exe\\ * *cmd.exe\\ osk.exe\\ * *cmd.exe\\ Magnify.exe\\ * *cmd.exe\\ Narrator.exe\\ * *cmd.exe\\ DisplaySwitch.exe\\ *))
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/Sticky-Key-Like-Backdoor-Usage <<EOF\n{\n  "metadata": {\n    "title": "Sticky Key Like Backdoor Usage",\n    "description": "Detects the usage and installation of a backdoor that uses an option to register a malicious debugger for built-in tools that are accessible in the login screen",\n    "tags": [\n      "attack.privilege_escalation",\n      "attack.persistence",\n      "attack.t1015",\n      "car.2014-11-003",\n      "car.2014-11-008"\n    ],\n    "query": "(EventID:\\"13\\" AND TargetObject.keyword:(*\\\\\\\\SOFTWARE\\\\\\\\Microsoft\\\\\\\\Windows\\\\ NT\\\\\\\\CurrentVersion\\\\\\\\Image\\\\ File\\\\ Execution\\\\ Options\\\\\\\\sethc.exe\\\\\\\\Debugger *\\\\\\\\SOFTWARE\\\\\\\\Microsoft\\\\\\\\Windows\\\\ NT\\\\\\\\CurrentVersion\\\\\\\\Image\\\\ File\\\\ Execution\\\\ Options\\\\\\\\utilman.exe\\\\\\\\Debugger *\\\\\\\\SOFTWARE\\\\\\\\Microsoft\\\\\\\\Windows\\\\ NT\\\\\\\\CurrentVersion\\\\\\\\Image\\\\ File\\\\ Execution\\\\ Options\\\\\\\\osk.exe\\\\\\\\Debugger *\\\\\\\\SOFTWARE\\\\\\\\Microsoft\\\\\\\\Windows\\\\ NT\\\\\\\\CurrentVersion\\\\\\\\Image\\\\ File\\\\ Execution\\\\ Options\\\\\\\\Magnify.exe\\\\\\\\Debugger *\\\\\\\\SOFTWARE\\\\\\\\Microsoft\\\\\\\\Windows\\\\ NT\\\\\\\\CurrentVersion\\\\\\\\Image\\\\ File\\\\ Execution\\\\ Options\\\\\\\\Narrator.exe\\\\\\\\Debugger *\\\\\\\\SOFTWARE\\\\\\\\Microsoft\\\\\\\\Windows\\\\ NT\\\\\\\\CurrentVersion\\\\\\\\Image\\\\ File\\\\ Execution\\\\ Options\\\\\\\\DisplaySwitch.exe\\\\\\\\Debugger) AND EventType:\\"SetValue\\")"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "(EventID:\\"13\\" AND TargetObject.keyword:(*\\\\\\\\SOFTWARE\\\\\\\\Microsoft\\\\\\\\Windows\\\\ NT\\\\\\\\CurrentVersion\\\\\\\\Image\\\\ File\\\\ Execution\\\\ Options\\\\\\\\sethc.exe\\\\\\\\Debugger *\\\\\\\\SOFTWARE\\\\\\\\Microsoft\\\\\\\\Windows\\\\ NT\\\\\\\\CurrentVersion\\\\\\\\Image\\\\ File\\\\ Execution\\\\ Options\\\\\\\\utilman.exe\\\\\\\\Debugger *\\\\\\\\SOFTWARE\\\\\\\\Microsoft\\\\\\\\Windows\\\\ NT\\\\\\\\CurrentVersion\\\\\\\\Image\\\\ File\\\\ Execution\\\\ Options\\\\\\\\osk.exe\\\\\\\\Debugger *\\\\\\\\SOFTWARE\\\\\\\\Microsoft\\\\\\\\Windows\\\\ NT\\\\\\\\CurrentVersion\\\\\\\\Image\\\\ File\\\\ Execution\\\\ Options\\\\\\\\Magnify.exe\\\\\\\\Debugger *\\\\\\\\SOFTWARE\\\\\\\\Microsoft\\\\\\\\Windows\\\\ NT\\\\\\\\CurrentVersion\\\\\\\\Image\\\\ File\\\\ Execution\\\\ Options\\\\\\\\Narrator.exe\\\\\\\\Debugger *\\\\\\\\SOFTWARE\\\\\\\\Microsoft\\\\\\\\Windows\\\\ NT\\\\\\\\CurrentVersion\\\\\\\\Image\\\\ File\\\\ Execution\\\\ Options\\\\\\\\DisplaySwitch.exe\\\\\\\\Debugger) AND EventType:\\"SetValue\\")",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Sticky Key Like Backdoor Usage\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\ncurl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/Sticky-Key-Like-Backdoor-Usage-2 <<EOF\n{\n  "metadata": {\n    "title": "Sticky Key Like Backdoor Usage",\n    "description": "Detects the usage and installation of a backdoor that uses an option to register a malicious debugger for built-in tools that are accessible in the login screen",\n    "tags": [\n      "attack.privilege_escalation",\n      "attack.persistence",\n      "attack.t1015",\n      "car.2014-11-003",\n      "car.2014-11-008"\n    ],\n    "query": "(ParentImage.keyword:(*\\\\\\\\winlogon.exe) AND CommandLine.keyword:(*cmd.exe\\\\ sethc.exe\\\\ * *cmd.exe\\\\ utilman.exe\\\\ * *cmd.exe\\\\ osk.exe\\\\ * *cmd.exe\\\\ Magnify.exe\\\\ * *cmd.exe\\\\ Narrator.exe\\\\ * *cmd.exe\\\\ DisplaySwitch.exe\\\\ *))"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "(ParentImage.keyword:(*\\\\\\\\winlogon.exe) AND CommandLine.keyword:(*cmd.exe\\\\ sethc.exe\\\\ * *cmd.exe\\\\ utilman.exe\\\\ * *cmd.exe\\\\ osk.exe\\\\ * *cmd.exe\\\\ Magnify.exe\\\\ * *cmd.exe\\\\ Narrator.exe\\\\ * *cmd.exe\\\\ DisplaySwitch.exe\\\\ *))",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Sticky Key Like Backdoor Usage\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
(EventID:"13" AND TargetObject:("*\\\\SOFTWARE\\\\Microsoft\\\\Windows NT\\\\CurrentVersion\\\\Image File Execution Options\\\\sethc.exe\\\\Debugger" "*\\\\SOFTWARE\\\\Microsoft\\\\Windows NT\\\\CurrentVersion\\\\Image File Execution Options\\\\utilman.exe\\\\Debugger" "*\\\\SOFTWARE\\\\Microsoft\\\\Windows NT\\\\CurrentVersion\\\\Image File Execution Options\\\\osk.exe\\\\Debugger" "*\\\\SOFTWARE\\\\Microsoft\\\\Windows NT\\\\CurrentVersion\\\\Image File Execution Options\\\\Magnify.exe\\\\Debugger" "*\\\\SOFTWARE\\\\Microsoft\\\\Windows NT\\\\CurrentVersion\\\\Image File Execution Options\\\\Narrator.exe\\\\Debugger" "*\\\\SOFTWARE\\\\Microsoft\\\\Windows NT\\\\CurrentVersion\\\\Image File Execution Options\\\\DisplaySwitch.exe\\\\Debugger") AND EventType:"SetValue")\n(ParentImage:("*\\\\winlogon.exe") AND CommandLine:("*cmd.exe sethc.exe *" "*cmd.exe utilman.exe *" "*cmd.exe osk.exe *" "*cmd.exe Magnify.exe *" "*cmd.exe Narrator.exe *" "*cmd.exe DisplaySwitch.exe *"))
```


### splunk
    
```
(EventID="13" (TargetObject="*\\\\SOFTWARE\\\\Microsoft\\\\Windows NT\\\\CurrentVersion\\\\Image File Execution Options\\\\sethc.exe\\\\Debugger" OR TargetObject="*\\\\SOFTWARE\\\\Microsoft\\\\Windows NT\\\\CurrentVersion\\\\Image File Execution Options\\\\utilman.exe\\\\Debugger" OR TargetObject="*\\\\SOFTWARE\\\\Microsoft\\\\Windows NT\\\\CurrentVersion\\\\Image File Execution Options\\\\osk.exe\\\\Debugger" OR TargetObject="*\\\\SOFTWARE\\\\Microsoft\\\\Windows NT\\\\CurrentVersion\\\\Image File Execution Options\\\\Magnify.exe\\\\Debugger" OR TargetObject="*\\\\SOFTWARE\\\\Microsoft\\\\Windows NT\\\\CurrentVersion\\\\Image File Execution Options\\\\Narrator.exe\\\\Debugger" OR TargetObject="*\\\\SOFTWARE\\\\Microsoft\\\\Windows NT\\\\CurrentVersion\\\\Image File Execution Options\\\\DisplaySwitch.exe\\\\Debugger") EventType="SetValue")\n((ParentImage="*\\\\winlogon.exe") (CommandLine="*cmd.exe sethc.exe *" OR CommandLine="*cmd.exe utilman.exe *" OR CommandLine="*cmd.exe osk.exe *" OR CommandLine="*cmd.exe Magnify.exe *" OR CommandLine="*cmd.exe Narrator.exe *" OR CommandLine="*cmd.exe DisplaySwitch.exe *"))
```


### logpoint
    
```
(EventID="13" TargetObject IN ["*\\\\SOFTWARE\\\\Microsoft\\\\Windows NT\\\\CurrentVersion\\\\Image File Execution Options\\\\sethc.exe\\\\Debugger", "*\\\\SOFTWARE\\\\Microsoft\\\\Windows NT\\\\CurrentVersion\\\\Image File Execution Options\\\\utilman.exe\\\\Debugger", "*\\\\SOFTWARE\\\\Microsoft\\\\Windows NT\\\\CurrentVersion\\\\Image File Execution Options\\\\osk.exe\\\\Debugger", "*\\\\SOFTWARE\\\\Microsoft\\\\Windows NT\\\\CurrentVersion\\\\Image File Execution Options\\\\Magnify.exe\\\\Debugger", "*\\\\SOFTWARE\\\\Microsoft\\\\Windows NT\\\\CurrentVersion\\\\Image File Execution Options\\\\Narrator.exe\\\\Debugger", "*\\\\SOFTWARE\\\\Microsoft\\\\Windows NT\\\\CurrentVersion\\\\Image File Execution Options\\\\DisplaySwitch.exe\\\\Debugger"] EventType="SetValue")\n(ParentImage IN ["*\\\\winlogon.exe"] CommandLine IN ["*cmd.exe sethc.exe *", "*cmd.exe utilman.exe *", "*cmd.exe osk.exe *", "*cmd.exe Magnify.exe *", "*cmd.exe Narrator.exe *", "*cmd.exe DisplaySwitch.exe *"])
```


### grep
    
```
grep -P '^(?:.*(?=.*13)(?=.*(?:.*.*\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\sethc\\.exe\\Debugger|.*.*\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\utilman\\.exe\\Debugger|.*.*\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\osk\\.exe\\Debugger|.*.*\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\Magnify\\.exe\\Debugger|.*.*\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\Narrator\\.exe\\Debugger|.*.*\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\DisplaySwitch\\.exe\\Debugger))(?=.*SetValue))'\ngrep -P '^(?:.*(?=.*(?:.*.*\\winlogon\\.exe))(?=.*(?:.*.*cmd\\.exe sethc\\.exe .*|.*.*cmd\\.exe utilman\\.exe .*|.*.*cmd\\.exe osk\\.exe .*|.*.*cmd\\.exe Magnify\\.exe .*|.*.*cmd\\.exe Narrator\\.exe .*|.*.*cmd\\.exe DisplaySwitch\\.exe .*)))'
```



