| Title                    | Direct Autorun Keys Modification       |
|:-------------------------|:------------------|
| **Description**          | Detects direct modification of autostart extensibility point (ASEP) in registry using reg.exe. |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0003: Persistence](https://attack.mitre.org/tactics/TA0003)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1547.001: Registry Run Keys / Startup Folder](https://attack.mitre.org/techniques/T1547/001)</li><li>[T1060: Registry Run Keys / Startup Folder](https://attack.mitre.org/techniques/T1060)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1547.001: Registry Run Keys / Startup Folder](../Triggers/T1547.001.md)</li></ul>  |
| **Severity Level**       | medium |
| **False Positives**      | <ul><li>Legitimate software automatically (mostly, during installation) sets up autorun keys for legitimate reason</li><li>Legitimate administrator sets up autorun keys for legitimate reason</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1060/T1060.yaml](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1060/T1060.yaml)</li></ul>  |
| **Author**               | Victor Sergeev, Daniil Yugoslavskiy, oscd.community |


## Detection Rules

### Sigma rule

```
title: Direct Autorun Keys Modification
id: 24357373-078f-44ed-9ac4-6d334a668a11
description: Detects direct modification of autostart extensibility point (ASEP) in registry using reg.exe.
status: experimental
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1060/T1060.yaml
tags:
    - attack.persistence
    - attack.t1547.001
    - attack.t1060      # an old one
date: 2019/10/25
modified: 2019/11/10
author: Victor Sergeev, Daniil Yugoslavskiy, oscd.community
logsource:
    category: process_creation
    product: windows
detection:
    selection_1:
        Image|endswith: '*\reg.exe'
        CommandLine|contains: 'add' # to avoid intersection with discovery tactic rules
    selection_2:
        CommandLine|contains:       # need to improve this list, there are plenty of ASEP reg keys
            - '\software\Microsoft\Windows\CurrentVersion\Run'
            - '\software\Microsoft\Windows\CurrentVersion\RunOnce'
            - '\software\Microsoft\Windows\CurrentVersion\RunOnceEx'
            - '\software\Microsoft\Windows\CurrentVersion\RunServices'
            - '\software\Microsoft\Windows\CurrentVersion\RunServicesOnce'
            - '\software\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit'
            - '\software\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell'
            - '\software\Microsoft\Windows NT\CurrentVersion\Windows'
            - '\software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders'
            - '\system\CurrentControlSet\Control\SafeBoot\AlternateShell'
    condition: selection_1 and selection_2
fields:
    - CommandLine
    - ParentCommandLine
falsepositives:
    - Legitimate software automatically (mostly, during installation) sets up autorun keys for legitimate reason
    - Legitimate administrator sets up autorun keys for legitimate reason
level: medium

```





### powershell
    
```
Get-WinEvent | where {($_.message -match "Image.*.*\\\\reg.exe" -and $_.message -match "CommandLine.*.*add.*" -and ($_.message -match "CommandLine.*.*\\\\software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run.*" -or $_.message -match "CommandLine.*.*\\\\software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\RunOnce.*" -or $_.message -match "CommandLine.*.*\\\\software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\RunOnceEx.*" -or $_.message -match "CommandLine.*.*\\\\software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\RunServices.*" -or $_.message -match "CommandLine.*.*\\\\software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\RunServicesOnce.*" -or $_.message -match "CommandLine.*.*\\\\software\\\\Microsoft\\\\Windows NT\\\\CurrentVersion\\\\Winlogon\\\\Userinit.*" -or $_.message -match "CommandLine.*.*\\\\software\\\\Microsoft\\\\Windows NT\\\\CurrentVersion\\\\Winlogon\\\\Shell.*" -or $_.message -match "CommandLine.*.*\\\\software\\\\Microsoft\\\\Windows NT\\\\CurrentVersion\\\\Windows.*" -or $_.message -match "CommandLine.*.*\\\\software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Explorer\\\\User Shell Folders.*" -or $_.message -match "CommandLine.*.*\\\\system\\\\CurrentControlSet\\\\Control\\\\SafeBoot\\\\AlternateShell.*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.event_data.Image.keyword:*\\\\reg.exe AND winlog.event_data.CommandLine.keyword:*add* AND winlog.event_data.CommandLine.keyword:(*\\\\software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run* OR *\\\\software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\RunOnce* OR *\\\\software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\RunOnceEx* OR *\\\\software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\RunServices* OR *\\\\software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\RunServicesOnce* OR *\\\\software\\\\Microsoft\\\\Windows\\ NT\\\\CurrentVersion\\\\Winlogon\\\\Userinit* OR *\\\\software\\\\Microsoft\\\\Windows\\ NT\\\\CurrentVersion\\\\Winlogon\\\\Shell* OR *\\\\software\\\\Microsoft\\\\Windows\\ NT\\\\CurrentVersion\\\\Windows* OR *\\\\software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Explorer\\\\User\\ Shell\\ Folders* OR *\\\\system\\\\CurrentControlSet\\\\Control\\\\SafeBoot\\\\AlternateShell*))
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/24357373-078f-44ed-9ac4-6d334a668a11 <<EOF\n{\n  "metadata": {\n    "title": "Direct Autorun Keys Modification",\n    "description": "Detects direct modification of autostart extensibility point (ASEP) in registry using reg.exe.",\n    "tags": [\n      "attack.persistence",\n      "attack.t1547.001",\n      "attack.t1060"\n    ],\n    "query": "(winlog.event_data.Image.keyword:*\\\\\\\\reg.exe AND winlog.event_data.CommandLine.keyword:*add* AND winlog.event_data.CommandLine.keyword:(*\\\\\\\\software\\\\\\\\Microsoft\\\\\\\\Windows\\\\\\\\CurrentVersion\\\\\\\\Run* OR *\\\\\\\\software\\\\\\\\Microsoft\\\\\\\\Windows\\\\\\\\CurrentVersion\\\\\\\\RunOnce* OR *\\\\\\\\software\\\\\\\\Microsoft\\\\\\\\Windows\\\\\\\\CurrentVersion\\\\\\\\RunOnceEx* OR *\\\\\\\\software\\\\\\\\Microsoft\\\\\\\\Windows\\\\\\\\CurrentVersion\\\\\\\\RunServices* OR *\\\\\\\\software\\\\\\\\Microsoft\\\\\\\\Windows\\\\\\\\CurrentVersion\\\\\\\\RunServicesOnce* OR *\\\\\\\\software\\\\\\\\Microsoft\\\\\\\\Windows\\\\ NT\\\\\\\\CurrentVersion\\\\\\\\Winlogon\\\\\\\\Userinit* OR *\\\\\\\\software\\\\\\\\Microsoft\\\\\\\\Windows\\\\ NT\\\\\\\\CurrentVersion\\\\\\\\Winlogon\\\\\\\\Shell* OR *\\\\\\\\software\\\\\\\\Microsoft\\\\\\\\Windows\\\\ NT\\\\\\\\CurrentVersion\\\\\\\\Windows* OR *\\\\\\\\software\\\\\\\\Microsoft\\\\\\\\Windows\\\\\\\\CurrentVersion\\\\\\\\Explorer\\\\\\\\User\\\\ Shell\\\\ Folders* OR *\\\\\\\\system\\\\\\\\CurrentControlSet\\\\\\\\Control\\\\\\\\SafeBoot\\\\\\\\AlternateShell*))"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "(winlog.event_data.Image.keyword:*\\\\\\\\reg.exe AND winlog.event_data.CommandLine.keyword:*add* AND winlog.event_data.CommandLine.keyword:(*\\\\\\\\software\\\\\\\\Microsoft\\\\\\\\Windows\\\\\\\\CurrentVersion\\\\\\\\Run* OR *\\\\\\\\software\\\\\\\\Microsoft\\\\\\\\Windows\\\\\\\\CurrentVersion\\\\\\\\RunOnce* OR *\\\\\\\\software\\\\\\\\Microsoft\\\\\\\\Windows\\\\\\\\CurrentVersion\\\\\\\\RunOnceEx* OR *\\\\\\\\software\\\\\\\\Microsoft\\\\\\\\Windows\\\\\\\\CurrentVersion\\\\\\\\RunServices* OR *\\\\\\\\software\\\\\\\\Microsoft\\\\\\\\Windows\\\\\\\\CurrentVersion\\\\\\\\RunServicesOnce* OR *\\\\\\\\software\\\\\\\\Microsoft\\\\\\\\Windows\\\\ NT\\\\\\\\CurrentVersion\\\\\\\\Winlogon\\\\\\\\Userinit* OR *\\\\\\\\software\\\\\\\\Microsoft\\\\\\\\Windows\\\\ NT\\\\\\\\CurrentVersion\\\\\\\\Winlogon\\\\\\\\Shell* OR *\\\\\\\\software\\\\\\\\Microsoft\\\\\\\\Windows\\\\ NT\\\\\\\\CurrentVersion\\\\\\\\Windows* OR *\\\\\\\\software\\\\\\\\Microsoft\\\\\\\\Windows\\\\\\\\CurrentVersion\\\\\\\\Explorer\\\\\\\\User\\\\ Shell\\\\ Folders* OR *\\\\\\\\system\\\\\\\\CurrentControlSet\\\\\\\\Control\\\\\\\\SafeBoot\\\\\\\\AlternateShell*))",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": [\n          "winlogbeat-*"\n        ]\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "throttle_period": "15m",\n      "email": {\n        "profile": "standard",\n        "from": "root@localhost",\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Direct Autorun Keys Modification\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}Hit on {{_source.@timestamp}}:\\n      CommandLine = {{_source.CommandLine}}\\nParentCommandLine = {{_source.ParentCommandLine}}================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
(Image.keyword:*\\\\reg.exe AND CommandLine.keyword:*add* AND CommandLine.keyword:(*\\\\software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run* *\\\\software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\RunOnce* *\\\\software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\RunOnceEx* *\\\\software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\RunServices* *\\\\software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\RunServicesOnce* *\\\\software\\\\Microsoft\\\\Windows NT\\\\CurrentVersion\\\\Winlogon\\\\Userinit* *\\\\software\\\\Microsoft\\\\Windows NT\\\\CurrentVersion\\\\Winlogon\\\\Shell* *\\\\software\\\\Microsoft\\\\Windows NT\\\\CurrentVersion\\\\Windows* *\\\\software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Explorer\\\\User Shell Folders* *\\\\system\\\\CurrentControlSet\\\\Control\\\\SafeBoot\\\\AlternateShell*))
```


### splunk
    
```
(Image="*\\\\reg.exe" CommandLine="*add*" (CommandLine="*\\\\software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run*" OR CommandLine="*\\\\software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\RunOnce*" OR CommandLine="*\\\\software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\RunOnceEx*" OR CommandLine="*\\\\software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\RunServices*" OR CommandLine="*\\\\software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\RunServicesOnce*" OR CommandLine="*\\\\software\\\\Microsoft\\\\Windows NT\\\\CurrentVersion\\\\Winlogon\\\\Userinit*" OR CommandLine="*\\\\software\\\\Microsoft\\\\Windows NT\\\\CurrentVersion\\\\Winlogon\\\\Shell*" OR CommandLine="*\\\\software\\\\Microsoft\\\\Windows NT\\\\CurrentVersion\\\\Windows*" OR CommandLine="*\\\\software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Explorer\\\\User Shell Folders*" OR CommandLine="*\\\\system\\\\CurrentControlSet\\\\Control\\\\SafeBoot\\\\AlternateShell*")) | table CommandLine,ParentCommandLine
```


### logpoint
    
```
(Image="*\\\\reg.exe" CommandLine="*add*" CommandLine IN ["*\\\\software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run*", "*\\\\software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\RunOnce*", "*\\\\software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\RunOnceEx*", "*\\\\software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\RunServices*", "*\\\\software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\RunServicesOnce*", "*\\\\software\\\\Microsoft\\\\Windows NT\\\\CurrentVersion\\\\Winlogon\\\\Userinit*", "*\\\\software\\\\Microsoft\\\\Windows NT\\\\CurrentVersion\\\\Winlogon\\\\Shell*", "*\\\\software\\\\Microsoft\\\\Windows NT\\\\CurrentVersion\\\\Windows*", "*\\\\software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Explorer\\\\User Shell Folders*", "*\\\\system\\\\CurrentControlSet\\\\Control\\\\SafeBoot\\\\AlternateShell*"])
```


### grep
    
```
grep -P '^(?:.*(?=.*.*\\reg\\.exe)(?=.*.*add.*)(?=.*(?:.*.*\\software\\Microsoft\\Windows\\CurrentVersion\\Run.*|.*.*\\software\\Microsoft\\Windows\\CurrentVersion\\RunOnce.*|.*.*\\software\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx.*|.*.*\\software\\Microsoft\\Windows\\CurrentVersion\\RunServices.*|.*.*\\software\\Microsoft\\Windows\\CurrentVersion\\RunServicesOnce.*|.*.*\\software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Userinit.*|.*.*\\software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Shell.*|.*.*\\software\\Microsoft\\Windows NT\\CurrentVersion\\Windows.*|.*.*\\software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders.*|.*.*\\system\\CurrentControlSet\\Control\\SafeBoot\\AlternateShell.*)))'
```



