| Title                    | Operation Wocao Activity       |
|:-------------------------|:------------------|
| **Description**          | Detects activity mentioned in Operation Wocao report |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0007: Discovery](https://attack.mitre.org/tactics/TA0007)</li><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1012: Query Registry](https://attack.mitre.org/techniques/T1012)</li><li>[T1036.004: Masquerade Task or Service](https://attack.mitre.org/techniques/T1036/004)</li><li>[T1036: Masquerading](https://attack.mitre.org/techniques/T1036)</li><li>[T1027: Obfuscated Files or Information](https://attack.mitre.org/techniques/T1027)</li><li>[T1053.005: Scheduled Task](https://attack.mitre.org/techniques/T1053/005)</li><li>[T1053: Scheduled Task/Job](https://attack.mitre.org/techniques/T1053)</li><li>[T1059.001: PowerShell](https://attack.mitre.org/techniques/T1059/001)</li><li>[T1086: PowerShell](https://attack.mitre.org/techniques/T1086)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1012: Query Registry](../Triggers/T1012.md)</li><li>[T1027: Obfuscated Files or Information](../Triggers/T1027.md)</li><li>[T1053.005: Scheduled Task](../Triggers/T1053.005.md)</li><li>[T1059.001: PowerShell](../Triggers/T1059.001.md)</li></ul>  |
| **Severity Level**       | high |
| **False Positives**      | <ul><li>Administrators that use checkadmin.exe tool to enumerate local administrators</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://www.fox-it.com/en/news/whitepapers/operation-wocao-shining-a-light-on-one-of-chinas-hidden-hacking-groups/](https://www.fox-it.com/en/news/whitepapers/operation-wocao-shining-a-light-on-one-of-chinas-hidden-hacking-groups/)</li><li>[https://twitter.com/SBousseaden/status/1207671369963646976](https://twitter.com/SBousseaden/status/1207671369963646976)</li></ul>  |
| **Author**               | Florian Roth |


## Detection Rules

### Sigma rule

```
action: global
title: Operation Wocao Activity
id: 74ad4314-482e-4c3e-b237-3f7ed3b9ca8d
author: Florian Roth
status: experimental
description: Detects activity mentioned in Operation Wocao report
references:
    - https://www.fox-it.com/en/news/whitepapers/operation-wocao-shining-a-light-on-one-of-chinas-hidden-hacking-groups/
    - https://twitter.com/SBousseaden/status/1207671369963646976
tags:
    - attack.discovery 
    - attack.t1012
    - attack.defense_evasion
    - attack.t1036.004
    - attack.t1036  # an old one
    - attack.t1027
    - attack.execution
    - attack.t1053.005
    - attack.t1053  # an old one
    - attack.t1059.001
    - attack.t1086  # an old one
date: 2019/12/20
modified: 2020/08/26
falsepositives:
    - Administrators that use checkadmin.exe tool to enumerate local administrators
level: high
---
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4799
        GroupName: 'Administrators'
        ProcessName: '*\checkadmin.exe'
    condition: selection
---
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains: 
            - 'checkadmin.exe 127.0.0.1 -all'
            - 'netsh advfirewall firewall add rule name=powershell dir=in'
            - 'cmd /c powershell.exe -ep bypass -file c:\s.ps1'
            - '/tn win32times /f'
            - 'create win32times binPath='
            - '\c$\windows\system32\devmgr.dll'
            - ' -exec bypass -enc JgAg'
            - 'type *keepass\KeePass.config.xml'
            - 'iie.exe iie.txt'
            - 'reg query HKEY_CURRENT_USER\Software\\*\PuTTY\Sessions\'
    condition: selection
```





### powershell
    
```
Get-WinEvent -LogName Security | where {($_.ID -eq "4799" -and $_.message -match "GroupName.*Administrators" -and $_.message -match "ProcessName.*.*\\\\checkadmin.exe") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message\nGet-WinEvent -LogName Security | where {($_.message -match "CommandLine.*.*checkadmin.exe 127.0.0.1 -all.*" -or $_.message -match "CommandLine.*.*netsh advfirewall firewall add rule name=powershell dir=in.*" -or $_.message -match "CommandLine.*.*cmd /c powershell.exe -ep bypass -file c:\\\\s.ps1.*" -or $_.message -match "CommandLine.*.*/tn win32times /f.*" -or $_.message -match "CommandLine.*.*create win32times binPath=.*" -or $_.message -match "CommandLine.*.*\\\\c$\\\\windows\\\\system32\\\\devmgr.dll.*" -or $_.message -match "CommandLine.*.* -exec bypass -enc JgAg.*" -or $_.message -match "CommandLine.*.*type .*keepass\\\\KeePass.config.xml.*" -or $_.message -match "CommandLine.*.*iie.exe iie.txt.*" -or $_.message -match "CommandLine.*.*reg query HKEY_CURRENT_USER\\\\Software\\\\.*\\\\PuTTY\\\\Sessions\\\\.*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.channel:"Security" AND winlog.event_id:"4799" AND winlog.event_data.GroupName:"Administrators" AND winlog.event_data.ProcessName.keyword:*\\\\checkadmin.exe)\nwinlog.event_data.CommandLine.keyword:(*checkadmin.exe\\ 127.0.0.1\\ \\-all* OR *netsh\\ advfirewall\\ firewall\\ add\\ rule\\ name\\=powershell\\ dir\\=in* OR *cmd\\ \\/c\\ powershell.exe\\ \\-ep\\ bypass\\ \\-file\\ c\\:\\\\s.ps1* OR *\\/tn\\ win32times\\ \\/f* OR *create\\ win32times\\ binPath\\=* OR *\\\\c$\\\\windows\\\\system32\\\\devmgr.dll* OR *\\ \\-exec\\ bypass\\ \\-enc\\ JgAg* OR *type\\ *keepass\\\\KeePass.config.xml* OR *iie.exe\\ iie.txt* OR *reg\\ query\\ HKEY_CURRENT_USER\\\\Software\\\\*\\\\PuTTY\\\\Sessions\\\\*)
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/74ad4314-482e-4c3e-b237-3f7ed3b9ca8d <<EOF\n{\n  "metadata": {\n    "title": "Operation Wocao Activity",\n    "description": "Detects activity mentioned in Operation Wocao report",\n    "tags": [\n      "attack.discovery",\n      "attack.t1012",\n      "attack.defense_evasion",\n      "attack.t1036.004",\n      "attack.t1036",\n      "attack.t1027",\n      "attack.execution",\n      "attack.t1053.005",\n      "attack.t1053",\n      "attack.t1059.001",\n      "attack.t1086"\n    ],\n    "query": "(winlog.channel:\\"Security\\" AND winlog.event_id:\\"4799\\" AND winlog.event_data.GroupName:\\"Administrators\\" AND winlog.event_data.ProcessName.keyword:*\\\\\\\\checkadmin.exe)"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "(winlog.channel:\\"Security\\" AND winlog.event_id:\\"4799\\" AND winlog.event_data.GroupName:\\"Administrators\\" AND winlog.event_data.ProcessName.keyword:*\\\\\\\\checkadmin.exe)",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": [\n          "winlogbeat-*"\n        ]\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "throttle_period": "15m",\n      "email": {\n        "profile": "standard",\n        "from": "root@localhost",\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Operation Wocao Activity\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\ncurl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/74ad4314-482e-4c3e-b237-3f7ed3b9ca8d-2 <<EOF\n{\n  "metadata": {\n    "title": "Operation Wocao Activity",\n    "description": "Detects activity mentioned in Operation Wocao report",\n    "tags": [\n      "attack.discovery",\n      "attack.t1012",\n      "attack.defense_evasion",\n      "attack.t1036.004",\n      "attack.t1036",\n      "attack.t1027",\n      "attack.execution",\n      "attack.t1053.005",\n      "attack.t1053",\n      "attack.t1059.001",\n      "attack.t1086"\n    ],\n    "query": "winlog.event_data.CommandLine.keyword:(*checkadmin.exe\\\\ 127.0.0.1\\\\ \\\\-all* OR *netsh\\\\ advfirewall\\\\ firewall\\\\ add\\\\ rule\\\\ name\\\\=powershell\\\\ dir\\\\=in* OR *cmd\\\\ \\\\/c\\\\ powershell.exe\\\\ \\\\-ep\\\\ bypass\\\\ \\\\-file\\\\ c\\\\:\\\\\\\\s.ps1* OR *\\\\/tn\\\\ win32times\\\\ \\\\/f* OR *create\\\\ win32times\\\\ binPath\\\\=* OR *\\\\\\\\c$\\\\\\\\windows\\\\\\\\system32\\\\\\\\devmgr.dll* OR *\\\\ \\\\-exec\\\\ bypass\\\\ \\\\-enc\\\\ JgAg* OR *type\\\\ *keepass\\\\\\\\KeePass.config.xml* OR *iie.exe\\\\ iie.txt* OR *reg\\\\ query\\\\ HKEY_CURRENT_USER\\\\\\\\Software\\\\\\\\*\\\\\\\\PuTTY\\\\\\\\Sessions\\\\\\\\*)"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "winlog.event_data.CommandLine.keyword:(*checkadmin.exe\\\\ 127.0.0.1\\\\ \\\\-all* OR *netsh\\\\ advfirewall\\\\ firewall\\\\ add\\\\ rule\\\\ name\\\\=powershell\\\\ dir\\\\=in* OR *cmd\\\\ \\\\/c\\\\ powershell.exe\\\\ \\\\-ep\\\\ bypass\\\\ \\\\-file\\\\ c\\\\:\\\\\\\\s.ps1* OR *\\\\/tn\\\\ win32times\\\\ \\\\/f* OR *create\\\\ win32times\\\\ binPath\\\\=* OR *\\\\\\\\c$\\\\\\\\windows\\\\\\\\system32\\\\\\\\devmgr.dll* OR *\\\\ \\\\-exec\\\\ bypass\\\\ \\\\-enc\\\\ JgAg* OR *type\\\\ *keepass\\\\\\\\KeePass.config.xml* OR *iie.exe\\\\ iie.txt* OR *reg\\\\ query\\\\ HKEY_CURRENT_USER\\\\\\\\Software\\\\\\\\*\\\\\\\\PuTTY\\\\\\\\Sessions\\\\\\\\*)",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": [\n          "winlogbeat-*"\n        ]\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "throttle_period": "15m",\n      "email": {\n        "profile": "standard",\n        "from": "root@localhost",\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Operation Wocao Activity\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
(EventID:"4799" AND GroupName:"Administrators" AND ProcessName.keyword:*\\\\checkadmin.exe)\nCommandLine.keyword:(*checkadmin.exe 127.0.0.1 \\-all* *netsh advfirewall firewall add rule name=powershell dir=in* *cmd \\/c powershell.exe \\-ep bypass \\-file c\\:\\\\s.ps1* *\\/tn win32times \\/f* *create win32times binPath=* *\\\\c$\\\\windows\\\\system32\\\\devmgr.dll* * \\-exec bypass \\-enc JgAg* *type *keepass\\\\KeePass.config.xml* *iie.exe iie.txt* *reg query HKEY_CURRENT_USER\\\\Software\\\\*\\\\PuTTY\\\\Sessions\\\\*)
```


### splunk
    
```
(source="WinEventLog:Security" EventCode="4799" GroupName="Administrators" ProcessName="*\\\\checkadmin.exe")\n(CommandLine="*checkadmin.exe 127.0.0.1 -all*" OR CommandLine="*netsh advfirewall firewall add rule name=powershell dir=in*" OR CommandLine="*cmd /c powershell.exe -ep bypass -file c:\\\\s.ps1*" OR CommandLine="*/tn win32times /f*" OR CommandLine="*create win32times binPath=*" OR CommandLine="*\\\\c$\\\\windows\\\\system32\\\\devmgr.dll*" OR CommandLine="* -exec bypass -enc JgAg*" OR CommandLine="*type *keepass\\\\KeePass.config.xml*" OR CommandLine="*iie.exe iie.txt*" OR CommandLine="*reg query HKEY_CURRENT_USER\\\\Software\\\\*\\\\PuTTY\\\\Sessions\\\\*")
```


### logpoint
    
```
(event_source="Microsoft-Windows-Security-Auditing" event_id="4799" group_name="Administrators" ProcessName="*\\\\checkadmin.exe")\nCommandLine IN ["*checkadmin.exe 127.0.0.1 -all*", "*netsh advfirewall firewall add rule name=powershell dir=in*", "*cmd /c powershell.exe -ep bypass -file c:\\\\s.ps1*", "*/tn win32times /f*", "*create win32times binPath=*", "*\\\\c$\\\\windows\\\\system32\\\\devmgr.dll*", "* -exec bypass -enc JgAg*", "*type *keepass\\\\KeePass.config.xml*", "*iie.exe iie.txt*", "*reg query HKEY_CURRENT_USER\\\\Software\\\\*\\\\PuTTY\\\\Sessions\\\\*"]
```


### grep
    
```
grep -P '^(?:.*(?=.*4799)(?=.*Administrators)(?=.*.*\\checkadmin\\.exe))'\ngrep -P '^(?:.*.*checkadmin\\.exe 127\\.0\\.0\\.1 -all.*|.*.*netsh advfirewall firewall add rule name=powershell dir=in.*|.*.*cmd /c powershell\\.exe -ep bypass -file c:\\s\\.ps1.*|.*.*/tn win32times /f.*|.*.*create win32times binPath=.*|.*.*\\c\\$\\windows\\system32\\devmgr\\.dll.*|.*.* -exec bypass -enc JgAg.*|.*.*type .*keepass\\KeePass\\.config\\.xml.*|.*.*iie\\.exe iie\\.txt.*|.*.*reg query HKEY_CURRENT_USER\\Software\\\\.*\\PuTTY\\Sessions\\\\.*)'
```



