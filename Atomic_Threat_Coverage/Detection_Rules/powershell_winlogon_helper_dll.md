| Title                    | Winlogon Helper DLL       |
|:-------------------------|:------------------|
| **Description**          | Winlogon.exe is a Windows component responsible for actions at logon/logoff as well as the secure attention sequence (SAS) triggered by Ctrl-Alt-Delete. Registry entries in HKLM\Software[Wow6432Node]Microsoft\Windows NT\CurrentVersion\Winlogon\ and HKCU\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\ are used to manage additional helper programs and functionalities that support Winlogon. Malicious modifications to these Registry keys may cause Winlogon to load and execute malicious DLLs and/or executables. |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0003: Persistence](https://attack.mitre.org/tactics/TA0003)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1547.004: Winlogon Helper DLL](https://attack.mitre.org/techniques/T1547.004)</li><li>[T1004: Winlogon Helper DLL](https://attack.mitre.org/techniques/T1004)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0036_4104_windows_powershell_script_block](../Data_Needed/DN_0036_4104_windows_powershell_script_block.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1547.004: Winlogon Helper DLL](../Triggers/T1547.004.md)</li></ul>  |
| **Severity Level**       | medium |
| **False Positives**      | <ul><li>Unknown</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1004/T1004.yaml](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1004/T1004.yaml)</li></ul>  |
| **Author**               | Timur Zinniatullin, oscd.community |


## Detection Rules

### Sigma rule

```
title: Winlogon Helper DLL
id: 851c506b-6b7c-4ce2-8802-c703009d03c0
status: experimental
description: Winlogon.exe is a Windows component responsible for actions at logon/logoff as well as the secure attention sequence (SAS) triggered by Ctrl-Alt-Delete. Registry entries in HKLM\Software[Wow6432Node]Microsoft\Windows NT\CurrentVersion\Winlogon\ and HKCU\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\ are used to manage additional helper programs and functionalities that support Winlogon. Malicious modifications to these Registry keys may cause Winlogon to load and execute malicious DLLs and/or executables.
author: Timur Zinniatullin, oscd.community
date: 2019/10/21
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1004/T1004.yaml
logsource:
    product: windows
    service: powershell
    definition: 'Script block logging must be enabled'
detection:
    selection:
        EventID: 4104
    keyword1:
        - '*Set-ItemProperty*'
        - '*New-Item*'
    keyword2:
        - '*CurrentVersion\Winlogon*'
    condition: selection and ( keyword1 and keyword2 )
falsepositives:
    - Unknown
level: medium
tags:
    - attack.persistence
    - attack.t1547.004
    - attack.t1004  # an old one

```





### powershell
    
```
Get-WinEvent -LogName Microsoft-Windows-PowerShell/Operational | where {($_.ID -eq "4104" -and ($_.message -match "*Set-ItemProperty*" -or $_.message -match "*New-Item*") -and $_.message -match "*CurrentVersion\\Winlogon*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.event_id:"4104" AND \\*.keyword:(*Set\\-ItemProperty* OR *New\\-Item*) AND "*CurrentVersion\\\\Winlogon*")
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/851c506b-6b7c-4ce2-8802-c703009d03c0 <<EOF\n{\n  "metadata": {\n    "title": "Winlogon Helper DLL",\n    "description": "Winlogon.exe is a Windows component responsible for actions at logon/logoff as well as the secure attention sequence (SAS) triggered by Ctrl-Alt-Delete. Registry entries in HKLM\\\\Software[Wow6432Node]Microsoft\\\\Windows NT\\\\CurrentVersion\\\\Winlogon\\\\ and HKCU\\\\Software\\\\Microsoft\\\\Windows NT\\\\CurrentVersion\\\\Winlogon\\\\ are used to manage additional helper programs and functionalities that support Winlogon. Malicious modifications to these Registry keys may cause Winlogon to load and execute malicious DLLs and/or executables.",\n    "tags": [\n      "attack.persistence",\n      "attack.t1547.004",\n      "attack.t1004"\n    ],\n    "query": "(winlog.event_id:\\"4104\\" AND \\\\*.keyword:(*Set\\\\-ItemProperty* OR *New\\\\-Item*) AND \\"*CurrentVersion\\\\\\\\Winlogon*\\")"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "(winlog.event_id:\\"4104\\" AND \\\\*.keyword:(*Set\\\\-ItemProperty* OR *New\\\\-Item*) AND \\"*CurrentVersion\\\\\\\\Winlogon*\\")",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": [\n          "winlogbeat-*"\n        ]\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "throttle_period": "15m",\n      "email": {\n        "profile": "standard",\n        "from": "root@localhost",\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Winlogon Helper DLL\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
(EventID:"4104" AND \\*.keyword:(*Set\\-ItemProperty* OR *New\\-Item*) AND "*CurrentVersion\\\\Winlogon*")
```


### splunk
    
```
(source="WinEventLog:Microsoft-Windows-PowerShell/Operational" EventCode="4104" ("*Set-ItemProperty*" OR "*New-Item*") "*CurrentVersion\\\\Winlogon*")
```


### logpoint
    
```
(event_id="4104" ("*Set-ItemProperty*" OR "*New-Item*") "*CurrentVersion\\\\Winlogon*")
```


### grep
    
```
grep -P '^(?:.*(?=.*4104)(?=.*(?:.*(?:.*.*Set-ItemProperty.*|.*.*New-Item.*)))(?=.*.*CurrentVersion\\Winlogon.*))'
```



