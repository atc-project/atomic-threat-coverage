| Title                    | Baby Shark Activity       |
|:-------------------------|:------------------|
| **Description**          | Detects activity that could be related to Baby Shark malware |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li><li>[TA0007: Discovery](https://attack.mitre.org/tactics/TA0007)</li><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1059: Command and Scripting Interpreter](https://attack.mitre.org/techniques/T1059)</li><li>[T1086: PowerShell](https://attack.mitre.org/techniques/T1086)</li><li>[T1059.003: Windows Command Shell](https://attack.mitre.org/techniques/T1059/003)</li><li>[T1059.001: PowerShell](https://attack.mitre.org/techniques/T1059/001)</li><li>[T1012: Query Registry](https://attack.mitre.org/techniques/T1012)</li><li>[T1170: Mshta](https://attack.mitre.org/techniques/T1170)</li><li>[T1218: Signed Binary Proxy Execution](https://attack.mitre.org/techniques/T1218)</li><li>[T1218.005: Mshta](https://attack.mitre.org/techniques/T1218/005)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1059.003: Windows Command Shell](../Triggers/T1059.003.md)</li><li>[T1059.001: PowerShell](../Triggers/T1059.001.md)</li><li>[T1012: Query Registry](../Triggers/T1012.md)</li><li>[T1218: Signed Binary Proxy Execution](../Triggers/T1218.md)</li><li>[T1218.005: Mshta](../Triggers/T1218.005.md)</li></ul>  |
| **Severity Level**       | high |
| **False Positives**      | <ul><li>unknown</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://unit42.paloaltonetworks.com/new-babyshark-malware-targets-u-s-national-security-think-tanks/](https://unit42.paloaltonetworks.com/new-babyshark-malware-targets-u-s-national-security-think-tanks/)</li></ul>  |
| **Author**               | Florian Roth |


## Detection Rules

### Sigma rule

```
title: Baby Shark Activity
id: 2b30fa36-3a18-402f-a22d-bf4ce2189f35
status: experimental
description: Detects activity that could be related to Baby Shark malware
references:
    - https://unit42.paloaltonetworks.com/new-babyshark-malware-targets-u-s-national-security-think-tanks/
tags:
    - attack.execution
    - attack.t1059 # an old one
    - attack.t1086 # an old one
    - attack.t1059.003
    - attack.t1059.001
    - attack.discovery
    - attack.t1012
    - attack.defense_evasion
    - attack.t1170 # an old one
    - attack.t1218 # an old one
    - attack.t1218.005
logsource:
    category: process_creation
    product: windows
author: Florian Roth
date: 2019/02/24
modified: 2020/08/26
detection:
    selection:
        CommandLine:
            - reg query "HKEY_CURRENT_USER\Software\Microsoft\Terminal Server Client\Default"
            - powershell.exe mshta.exe http*
            - cmd.exe /c taskkill /im cmd.exe
    condition: selection
falsepositives:
    - unknown
level: high

```





### powershell
    
```
Get-WinEvent | where {($_.message -match "reg query \\"HKEY_CURRENT_USER\\\\Software\\\\Microsoft\\\\Terminal Server Client\\\\Default\\"" -or $_.message -match "CommandLine.*powershell.exe mshta.exe http.*" -or $_.message -match "cmd.exe /c taskkill /im cmd.exe") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
winlog.event_data.CommandLine.keyword:(reg\\ query\\ \\"HKEY_CURRENT_USER\\\\Software\\\\Microsoft\\\\Terminal\\ Server\\ Client\\\\Default\\" OR powershell.exe\\ mshta.exe\\ http* OR cmd.exe\\ \\/c\\ taskkill\\ \\/im\\ cmd.exe)
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/2b30fa36-3a18-402f-a22d-bf4ce2189f35 <<EOF\n{\n  "metadata": {\n    "title": "Baby Shark Activity",\n    "description": "Detects activity that could be related to Baby Shark malware",\n    "tags": [\n      "attack.execution",\n      "attack.t1059",\n      "attack.t1086",\n      "attack.t1059.003",\n      "attack.t1059.001",\n      "attack.discovery",\n      "attack.t1012",\n      "attack.defense_evasion",\n      "attack.t1170",\n      "attack.t1218",\n      "attack.t1218.005"\n    ],\n    "query": "winlog.event_data.CommandLine.keyword:(reg\\\\ query\\\\ \\\\\\"HKEY_CURRENT_USER\\\\\\\\Software\\\\\\\\Microsoft\\\\\\\\Terminal\\\\ Server\\\\ Client\\\\\\\\Default\\\\\\" OR powershell.exe\\\\ mshta.exe\\\\ http* OR cmd.exe\\\\ \\\\/c\\\\ taskkill\\\\ \\\\/im\\\\ cmd.exe)"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "winlog.event_data.CommandLine.keyword:(reg\\\\ query\\\\ \\\\\\"HKEY_CURRENT_USER\\\\\\\\Software\\\\\\\\Microsoft\\\\\\\\Terminal\\\\ Server\\\\ Client\\\\\\\\Default\\\\\\" OR powershell.exe\\\\ mshta.exe\\\\ http* OR cmd.exe\\\\ \\\\/c\\\\ taskkill\\\\ \\\\/im\\\\ cmd.exe)",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": [\n          "winlogbeat-*"\n        ]\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "throttle_period": "15m",\n      "email": {\n        "profile": "standard",\n        "from": "root@localhost",\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Baby Shark Activity\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
CommandLine.keyword:(reg query \\"HKEY_CURRENT_USER\\\\Software\\\\Microsoft\\\\Terminal Server Client\\\\Default\\" powershell.exe mshta.exe http* cmd.exe \\/c taskkill \\/im cmd.exe)
```


### splunk
    
```
(CommandLine="reg query \\"HKEY_CURRENT_USER\\\\Software\\\\Microsoft\\\\Terminal Server Client\\\\Default\\"" OR CommandLine="powershell.exe mshta.exe http*" OR CommandLine="cmd.exe /c taskkill /im cmd.exe")
```


### logpoint
    
```
CommandLine IN ["reg query \\"HKEY_CURRENT_USER\\\\Software\\\\Microsoft\\\\Terminal Server Client\\\\Default\\"", "powershell.exe mshta.exe http*", "cmd.exe /c taskkill /im cmd.exe"]
```


### grep
    
```
grep -P \'^(?:.*reg query "HKEY_CURRENT_USER\\Software\\Microsoft\\Terminal Server Client\\Default"|.*powershell\\.exe mshta\\.exe http.*|.*cmd\\.exe /c taskkill /im cmd\\.exe)\'
```



