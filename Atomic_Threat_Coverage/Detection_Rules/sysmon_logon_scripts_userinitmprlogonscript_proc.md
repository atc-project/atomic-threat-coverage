| Title                    | Logon Scripts (UserInitMprLogonScript)       |
|:-------------------------|:------------------|
| **Description**          | Detects creation or execution of UserInitMprLogonScript persistence method |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0003: Persistence](https://attack.mitre.org/tactics/TA0003)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1037: Boot or Logon Initialization Scripts](https://attack.mitre.org/techniques/T1037)</li><li>[T1037.001: Logon Script (Windows)](https://attack.mitre.org/techniques/T1037.001)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1037.001: Logon Script (Windows)](../Triggers/T1037.001.md)</li></ul>  |
| **Severity Level**       | high |
| **False Positives**      | <ul><li>exclude legitimate logon scripts</li><li>penetration tests, red teaming</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://attack.mitre.org/techniques/T1037/](https://attack.mitre.org/techniques/T1037/)</li></ul>  |
| **Author**               | Tom Ueltschi (@c_APT_ure) |


## Detection Rules

### Sigma rule

```
title: Logon Scripts (UserInitMprLogonScript)
id: 0a98a10c-685d-4ab0-bddc-b6bdd1d48458
status: experimental
description: Detects creation or execution of UserInitMprLogonScript persistence method
references:
    - https://attack.mitre.org/techniques/T1037/
tags:
    - attack.t1037 # an old one
    - attack.t1037.001
    - attack.persistence
author: Tom Ueltschi (@c_APT_ure)
date: 2019/01/12
modified: 2020/08/26
logsource:
    category: process_creation
    product: windows
detection:
    exec_selection:
        ParentImage: '*\userinit.exe'
    exec_exclusion1:
        Image: '*\explorer.exe'
    exec_exclusion2:
        CommandLine|contains:
            - 'netlogon.bat'
            - 'UsrLogon.cmd'
    create_keywords_cli:
        CommandLine: '*UserInitMprLogonScript*'
    condition: ( exec_selection and not exec_exclusion1 and not exec_exclusion2 ) or create_keywords_cli
falsepositives:
    - exclude legitimate logon scripts
    - penetration tests, red teaming
level: high
```





### powershell
    
```
Get-WinEvent | where {((($_.message -match "ParentImage.*.*\\\\userinit.exe" -and  -not ($_.message -match "Image.*.*\\\\explorer.exe")) -and  -not (($_.message -match "CommandLine.*.*netlogon.bat.*" -or $_.message -match "CommandLine.*.*UsrLogon.cmd.*"))) -or $_.message -match "CommandLine.*.*UserInitMprLogonScript.*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(((winlog.event_data.ParentImage.keyword:*\\\\userinit.exe AND (NOT (winlog.event_data.Image.keyword:*\\\\explorer.exe))) AND (NOT (winlog.event_data.CommandLine.keyword:(*netlogon.bat* OR *UsrLogon.cmd*)))) OR winlog.event_data.CommandLine.keyword:*UserInitMprLogonScript*)
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/0a98a10c-685d-4ab0-bddc-b6bdd1d48458 <<EOF\n{\n  "metadata": {\n    "title": "Logon Scripts (UserInitMprLogonScript)",\n    "description": "Detects creation or execution of UserInitMprLogonScript persistence method",\n    "tags": [\n      "attack.t1037",\n      "attack.t1037.001",\n      "attack.persistence"\n    ],\n    "query": "(((winlog.event_data.ParentImage.keyword:*\\\\\\\\userinit.exe AND (NOT (winlog.event_data.Image.keyword:*\\\\\\\\explorer.exe))) AND (NOT (winlog.event_data.CommandLine.keyword:(*netlogon.bat* OR *UsrLogon.cmd*)))) OR winlog.event_data.CommandLine.keyword:*UserInitMprLogonScript*)"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "(((winlog.event_data.ParentImage.keyword:*\\\\\\\\userinit.exe AND (NOT (winlog.event_data.Image.keyword:*\\\\\\\\explorer.exe))) AND (NOT (winlog.event_data.CommandLine.keyword:(*netlogon.bat* OR *UsrLogon.cmd*)))) OR winlog.event_data.CommandLine.keyword:*UserInitMprLogonScript*)",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": [\n          "winlogbeat-*"\n        ]\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "throttle_period": "15m",\n      "email": {\n        "profile": "standard",\n        "from": "root@localhost",\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Logon Scripts (UserInitMprLogonScript)\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
(((ParentImage.keyword:*\\\\userinit.exe AND (NOT (Image.keyword:*\\\\explorer.exe))) AND (NOT (CommandLine.keyword:(*netlogon.bat* *UsrLogon.cmd*)))) OR CommandLine.keyword:*UserInitMprLogonScript*)
```


### splunk
    
```
(((ParentImage="*\\\\userinit.exe" NOT (Image="*\\\\explorer.exe")) NOT ((CommandLine="*netlogon.bat*" OR CommandLine="*UsrLogon.cmd*"))) OR CommandLine="*UserInitMprLogonScript*")
```


### logpoint
    
```
(((ParentImage="*\\\\userinit.exe"  -(Image="*\\\\explorer.exe"))  -(CommandLine IN ["*netlogon.bat*", "*UsrLogon.cmd*"])) OR CommandLine="*UserInitMprLogonScript*")
```


### grep
    
```
grep -P '^(?:.*(?:.*(?:.*(?=.*(?:.*(?=.*.*\\userinit\\.exe)(?=.*(?!.*(?:.*(?=.*.*\\explorer\\.exe))))))(?=.*(?!.*(?:.*(?=.*(?:.*.*netlogon\\.bat.*|.*.*UsrLogon\\.cmd.*))))))|.*.*UserInitMprLogonScript.*))'
```



