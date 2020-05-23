| Title                    | Malicious PowerShell Keywords       |
|:-------------------------|:------------------|
| **Description**          | Detects keywords from well-known PowerShell exploitation frameworks |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1086: PowerShell](https://attack.mitre.org/techniques/T1086)</li></ul>  |
| **Data Needed**          |  There is no documented Data Needed for this Detection Rule yet  |
| **Trigger**              | <ul><li>[T1086: PowerShell](../Triggers/T1086.md)</li></ul>  |
| **Severity Level**       | high |
| **False Positives**      | <ul><li>Penetration tests</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://adsecurity.org/?p=2921](https://adsecurity.org/?p=2921)</li></ul>  |
| **Author**               | Sean Metcalf (source), Florian Roth (rule) |


## Detection Rules

### Sigma rule

```
title: Malicious PowerShell Keywords
id: f62176f3-8128-4faa-bf6c-83261322e5eb
status: experimental
description: Detects keywords from well-known PowerShell exploitation frameworks
modified: 2019/01/22
references:
    - https://adsecurity.org/?p=2921
tags:
    - attack.execution
    - attack.t1086
author: Sean Metcalf (source), Florian Roth (rule)
date: 2017/03/05
logsource:
    product: windows
    service: powershell
    definition: 'It is recommended to use the new "Script Block Logging" of PowerShell v5 https://adsecurity.org/?p=2277'
detection:
    keywords:
        Message:
            - "*AdjustTokenPrivileges*"
            - "*IMAGE_NT_OPTIONAL_HDR64_MAGIC*"
            - "*Microsoft.Win32.UnsafeNativeMethods*"
            - "*ReadProcessMemory.Invoke*"
            - "*SE_PRIVILEGE_ENABLED*"
            - "*LSA_UNICODE_STRING*"
            - "*MiniDumpWriteDump*"
            - "*PAGE_EXECUTE_READ*"
            - "*SECURITY_DELEGATION*"
            - "*TOKEN_ADJUST_PRIVILEGES*"
            - "*TOKEN_ALL_ACCESS*"
            - "*TOKEN_ASSIGN_PRIMARY*"
            - "*TOKEN_DUPLICATE*"
            - "*TOKEN_ELEVATION*"
            - "*TOKEN_IMPERSONATE*"
            - "*TOKEN_INFORMATION_CLASS*"
            - "*TOKEN_PRIVILEGES*"
            - "*TOKEN_QUERY*"
            - "*Metasploit*"
            - "*Mimikatz*"
    condition: keywords
falsepositives:
    - Penetration tests
level: high

```





### powershell
    
```
Get-WinEvent -LogName Microsoft-Windows-PowerShell/Operational | where {(($_.message -match "Message.*.*AdjustTokenPrivileges.*" -or $_.message -match "Message.*.*IMAGE_NT_OPTIONAL_HDR64_MAGIC.*" -or $_.message -match "Message.*.*Microsoft.Win32.UnsafeNativeMethods.*" -or $_.message -match "Message.*.*ReadProcessMemory.Invoke.*" -or $_.message -match "Message.*.*SE_PRIVILEGE_ENABLED.*" -or $_.message -match "Message.*.*LSA_UNICODE_STRING.*" -or $_.message -match "Message.*.*MiniDumpWriteDump.*" -or $_.message -match "Message.*.*PAGE_EXECUTE_READ.*" -or $_.message -match "Message.*.*SECURITY_DELEGATION.*" -or $_.message -match "Message.*.*TOKEN_ADJUST_PRIVILEGES.*" -or $_.message -match "Message.*.*TOKEN_ALL_ACCESS.*" -or $_.message -match "Message.*.*TOKEN_ASSIGN_PRIMARY.*" -or $_.message -match "Message.*.*TOKEN_DUPLICATE.*" -or $_.message -match "Message.*.*TOKEN_ELEVATION.*" -or $_.message -match "Message.*.*TOKEN_IMPERSONATE.*" -or $_.message -match "Message.*.*TOKEN_INFORMATION_CLASS.*" -or $_.message -match "Message.*.*TOKEN_PRIVILEGES.*" -or $_.message -match "Message.*.*TOKEN_QUERY.*" -or $_.message -match "Message.*.*Metasploit.*" -or $_.message -match "Message.*.*Mimikatz.*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
winlog.event_data.Message.keyword:(*AdjustTokenPrivileges* OR *IMAGE_NT_OPTIONAL_HDR64_MAGIC* OR *Microsoft.Win32.UnsafeNativeMethods* OR *ReadProcessMemory.Invoke* OR *SE_PRIVILEGE_ENABLED* OR *LSA_UNICODE_STRING* OR *MiniDumpWriteDump* OR *PAGE_EXECUTE_READ* OR *SECURITY_DELEGATION* OR *TOKEN_ADJUST_PRIVILEGES* OR *TOKEN_ALL_ACCESS* OR *TOKEN_ASSIGN_PRIMARY* OR *TOKEN_DUPLICATE* OR *TOKEN_ELEVATION* OR *TOKEN_IMPERSONATE* OR *TOKEN_INFORMATION_CLASS* OR *TOKEN_PRIVILEGES* OR *TOKEN_QUERY* OR *Metasploit* OR *Mimikatz*)
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/f62176f3-8128-4faa-bf6c-83261322e5eb <<EOF\n{\n  "metadata": {\n    "title": "Malicious PowerShell Keywords",\n    "description": "Detects keywords from well-known PowerShell exploitation frameworks",\n    "tags": [\n      "attack.execution",\n      "attack.t1086"\n    ],\n    "query": "winlog.event_data.Message.keyword:(*AdjustTokenPrivileges* OR *IMAGE_NT_OPTIONAL_HDR64_MAGIC* OR *Microsoft.Win32.UnsafeNativeMethods* OR *ReadProcessMemory.Invoke* OR *SE_PRIVILEGE_ENABLED* OR *LSA_UNICODE_STRING* OR *MiniDumpWriteDump* OR *PAGE_EXECUTE_READ* OR *SECURITY_DELEGATION* OR *TOKEN_ADJUST_PRIVILEGES* OR *TOKEN_ALL_ACCESS* OR *TOKEN_ASSIGN_PRIMARY* OR *TOKEN_DUPLICATE* OR *TOKEN_ELEVATION* OR *TOKEN_IMPERSONATE* OR *TOKEN_INFORMATION_CLASS* OR *TOKEN_PRIVILEGES* OR *TOKEN_QUERY* OR *Metasploit* OR *Mimikatz*)"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "winlog.event_data.Message.keyword:(*AdjustTokenPrivileges* OR *IMAGE_NT_OPTIONAL_HDR64_MAGIC* OR *Microsoft.Win32.UnsafeNativeMethods* OR *ReadProcessMemory.Invoke* OR *SE_PRIVILEGE_ENABLED* OR *LSA_UNICODE_STRING* OR *MiniDumpWriteDump* OR *PAGE_EXECUTE_READ* OR *SECURITY_DELEGATION* OR *TOKEN_ADJUST_PRIVILEGES* OR *TOKEN_ALL_ACCESS* OR *TOKEN_ASSIGN_PRIMARY* OR *TOKEN_DUPLICATE* OR *TOKEN_ELEVATION* OR *TOKEN_IMPERSONATE* OR *TOKEN_INFORMATION_CLASS* OR *TOKEN_PRIVILEGES* OR *TOKEN_QUERY* OR *Metasploit* OR *Mimikatz*)",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": [\n          "winlogbeat-*"\n        ]\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Malicious PowerShell Keywords\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
Message.keyword:(*AdjustTokenPrivileges* *IMAGE_NT_OPTIONAL_HDR64_MAGIC* *Microsoft.Win32.UnsafeNativeMethods* *ReadProcessMemory.Invoke* *SE_PRIVILEGE_ENABLED* *LSA_UNICODE_STRING* *MiniDumpWriteDump* *PAGE_EXECUTE_READ* *SECURITY_DELEGATION* *TOKEN_ADJUST_PRIVILEGES* *TOKEN_ALL_ACCESS* *TOKEN_ASSIGN_PRIMARY* *TOKEN_DUPLICATE* *TOKEN_ELEVATION* *TOKEN_IMPERSONATE* *TOKEN_INFORMATION_CLASS* *TOKEN_PRIVILEGES* *TOKEN_QUERY* *Metasploit* *Mimikatz*)
```


### splunk
    
```
(source="WinEventLog:Microsoft-Windows-PowerShell/Operational" (Message="*AdjustTokenPrivileges*" OR Message="*IMAGE_NT_OPTIONAL_HDR64_MAGIC*" OR Message="*Microsoft.Win32.UnsafeNativeMethods*" OR Message="*ReadProcessMemory.Invoke*" OR Message="*SE_PRIVILEGE_ENABLED*" OR Message="*LSA_UNICODE_STRING*" OR Message="*MiniDumpWriteDump*" OR Message="*PAGE_EXECUTE_READ*" OR Message="*SECURITY_DELEGATION*" OR Message="*TOKEN_ADJUST_PRIVILEGES*" OR Message="*TOKEN_ALL_ACCESS*" OR Message="*TOKEN_ASSIGN_PRIMARY*" OR Message="*TOKEN_DUPLICATE*" OR Message="*TOKEN_ELEVATION*" OR Message="*TOKEN_IMPERSONATE*" OR Message="*TOKEN_INFORMATION_CLASS*" OR Message="*TOKEN_PRIVILEGES*" OR Message="*TOKEN_QUERY*" OR Message="*Metasploit*" OR Message="*Mimikatz*"))
```


### logpoint
    
```
Message IN ["*AdjustTokenPrivileges*", "*IMAGE_NT_OPTIONAL_HDR64_MAGIC*", "*Microsoft.Win32.UnsafeNativeMethods*", "*ReadProcessMemory.Invoke*", "*SE_PRIVILEGE_ENABLED*", "*LSA_UNICODE_STRING*", "*MiniDumpWriteDump*", "*PAGE_EXECUTE_READ*", "*SECURITY_DELEGATION*", "*TOKEN_ADJUST_PRIVILEGES*", "*TOKEN_ALL_ACCESS*", "*TOKEN_ASSIGN_PRIMARY*", "*TOKEN_DUPLICATE*", "*TOKEN_ELEVATION*", "*TOKEN_IMPERSONATE*", "*TOKEN_INFORMATION_CLASS*", "*TOKEN_PRIVILEGES*", "*TOKEN_QUERY*", "*Metasploit*", "*Mimikatz*"]
```


### grep
    
```
grep -P '^(?:.*.*AdjustTokenPrivileges.*|.*.*IMAGE_NT_OPTIONAL_HDR64_MAGIC.*|.*.*Microsoft\\.Win32\\.UnsafeNativeMethods.*|.*.*ReadProcessMemory\\.Invoke.*|.*.*SE_PRIVILEGE_ENABLED.*|.*.*LSA_UNICODE_STRING.*|.*.*MiniDumpWriteDump.*|.*.*PAGE_EXECUTE_READ.*|.*.*SECURITY_DELEGATION.*|.*.*TOKEN_ADJUST_PRIVILEGES.*|.*.*TOKEN_ALL_ACCESS.*|.*.*TOKEN_ASSIGN_PRIMARY.*|.*.*TOKEN_DUPLICATE.*|.*.*TOKEN_ELEVATION.*|.*.*TOKEN_IMPERSONATE.*|.*.*TOKEN_INFORMATION_CLASS.*|.*.*TOKEN_PRIVILEGES.*|.*.*TOKEN_QUERY.*|.*.*Metasploit.*|.*.*Mimikatz.*)'
```



