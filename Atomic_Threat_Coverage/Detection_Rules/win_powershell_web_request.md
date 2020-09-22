| Title                    | Windows PowerShell Web Request       |
|:-------------------------|:------------------|
| **Description**          | Detects the use of various web request methods (including aliases) via Windows PowerShell |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1059.001: PowerShell](https://attack.mitre.org/techniques/T1059.001)</li><li>[T1086: PowerShell](https://attack.mitre.org/techniques/T1086)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li><li>[DN_0036_4104_windows_powershell_script_block](../Data_Needed/DN_0036_4104_windows_powershell_script_block.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1059.001: PowerShell](../Triggers/T1059.001.md)</li></ul>  |
| **Severity Level**       | medium |
| **False Positives**      | <ul><li>Use of Get-Command and Get-Help modules to reference Invoke-WebRequest and Start-BitsTransfer.</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://4sysops.com/archives/use-powershell-to-download-a-file-with-http-https-and-ftp/](https://4sysops.com/archives/use-powershell-to-download-a-file-with-http-https-and-ftp/)</li><li>[https://blog.jourdant.me/post/3-ways-to-download-files-with-powershell](https://blog.jourdant.me/post/3-ways-to-download-files-with-powershell)</li></ul>  |
| **Author**               | James Pemberton / @4A616D6573 |


## Detection Rules

### Sigma rule

```
action: global
title: Windows PowerShell Web Request
id: 9fc51a3c-81b3-4fa7-b35f-7c02cf10fd2d
status: experimental
description: Detects the use of various web request methods (including aliases) via Windows PowerShell
references:
    - https://4sysops.com/archives/use-powershell-to-download-a-file-with-http-https-and-ftp/
    - https://blog.jourdant.me/post/3-ways-to-download-files-with-powershell
author: James Pemberton / @4A616D6573
date: 2019/10/24
modified: 2020/08/24
tags:
    - attack.execution
    - attack.t1059.001
    - attack.t1086  #an old one
detection:
    condition: selection
falsepositives:
    - Use of Get-Command and Get-Help modules to reference Invoke-WebRequest and Start-BitsTransfer.
level: medium
---
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains:
            - 'Invoke-WebRequest'
            - 'iwr '
            - 'wget '
            - 'curl '
            - 'Net.WebClient'
            - 'Start-BitsTransfer'
---
logsource:
    product: windows
    service: powershell
detection:
    selection:
        EventID: 4104
        ScriptBlockText|contains:
            - 'Invoke-WebRequest'
            - 'iwr '
            - 'wget '
            - 'curl '
            - 'Net.WebClient'
            - 'Start-BitsTransfer'

```





### powershell
    
```
Get-WinEvent | where {($_.message -match "CommandLine.*.*Invoke-WebRequest.*" -or $_.message -match "CommandLine.*.*iwr .*" -or $_.message -match "CommandLine.*.*wget .*" -or $_.message -match "CommandLine.*.*curl .*" -or $_.message -match "CommandLine.*.*Net.WebClient.*" -or $_.message -match "CommandLine.*.*Start-BitsTransfer.*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message\nGet-WinEvent -LogName Microsoft-Windows-PowerShell/Operational | where {($_.ID -eq "4104" -and ($_.message -match "ScriptBlockText.*.*Invoke-WebRequest.*" -or $_.message -match "ScriptBlockText.*.*iwr .*" -or $_.message -match "ScriptBlockText.*.*wget .*" -or $_.message -match "ScriptBlockText.*.*curl .*" -or $_.message -match "ScriptBlockText.*.*Net.WebClient.*" -or $_.message -match "ScriptBlockText.*.*Start-BitsTransfer.*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
winlog.event_data.CommandLine.keyword:(*Invoke\\-WebRequest* OR *iwr\\ * OR *wget\\ * OR *curl\\ * OR *Net.WebClient* OR *Start\\-BitsTransfer*)\n(winlog.event_id:"4104" AND ScriptBlockText.keyword:(*Invoke\\-WebRequest* OR *iwr\\ * OR *wget\\ * OR *curl\\ * OR *Net.WebClient* OR *Start\\-BitsTransfer*))
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/9fc51a3c-81b3-4fa7-b35f-7c02cf10fd2d <<EOF\n{\n  "metadata": {\n    "title": "Windows PowerShell Web Request",\n    "description": "Detects the use of various web request methods (including aliases) via Windows PowerShell",\n    "tags": [\n      "attack.execution",\n      "attack.t1059.001",\n      "attack.t1086"\n    ],\n    "query": "winlog.event_data.CommandLine.keyword:(*Invoke\\\\-WebRequest* OR *iwr\\\\ * OR *wget\\\\ * OR *curl\\\\ * OR *Net.WebClient* OR *Start\\\\-BitsTransfer*)"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "winlog.event_data.CommandLine.keyword:(*Invoke\\\\-WebRequest* OR *iwr\\\\ * OR *wget\\\\ * OR *curl\\\\ * OR *Net.WebClient* OR *Start\\\\-BitsTransfer*)",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": [\n          "winlogbeat-*"\n        ]\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "throttle_period": "15m",\n      "email": {\n        "profile": "standard",\n        "from": "root@localhost",\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Windows PowerShell Web Request\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\ncurl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/9fc51a3c-81b3-4fa7-b35f-7c02cf10fd2d-2 <<EOF\n{\n  "metadata": {\n    "title": "Windows PowerShell Web Request",\n    "description": "Detects the use of various web request methods (including aliases) via Windows PowerShell",\n    "tags": [\n      "attack.execution",\n      "attack.t1059.001",\n      "attack.t1086"\n    ],\n    "query": "(winlog.event_id:\\"4104\\" AND ScriptBlockText.keyword:(*Invoke\\\\-WebRequest* OR *iwr\\\\ * OR *wget\\\\ * OR *curl\\\\ * OR *Net.WebClient* OR *Start\\\\-BitsTransfer*))"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "(winlog.event_id:\\"4104\\" AND ScriptBlockText.keyword:(*Invoke\\\\-WebRequest* OR *iwr\\\\ * OR *wget\\\\ * OR *curl\\\\ * OR *Net.WebClient* OR *Start\\\\-BitsTransfer*))",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": [\n          "winlogbeat-*"\n        ]\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "throttle_period": "15m",\n      "email": {\n        "profile": "standard",\n        "from": "root@localhost",\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Windows PowerShell Web Request\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
CommandLine.keyword:(*Invoke\\-WebRequest* *iwr * *wget * *curl * *Net.WebClient* *Start\\-BitsTransfer*)\n(EventID:"4104" AND ScriptBlockText.keyword:(*Invoke\\-WebRequest* *iwr * *wget * *curl * *Net.WebClient* *Start\\-BitsTransfer*))
```


### splunk
    
```
(CommandLine="*Invoke-WebRequest*" OR CommandLine="*iwr *" OR CommandLine="*wget *" OR CommandLine="*curl *" OR CommandLine="*Net.WebClient*" OR CommandLine="*Start-BitsTransfer*")\n(source="WinEventLog:Microsoft-Windows-PowerShell/Operational" EventCode="4104" (ScriptBlockText="*Invoke-WebRequest*" OR ScriptBlockText="*iwr *" OR ScriptBlockText="*wget *" OR ScriptBlockText="*curl *" OR ScriptBlockText="*Net.WebClient*" OR ScriptBlockText="*Start-BitsTransfer*"))
```


### logpoint
    
```
CommandLine IN ["*Invoke-WebRequest*", "*iwr *", "*wget *", "*curl *", "*Net.WebClient*", "*Start-BitsTransfer*"]\n(event_id="4104" ScriptBlockText IN ["*Invoke-WebRequest*", "*iwr *", "*wget *", "*curl *", "*Net.WebClient*", "*Start-BitsTransfer*"])
```


### grep
    
```
grep -P '^(?:.*.*Invoke-WebRequest.*|.*.*iwr .*|.*.*wget .*|.*.*curl .*|.*.*Net\\.WebClient.*|.*.*Start-BitsTransfer.*)'\ngrep -P '^(?:.*(?=.*4104)(?=.*(?:.*.*Invoke-WebRequest.*|.*.*iwr .*|.*.*wget .*|.*.*curl .*|.*.*Net\\.WebClient.*|.*.*Start-BitsTransfer.*)))'
```



