| Title                    | Suspicious XOR Encoded PowerShell Command Line       |
|:-------------------------|:------------------|
| **Description**          | Detects suspicious powershell process which includes bxor command, alternative obfuscation method to b64 encoded commands. |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1086: PowerShell](https://attack.mitre.org/techniques/T1086)</li><li>[T1059.001: PowerShell](https://attack.mitre.org/techniques/T1059/001)</li><li>[T1140: Deobfuscate/Decode Files or Information](https://attack.mitre.org/techniques/T1140)</li><li>[T1027: Obfuscated Files or Information](https://attack.mitre.org/techniques/T1027)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1059.001: PowerShell](../Triggers/T1059.001.md)</li><li>[T1140: Deobfuscate/Decode Files or Information](../Triggers/T1140.md)</li><li>[T1027: Obfuscated Files or Information](../Triggers/T1027.md)</li></ul>  |
| **Severity Level**       | medium |
| **False Positives**      | <ul><li>unknown</li></ul>  |
| **Development Status**   | experimental |
| **References**           |  There are no documented References for this Detection Rule yet  |
| **Author**               | Sami Ruohonen, Harish Segar (improvement) |


## Detection Rules

### Sigma rule

```
title: Suspicious XOR Encoded PowerShell Command Line
id: bb780e0c-16cf-4383-8383-1e5471db6cf9
description: Detects suspicious powershell process which includes bxor command, alternative obfuscation method to b64 encoded commands.
status: experimental
author: Sami Ruohonen, Harish Segar (improvement)
date: 2018/09/05
modified: 2020/09/06
tags:
    - attack.defense_evasion
    - attack.t1086 # an old one
    - attack.t1059.001
    - attack.t1140
    - attack.t1027    
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        - Description: "Windows PowerShell"
        - Product: "PowerShell Core 6"
    filter:
        CommandLine|contains:
            - "bxor"
            - "join"
            - "char"
    condition: selection and filter
falsepositives:
    - unknown
level: medium

```





### powershell
    
```
Get-WinEvent | where {(($_.message -match "Description.*Windows PowerShell" -or $_.message -match "Product.*PowerShell Core 6") -and ($_.message -match "CommandLine.*.*bxor.*" -or $_.message -match "CommandLine.*.*join.*" -or $_.message -match "CommandLine.*.*char.*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
((winlog.event_data.Description:"Windows\\ PowerShell" OR Product:"PowerShell\\ Core\\ 6") AND winlog.event_data.CommandLine.keyword:(*bxor* OR *join* OR *char*))
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/bb780e0c-16cf-4383-8383-1e5471db6cf9 <<EOF\n{\n  "metadata": {\n    "title": "Suspicious XOR Encoded PowerShell Command Line",\n    "description": "Detects suspicious powershell process which includes bxor command, alternative obfuscation method to b64 encoded commands.",\n    "tags": [\n      "attack.defense_evasion",\n      "attack.t1086",\n      "attack.t1059.001",\n      "attack.t1140",\n      "attack.t1027"\n    ],\n    "query": "((winlog.event_data.Description:\\"Windows\\\\ PowerShell\\" OR Product:\\"PowerShell\\\\ Core\\\\ 6\\") AND winlog.event_data.CommandLine.keyword:(*bxor* OR *join* OR *char*))"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "((winlog.event_data.Description:\\"Windows\\\\ PowerShell\\" OR Product:\\"PowerShell\\\\ Core\\\\ 6\\") AND winlog.event_data.CommandLine.keyword:(*bxor* OR *join* OR *char*))",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": [\n          "winlogbeat-*"\n        ]\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "throttle_period": "15m",\n      "email": {\n        "profile": "standard",\n        "from": "root@localhost",\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Suspicious XOR Encoded PowerShell Command Line\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
((Description:"Windows PowerShell" OR Product:"PowerShell Core 6") AND CommandLine.keyword:(*bxor* *join* *char*))
```


### splunk
    
```
((Description="Windows PowerShell" OR Product="PowerShell Core 6") (CommandLine="*bxor*" OR CommandLine="*join*" OR CommandLine="*char*"))
```


### logpoint
    
```
((Description="Windows PowerShell" OR Product="PowerShell Core 6") CommandLine IN ["*bxor*", "*join*", "*char*"])
```


### grep
    
```
grep -P '^(?:.*(?=.*(?:.*(?:.*Windows PowerShell|.*PowerShell Core 6)))(?=.*(?:.*.*bxor.*|.*.*join.*|.*.*char.*)))'
```



