| Title                    | PowerShell DownloadFile       |
|:-------------------------|:------------------|
| **Description**          | Detects the execution of powershell, a WebClient object creation and the invocation of DownloadFile in a single command line |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1086: PowerShell](https://attack.mitre.org/techniques/T1086)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1086: PowerShell](../Triggers/T1086.md)</li></ul>  |
| **Severity Level**       | high |
| **False Positives**      | <ul><li>Unknown</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://www.fireeye.com/blog/threat-research/2020/03/apt41-initiates-global-intrusion-campaign-using-multiple-exploits.html](https://www.fireeye.com/blog/threat-research/2020/03/apt41-initiates-global-intrusion-campaign-using-multiple-exploits.html)</li></ul>  |
| **Author**               | Florian Roth |


## Detection Rules

### Sigma rule

```
title: PowerShell DownloadFile
id: 8f70ac5f-1f6f-4f8e-b454-db19561216c5
status: experimental
description: Detects the execution of powershell, a WebClient object creation and the invocation of DownloadFile in a single command line
references:
    - https://www.fireeye.com/blog/threat-research/2020/03/apt41-initiates-global-intrusion-campaign-using-multiple-exploits.html
author: Florian Roth
date: 2020/03/25
tags:
    - attack.execution
    - attack.t1086
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains|all: 
            - 'powershell'
            - '.DownloadFile'
            - 'System.Net.WebClient'
    condition: selection
falsepositives:
    - Unknown
level: high

```





### powershell
    
```
Get-WinEvent | where {($_.message -match "CommandLine.*.*powershell.*" -and $_.message -match "CommandLine.*.*.DownloadFile.*" -and $_.message -match "CommandLine.*.*System.Net.WebClient.*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.event_data.CommandLine.keyword:*powershell* AND winlog.event_data.CommandLine.keyword:*.DownloadFile* AND winlog.event_data.CommandLine.keyword:*System.Net.WebClient*)
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/8f70ac5f-1f6f-4f8e-b454-db19561216c5 <<EOF\n{\n  "metadata": {\n    "title": "PowerShell DownloadFile",\n    "description": "Detects the execution of powershell, a WebClient object creation and the invocation of DownloadFile in a single command line",\n    "tags": [\n      "attack.execution",\n      "attack.t1086"\n    ],\n    "query": "(winlog.event_data.CommandLine.keyword:*powershell* AND winlog.event_data.CommandLine.keyword:*.DownloadFile* AND winlog.event_data.CommandLine.keyword:*System.Net.WebClient*)"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "(winlog.event_data.CommandLine.keyword:*powershell* AND winlog.event_data.CommandLine.keyword:*.DownloadFile* AND winlog.event_data.CommandLine.keyword:*System.Net.WebClient*)",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": [\n          "winlogbeat-*"\n        ]\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'PowerShell DownloadFile\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
(CommandLine.keyword:*powershell* AND CommandLine.keyword:*.DownloadFile* AND CommandLine.keyword:*System.Net.WebClient*)
```


### splunk
    
```
(CommandLine="*powershell*" CommandLine="*.DownloadFile*" CommandLine="*System.Net.WebClient*")
```


### logpoint
    
```
(CommandLine="*powershell*" CommandLine="*.DownloadFile*" CommandLine="*System.Net.WebClient*")
```


### grep
    
```
grep -P '^(?:.*(?=.*.*powershell.*)(?=.*.*\\.DownloadFile.*)(?=.*.*System\\.Net\\.WebClient.*))'
```



