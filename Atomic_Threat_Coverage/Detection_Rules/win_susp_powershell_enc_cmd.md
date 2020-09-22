| Title                    | Suspicious Encoded PowerShell Command Line       |
|:-------------------------|:------------------|
| **Description**          | Detects suspicious powershell process starts with base64 encoded commands (e.g. Emotet) |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1059.001: PowerShell](https://attack.mitre.org/techniques/T1059.001)</li><li>[T1086: PowerShell](https://attack.mitre.org/techniques/T1086)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1059.001: PowerShell](../Triggers/T1059.001.md)</li></ul>  |
| **Severity Level**       | high |
| **False Positives**      |  There are no documented False Positives for this Detection Rule yet  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://app.any.run/tasks/6217d77d-3189-4db2-a957-8ab239f3e01e](https://app.any.run/tasks/6217d77d-3189-4db2-a957-8ab239f3e01e)</li></ul>  |
| **Author**               | Florian Roth, Markus Neis |


## Detection Rules

### Sigma rule

```
title: Suspicious Encoded PowerShell Command Line
id: ca2092a1-c273-4878-9b4b-0d60115bf5ea
description: Detects suspicious powershell process starts with base64 encoded commands (e.g. Emotet)
status: experimental
references:
    - https://app.any.run/tasks/6217d77d-3189-4db2-a957-8ab239f3e01e
author: Florian Roth, Markus Neis
date: 2018/09/03
modified: 2019/12/16
tags:
    - attack.execution
    - attack.t1059.001
    - attack.t1086      # an old one
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine:
            - '* -e JAB*'
            - '* -e  JAB*'
            - '* -e   JAB*'
            - '* -e    JAB*'
            - '* -e     JAB*'
            - '* -e      JAB*'
            - '* -en JAB*'
            - '* -enc JAB*'
            - '* -enc* JAB*'
            - '* -w hidden -e* JAB*'
            - '* BA^J e-'
            - '* -e SUVYI*'
            - '* -e aWV4I*'
            - '* -e SQBFAFgA*'
            - '* -e aQBlAHgA*'
            - '* -enc SUVYI*'
            - '* -enc aWV4I*'
            - '* -enc SQBFAFgA*'
            - '* -enc aQBlAHgA*'
    falsepositive1:
        CommandLine: '* -ExecutionPolicy remotesigned *'
    condition: selection and not falsepositive1
level: high

```





### powershell
    
```
Get-WinEvent | where {(($_.message -match "CommandLine.*.* -e JAB.*" -or $_.message -match "CommandLine.*.* -e  JAB.*" -or $_.message -match "CommandLine.*.* -e   JAB.*" -or $_.message -match "CommandLine.*.* -e    JAB.*" -or $_.message -match "CommandLine.*.* -e     JAB.*" -or $_.message -match "CommandLine.*.* -e      JAB.*" -or $_.message -match "CommandLine.*.* -en JAB.*" -or $_.message -match "CommandLine.*.* -enc JAB.*" -or $_.message -match "CommandLine.*.* -enc.* JAB.*" -or $_.message -match "CommandLine.*.* -w hidden -e.* JAB.*" -or $_.message -match "CommandLine.*.* BA^J e-" -or $_.message -match "CommandLine.*.* -e SUVYI.*" -or $_.message -match "CommandLine.*.* -e aWV4I.*" -or $_.message -match "CommandLine.*.* -e SQBFAFgA.*" -or $_.message -match "CommandLine.*.* -e aQBlAHgA.*" -or $_.message -match "CommandLine.*.* -enc SUVYI.*" -or $_.message -match "CommandLine.*.* -enc aWV4I.*" -or $_.message -match "CommandLine.*.* -enc SQBFAFgA.*" -or $_.message -match "CommandLine.*.* -enc aQBlAHgA.*") -and  -not ($_.message -match "CommandLine.*.* -ExecutionPolicy remotesigned .*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.event_data.CommandLine.keyword:(*\\ \\-e\\ JAB* OR *\\ \\-e\\ \\ JAB* OR *\\ \\-e\\ \\ \\ JAB* OR *\\ \\-e\\ \\ \\ \\ JAB* OR *\\ \\-e\\ \\ \\ \\ \\ JAB* OR *\\ \\-e\\ \\ \\ \\ \\ \\ JAB* OR *\\ \\-en\\ JAB* OR *\\ \\-enc\\ JAB* OR *\\ \\-enc*\\ JAB* OR *\\ \\-w\\ hidden\\ \\-e*\\ JAB* OR *\\ BA\\^J\\ e\\- OR *\\ \\-e\\ SUVYI* OR *\\ \\-e\\ aWV4I* OR *\\ \\-e\\ SQBFAFgA* OR *\\ \\-e\\ aQBlAHgA* OR *\\ \\-enc\\ SUVYI* OR *\\ \\-enc\\ aWV4I* OR *\\ \\-enc\\ SQBFAFgA* OR *\\ \\-enc\\ aQBlAHgA*) AND (NOT (winlog.event_data.CommandLine.keyword:*\\ \\-ExecutionPolicy\\ remotesigned\\ *)))
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/ca2092a1-c273-4878-9b4b-0d60115bf5ea <<EOF\n{\n  "metadata": {\n    "title": "Suspicious Encoded PowerShell Command Line",\n    "description": "Detects suspicious powershell process starts with base64 encoded commands (e.g. Emotet)",\n    "tags": [\n      "attack.execution",\n      "attack.t1059.001",\n      "attack.t1086"\n    ],\n    "query": "(winlog.event_data.CommandLine.keyword:(*\\\\ \\\\-e\\\\ JAB* OR *\\\\ \\\\-e\\\\ \\\\ JAB* OR *\\\\ \\\\-e\\\\ \\\\ \\\\ JAB* OR *\\\\ \\\\-e\\\\ \\\\ \\\\ \\\\ JAB* OR *\\\\ \\\\-e\\\\ \\\\ \\\\ \\\\ \\\\ JAB* OR *\\\\ \\\\-e\\\\ \\\\ \\\\ \\\\ \\\\ \\\\ JAB* OR *\\\\ \\\\-en\\\\ JAB* OR *\\\\ \\\\-enc\\\\ JAB* OR *\\\\ \\\\-enc*\\\\ JAB* OR *\\\\ \\\\-w\\\\ hidden\\\\ \\\\-e*\\\\ JAB* OR *\\\\ BA\\\\^J\\\\ e\\\\- OR *\\\\ \\\\-e\\\\ SUVYI* OR *\\\\ \\\\-e\\\\ aWV4I* OR *\\\\ \\\\-e\\\\ SQBFAFgA* OR *\\\\ \\\\-e\\\\ aQBlAHgA* OR *\\\\ \\\\-enc\\\\ SUVYI* OR *\\\\ \\\\-enc\\\\ aWV4I* OR *\\\\ \\\\-enc\\\\ SQBFAFgA* OR *\\\\ \\\\-enc\\\\ aQBlAHgA*) AND (NOT (winlog.event_data.CommandLine.keyword:*\\\\ \\\\-ExecutionPolicy\\\\ remotesigned\\\\ *)))"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "(winlog.event_data.CommandLine.keyword:(*\\\\ \\\\-e\\\\ JAB* OR *\\\\ \\\\-e\\\\ \\\\ JAB* OR *\\\\ \\\\-e\\\\ \\\\ \\\\ JAB* OR *\\\\ \\\\-e\\\\ \\\\ \\\\ \\\\ JAB* OR *\\\\ \\\\-e\\\\ \\\\ \\\\ \\\\ \\\\ JAB* OR *\\\\ \\\\-e\\\\ \\\\ \\\\ \\\\ \\\\ \\\\ JAB* OR *\\\\ \\\\-en\\\\ JAB* OR *\\\\ \\\\-enc\\\\ JAB* OR *\\\\ \\\\-enc*\\\\ JAB* OR *\\\\ \\\\-w\\\\ hidden\\\\ \\\\-e*\\\\ JAB* OR *\\\\ BA\\\\^J\\\\ e\\\\- OR *\\\\ \\\\-e\\\\ SUVYI* OR *\\\\ \\\\-e\\\\ aWV4I* OR *\\\\ \\\\-e\\\\ SQBFAFgA* OR *\\\\ \\\\-e\\\\ aQBlAHgA* OR *\\\\ \\\\-enc\\\\ SUVYI* OR *\\\\ \\\\-enc\\\\ aWV4I* OR *\\\\ \\\\-enc\\\\ SQBFAFgA* OR *\\\\ \\\\-enc\\\\ aQBlAHgA*) AND (NOT (winlog.event_data.CommandLine.keyword:*\\\\ \\\\-ExecutionPolicy\\\\ remotesigned\\\\ *)))",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": [\n          "winlogbeat-*"\n        ]\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "throttle_period": "15m",\n      "email": {\n        "profile": "standard",\n        "from": "root@localhost",\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Suspicious Encoded PowerShell Command Line\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
(CommandLine.keyword:(* \\-e JAB* * \\-e  JAB* * \\-e   JAB* * \\-e    JAB* * \\-e     JAB* * \\-e      JAB* * \\-en JAB* * \\-enc JAB* * \\-enc* JAB* * \\-w hidden \\-e* JAB* * BA\\^J e\\- * \\-e SUVYI* * \\-e aWV4I* * \\-e SQBFAFgA* * \\-e aQBlAHgA* * \\-enc SUVYI* * \\-enc aWV4I* * \\-enc SQBFAFgA* * \\-enc aQBlAHgA*) AND (NOT (CommandLine.keyword:* \\-ExecutionPolicy remotesigned *)))
```


### splunk
    
```
((CommandLine="* -e JAB*" OR CommandLine="* -e  JAB*" OR CommandLine="* -e   JAB*" OR CommandLine="* -e    JAB*" OR CommandLine="* -e     JAB*" OR CommandLine="* -e      JAB*" OR CommandLine="* -en JAB*" OR CommandLine="* -enc JAB*" OR CommandLine="* -enc* JAB*" OR CommandLine="* -w hidden -e* JAB*" OR CommandLine="* BA^J e-" OR CommandLine="* -e SUVYI*" OR CommandLine="* -e aWV4I*" OR CommandLine="* -e SQBFAFgA*" OR CommandLine="* -e aQBlAHgA*" OR CommandLine="* -enc SUVYI*" OR CommandLine="* -enc aWV4I*" OR CommandLine="* -enc SQBFAFgA*" OR CommandLine="* -enc aQBlAHgA*") NOT (CommandLine="* -ExecutionPolicy remotesigned *"))
```


### logpoint
    
```
(CommandLine IN ["* -e JAB*", "* -e  JAB*", "* -e   JAB*", "* -e    JAB*", "* -e     JAB*", "* -e      JAB*", "* -en JAB*", "* -enc JAB*", "* -enc* JAB*", "* -w hidden -e* JAB*", "* BA^J e-", "* -e SUVYI*", "* -e aWV4I*", "* -e SQBFAFgA*", "* -e aQBlAHgA*", "* -enc SUVYI*", "* -enc aWV4I*", "* -enc SQBFAFgA*", "* -enc aQBlAHgA*"]  -(CommandLine="* -ExecutionPolicy remotesigned *"))
```


### grep
    
```
grep -P '^(?:.*(?=.*(?:.*.* -e JAB.*|.*.* -e  JAB.*|.*.* -e   JAB.*|.*.* -e    JAB.*|.*.* -e     JAB.*|.*.* -e      JAB.*|.*.* -en JAB.*|.*.* -enc JAB.*|.*.* -enc.* JAB.*|.*.* -w hidden -e.* JAB.*|.*.* BA\\^J e-|.*.* -e SUVYI.*|.*.* -e aWV4I.*|.*.* -e SQBFAFgA.*|.*.* -e aQBlAHgA.*|.*.* -enc SUVYI.*|.*.* -enc aWV4I.*|.*.* -enc SQBFAFgA.*|.*.* -enc aQBlAHgA.*))(?=.*(?!.*(?:.*(?=.*.* -ExecutionPolicy remotesigned .*)))))'
```



