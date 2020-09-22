| Title                    | Explorer Root Flag Process Tree Break       |
|:-------------------------|:------------------|
| **Description**          | Detects a command line process that uses explorer.exe /root, which is similar to cmd.exe /c, only it breaks the process tree and makes its parent a new instance of explorer |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1036: Masquerading](https://attack.mitre.org/techniques/T1036)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              |  There is no documented Trigger for this Detection Rule yet  |
| **Severity Level**       | medium |
| **False Positives**      | <ul><li>Unknown how many legitimate software products use that method</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://twitter.com/CyberRaiju/status/1273597319322058752](https://twitter.com/CyberRaiju/status/1273597319322058752)</li><li>[https://twitter.com/bohops/status/1276357235954909188?s=12](https://twitter.com/bohops/status/1276357235954909188?s=12)</li></ul>  |
| **Author**               | Florian Roth |


## Detection Rules

### Sigma rule

```
title: Explorer Root Flag Process Tree Break
id: 949f1ffb-6e85-4f00-ae1e-c3c5b190d605
description: Detects a command line process that uses explorer.exe /root, which is similar to cmd.exe /c, only it breaks the process tree and makes its parent a new instance of explorer
status: experimental
references:
    - https://twitter.com/CyberRaiju/status/1273597319322058752
    - https://twitter.com/bohops/status/1276357235954909188?s=12
author: Florian Roth
date: 2019/06/29
modified: 2020/08/30
tags:
    - attack.defense_evasion
    - attack.t1036
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains|all: 
            - 'explorer.exe'
            - ' /root,'
    condition: selection
falsepositives:
    - Unknown how many legitimate software products use that method
level: medium

```





### powershell
    
```
Get-WinEvent | where {($_.message -match "CommandLine.*.*explorer.exe.*" -and $_.message -match "CommandLine.*.* /root,.*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.event_data.CommandLine.keyword:*explorer.exe* AND winlog.event_data.CommandLine.keyword:*\\ \\/root,*)
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/949f1ffb-6e85-4f00-ae1e-c3c5b190d605 <<EOF\n{\n  "metadata": {\n    "title": "Explorer Root Flag Process Tree Break",\n    "description": "Detects a command line process that uses explorer.exe /root, which is similar to cmd.exe /c, only it breaks the process tree and makes its parent a new instance of explorer",\n    "tags": [\n      "attack.defense_evasion",\n      "attack.t1036"\n    ],\n    "query": "(winlog.event_data.CommandLine.keyword:*explorer.exe* AND winlog.event_data.CommandLine.keyword:*\\\\ \\\\/root,*)"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "(winlog.event_data.CommandLine.keyword:*explorer.exe* AND winlog.event_data.CommandLine.keyword:*\\\\ \\\\/root,*)",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": [\n          "winlogbeat-*"\n        ]\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "throttle_period": "15m",\n      "email": {\n        "profile": "standard",\n        "from": "root@localhost",\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Explorer Root Flag Process Tree Break\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
(CommandLine.keyword:*explorer.exe* AND CommandLine.keyword:* \\/root,*)
```


### splunk
    
```
(CommandLine="*explorer.exe*" CommandLine="* /root,*")
```


### logpoint
    
```
(CommandLine="*explorer.exe*" CommandLine="* /root,*")
```


### grep
    
```
grep -P '^(?:.*(?=.*.*explorer\\.exe.*)(?=.*.* /root,.*))'
```



