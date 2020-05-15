| Title                    | PowerShell Downgrade Attack       |
|:-------------------------|:------------------|
| **Description**          | Detects PowerShell downgrade attack by comparing the host versions with the actually used engine version 2.0 |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1086: PowerShell](https://attack.mitre.org/techniques/T1086)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1086: PowerShell](../Triggers/T1086.md)</li></ul>  |
| **Severity Level**       | medium |
| **False Positives**      | <ul><li>Penetration Test</li><li>Unknown</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[http://www.leeholmes.com/blog/2017/03/17/detecting-and-preventing-powershell-downgrade-attacks/](http://www.leeholmes.com/blog/2017/03/17/detecting-and-preventing-powershell-downgrade-attacks/)</li></ul>  |
| **Author**               | Harish Segar (rule) |


## Detection Rules

### Sigma rule

```
title: PowerShell Downgrade Attack
id: b3512211-c67e-4707-bedc-66efc7848863
related:
  - id: 6331d09b-4785-4c13-980f-f96661356249
    type: derived
status: experimental
description: Detects PowerShell downgrade attack by comparing the host versions with the actually used engine version 2.0
references:
    - http://www.leeholmes.com/blog/2017/03/17/detecting-and-preventing-powershell-downgrade-attacks/
tags:
    - attack.defense_evasion
    - attack.execution
    - attack.t1086
author: Harish Segar (rule)
date: 2020/03/20
falsepositives:
    - Penetration Test
    - Unknown
level: medium
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains: 
            - ' -version 2 '
            - ' -versio 2 '
            - ' -versi 2 '
            - ' -vers 2 '
            - ' -ver 2 '
            - ' -ve 2 '        
        Image|endswith: '\powershell.exe'
    condition: selection

```





### powershell
    
```
Get-WinEvent | where {(($_.message -match "CommandLine.*.* -version 2 .*" -or $_.message -match "CommandLine.*.* -versio 2 .*" -or $_.message -match "CommandLine.*.* -versi 2 .*" -or $_.message -match "CommandLine.*.* -vers 2 .*" -or $_.message -match "CommandLine.*.* -ver 2 .*" -or $_.message -match "CommandLine.*.* -ve 2 .*") -and $_.message -match "Image.*.*\\\\powershell.exe") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.event_data.CommandLine.keyword:(*\\ \\-version\\ 2\\ * OR *\\ \\-versio\\ 2\\ * OR *\\ \\-versi\\ 2\\ * OR *\\ \\-vers\\ 2\\ * OR *\\ \\-ver\\ 2\\ * OR *\\ \\-ve\\ 2\\ *) AND winlog.event_data.Image.keyword:*\\\\powershell.exe)
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/b3512211-c67e-4707-bedc-66efc7848863 <<EOF\n{\n  "metadata": {\n    "title": "PowerShell Downgrade Attack",\n    "description": "Detects PowerShell downgrade attack by comparing the host versions with the actually used engine version 2.0",\n    "tags": [\n      "attack.defense_evasion",\n      "attack.execution",\n      "attack.t1086"\n    ],\n    "query": "(winlog.event_data.CommandLine.keyword:(*\\\\ \\\\-version\\\\ 2\\\\ * OR *\\\\ \\\\-versio\\\\ 2\\\\ * OR *\\\\ \\\\-versi\\\\ 2\\\\ * OR *\\\\ \\\\-vers\\\\ 2\\\\ * OR *\\\\ \\\\-ver\\\\ 2\\\\ * OR *\\\\ \\\\-ve\\\\ 2\\\\ *) AND winlog.event_data.Image.keyword:*\\\\\\\\powershell.exe)"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "(winlog.event_data.CommandLine.keyword:(*\\\\ \\\\-version\\\\ 2\\\\ * OR *\\\\ \\\\-versio\\\\ 2\\\\ * OR *\\\\ \\\\-versi\\\\ 2\\\\ * OR *\\\\ \\\\-vers\\\\ 2\\\\ * OR *\\\\ \\\\-ver\\\\ 2\\\\ * OR *\\\\ \\\\-ve\\\\ 2\\\\ *) AND winlog.event_data.Image.keyword:*\\\\\\\\powershell.exe)",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": [\n          "winlogbeat-*"\n        ]\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'PowerShell Downgrade Attack\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
(CommandLine.keyword:(* \\-version 2 * * \\-versio 2 * * \\-versi 2 * * \\-vers 2 * * \\-ver 2 * * \\-ve 2 *) AND Image.keyword:*\\\\powershell.exe)
```


### splunk
    
```
((CommandLine="* -version 2 *" OR CommandLine="* -versio 2 *" OR CommandLine="* -versi 2 *" OR CommandLine="* -vers 2 *" OR CommandLine="* -ver 2 *" OR CommandLine="* -ve 2 *") Image="*\\\\powershell.exe")
```


### logpoint
    
```
(CommandLine IN ["* -version 2 *", "* -versio 2 *", "* -versi 2 *", "* -vers 2 *", "* -ver 2 *", "* -ve 2 *"] Image="*\\\\powershell.exe")
```


### grep
    
```
grep -P '^(?:.*(?=.*(?:.*.* -version 2 .*|.*.* -versio 2 .*|.*.* -versi 2 .*|.*.* -vers 2 .*|.*.* -ver 2 .*|.*.* -ve 2 .*))(?=.*.*\\powershell\\.exe))'
```



