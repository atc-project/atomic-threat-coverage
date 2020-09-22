| Title                    | Judgement Panda Credential Access Activity       |
|:-------------------------|:------------------|
| **Description**          | Detects Russian group activity as described in Global Threat Report 2019 by Crowdstrike |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0006: Credential Access](https://attack.mitre.org/tactics/TA0006)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1081: Credentials in Files](https://attack.mitre.org/techniques/T1081)</li><li>[T1003: OS Credential Dumping](https://attack.mitre.org/techniques/T1003)</li><li>[T1552.001: Credentials In Files](https://attack.mitre.org/techniques/T1552.001)</li><li>[T1003.003: NTDS](https://attack.mitre.org/techniques/T1003.003)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1003: OS Credential Dumping](../Triggers/T1003.md)</li><li>[T1552.001: Credentials In Files](../Triggers/T1552.001.md)</li><li>[T1003.003: NTDS](../Triggers/T1003.003.md)</li></ul>  |
| **Severity Level**       | critical |
| **False Positives**      | <ul><li>unknown</li></ul>  |
| **Development Status**   |  Development Status wasn't defined for this Detection Rule yet  |
| **References**           | <ul><li>[https://www.crowdstrike.com/resources/reports/2019-crowdstrike-global-threat-report/](https://www.crowdstrike.com/resources/reports/2019-crowdstrike-global-threat-report/)</li></ul>  |
| **Author**               | Florian Roth |


## Detection Rules

### Sigma rule

```
title: Judgement Panda Credential Access Activity
id: b83f5166-9237-4b5e-9cd4-7b5d52f4d8ee
description: Detects Russian group activity as described in Global Threat Report 2019 by Crowdstrike
references:
    - https://www.crowdstrike.com/resources/reports/2019-crowdstrike-global-threat-report/
author: Florian Roth
date: 2019/02/21
modified: 2020/08/26
tags:
    - attack.credential_access
    - attack.t1081 # an old one
    - attack.t1003 # an old one
    - attack.t1552.001
    - attack.t1003.003
logsource:
    category: process_creation
    product: windows
detection:
    selection1:
        Image: '*\xcopy.exe'
        CommandLine: '* /S /E /C /Q /H \\*'
    selection2:
        Image: '*\adexplorer.exe'
        CommandLine: '* -snapshot "" c:\users\\*'
    condition: selection1 or selection2
falsepositives:
    - unknown
level: critical

```





### powershell
    
```
Get-WinEvent | where {(($_.message -match "Image.*.*\\\\xcopy.exe" -and $_.message -match "CommandLine.*.* /S /E /C /Q /H \\\\.*") -or ($_.message -match "Image.*.*\\\\adexplorer.exe" -and $_.message -match "CommandLine.*.* -snapshot \\"\\" c:\\\\users\\\\.*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
((winlog.event_data.Image.keyword:*\\\\xcopy.exe AND winlog.event_data.CommandLine.keyword:*\\ \\/S\\ \\/E\\ \\/C\\ \\/Q\\ \\/H\\ \\\\*) OR (winlog.event_data.Image.keyword:*\\\\adexplorer.exe AND winlog.event_data.CommandLine.keyword:*\\ \\-snapshot\\ \\"\\"\\ c\\:\\\\users\\\\*))
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/b83f5166-9237-4b5e-9cd4-7b5d52f4d8ee <<EOF\n{\n  "metadata": {\n    "title": "Judgement Panda Credential Access Activity",\n    "description": "Detects Russian group activity as described in Global Threat Report 2019 by Crowdstrike",\n    "tags": [\n      "attack.credential_access",\n      "attack.t1081",\n      "attack.t1003",\n      "attack.t1552.001",\n      "attack.t1003.003"\n    ],\n    "query": "((winlog.event_data.Image.keyword:*\\\\\\\\xcopy.exe AND winlog.event_data.CommandLine.keyword:*\\\\ \\\\/S\\\\ \\\\/E\\\\ \\\\/C\\\\ \\\\/Q\\\\ \\\\/H\\\\ \\\\\\\\*) OR (winlog.event_data.Image.keyword:*\\\\\\\\adexplorer.exe AND winlog.event_data.CommandLine.keyword:*\\\\ \\\\-snapshot\\\\ \\\\\\"\\\\\\"\\\\ c\\\\:\\\\\\\\users\\\\\\\\*))"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "((winlog.event_data.Image.keyword:*\\\\\\\\xcopy.exe AND winlog.event_data.CommandLine.keyword:*\\\\ \\\\/S\\\\ \\\\/E\\\\ \\\\/C\\\\ \\\\/Q\\\\ \\\\/H\\\\ \\\\\\\\*) OR (winlog.event_data.Image.keyword:*\\\\\\\\adexplorer.exe AND winlog.event_data.CommandLine.keyword:*\\\\ \\\\-snapshot\\\\ \\\\\\"\\\\\\"\\\\ c\\\\:\\\\\\\\users\\\\\\\\*))",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": [\n          "winlogbeat-*"\n        ]\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "throttle_period": "15m",\n      "email": {\n        "profile": "standard",\n        "from": "root@localhost",\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Judgement Panda Credential Access Activity\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
((Image.keyword:*\\\\xcopy.exe AND CommandLine.keyword:* \\/S \\/E \\/C \\/Q \\/H \\\\*) OR (Image.keyword:*\\\\adexplorer.exe AND CommandLine.keyword:* \\-snapshot \\"\\" c\\:\\\\users\\\\*))
```


### splunk
    
```
((Image="*\\\\xcopy.exe" CommandLine="* /S /E /C /Q /H \\\\*") OR (Image="*\\\\adexplorer.exe" CommandLine="* -snapshot \\"\\" c:\\\\users\\\\*"))
```


### logpoint
    
```
((Image="*\\\\xcopy.exe" CommandLine="* /S /E /C /Q /H \\\\*") OR (Image="*\\\\adexplorer.exe" CommandLine="* -snapshot \\"\\" c:\\\\users\\\\*"))
```


### grep
    
```
grep -P \'^(?:.*(?:.*(?:.*(?=.*.*\\xcopy\\.exe)(?=.*.* /S /E /C /Q /H \\\\.*))|.*(?:.*(?=.*.*\\adexplorer\\.exe)(?=.*.* -snapshot "" c:\\users\\\\.*))))\'
```



