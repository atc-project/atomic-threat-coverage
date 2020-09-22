| Title                    | XSL Script Processing       |
|:-------------------------|:------------------|
| **Description**          | Extensible Stylesheet Language (XSL) files are commonly used to describe the processing and rendering of data within XML files, rule detects when adversaries abuse this functionality to execute arbitrary files while potentially bypassing application whitelisting defenses |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1220: XSL Script Processing](https://attack.mitre.org/techniques/T1220)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1220: XSL Script Processing](../Triggers/T1220.md)</li></ul>  |
| **Severity Level**       | medium |
| **False Positives**      | <ul><li>WMIC.exe FP depend on scripts and administrative methods used in the monitored environment</li><li>msxsl.exe is not installed by default so unlikely.</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1220/T1220.yaml](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1220/T1220.yaml)</li></ul>  |
| **Author**               | Timur Zinniatullin, oscd.community |


## Detection Rules

### Sigma rule

```
title: XSL Script Processing
id: 05c36dd6-79d6-4a9a-97da-3db20298ab2d
status: experimental
description: Extensible Stylesheet Language (XSL) files are commonly used to describe the processing and rendering of data within XML files, rule detects when adversaries
    abuse this functionality to execute arbitrary files while potentially bypassing application whitelisting defenses
author: Timur Zinniatullin, oscd.community
date: 2019/10/21
modified: 2019/11/04
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1220/T1220.yaml
logsource:
    category: process_creation
    product: windows
detection:
    selection:
      - Image|endswith: '\wmic.exe'
        CommandLine|contains: '/format' # wmic process list /FORMAT /?
      - Image|endswith: '\msxsl.exe'
    condition: selection
falsepositives:
    - WMIC.exe FP depend on scripts and administrative methods used in the monitored environment
    - msxsl.exe is not installed by default so unlikely.
level: medium
tags:
    - attack.defense_evasion
    - attack.t1220
    - attack.execution # an old one

```





### powershell
    
```
Get-WinEvent | where {(($_.message -match "Image.*.*\\\\wmic.exe" -and $_.message -match "CommandLine.*.*/format.*") -or $_.message -match "Image.*.*\\\\msxsl.exe") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
((winlog.event_data.Image.keyword:*\\\\wmic.exe AND winlog.event_data.CommandLine.keyword:*\\/format*) OR winlog.event_data.Image.keyword:*\\\\msxsl.exe)
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/05c36dd6-79d6-4a9a-97da-3db20298ab2d <<EOF\n{\n  "metadata": {\n    "title": "XSL Script Processing",\n    "description": "Extensible Stylesheet Language (XSL) files are commonly used to describe the processing and rendering of data within XML files, rule detects when adversaries abuse this functionality to execute arbitrary files while potentially bypassing application whitelisting defenses",\n    "tags": [\n      "attack.defense_evasion",\n      "attack.t1220",\n      "attack.execution"\n    ],\n    "query": "((winlog.event_data.Image.keyword:*\\\\\\\\wmic.exe AND winlog.event_data.CommandLine.keyword:*\\\\/format*) OR winlog.event_data.Image.keyword:*\\\\\\\\msxsl.exe)"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "((winlog.event_data.Image.keyword:*\\\\\\\\wmic.exe AND winlog.event_data.CommandLine.keyword:*\\\\/format*) OR winlog.event_data.Image.keyword:*\\\\\\\\msxsl.exe)",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": [\n          "winlogbeat-*"\n        ]\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "throttle_period": "15m",\n      "email": {\n        "profile": "standard",\n        "from": "root@localhost",\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'XSL Script Processing\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
((Image.keyword:*\\\\wmic.exe AND CommandLine.keyword:*\\/format*) OR Image.keyword:*\\\\msxsl.exe)
```


### splunk
    
```
((Image="*\\\\wmic.exe" CommandLine="*/format*") OR Image="*\\\\msxsl.exe")
```


### logpoint
    
```
((Image="*\\\\wmic.exe" CommandLine="*/format*") OR Image="*\\\\msxsl.exe")
```


### grep
    
```
grep -P '^(?:.*(?:.*(?:.*(?=.*.*\\wmic\\.exe)(?=.*.*/format.*))|.*.*\\msxsl\\.exe))'
```



