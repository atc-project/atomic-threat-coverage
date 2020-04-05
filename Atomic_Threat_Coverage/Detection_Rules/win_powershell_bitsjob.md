| Title                    | Suspicious Bitsadmin Job via PowerShell       |
|:-------------------------|:------------------|
| **Description**          | Detect download by BITS jobs via PowerShell |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li><li>[TA0003: Persistence](https://attack.mitre.org/tactics/TA0003)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1197: BITS Jobs](https://attack.mitre.org/techniques/T1197)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1197: BITS Jobs](../Triggers/T1197.md)</li></ul>  |
| **Severity Level**       | medium |
| **False Positives**      | <ul><li>Unknown</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://eqllib.readthedocs.io/en/latest/analytics/ec5180c9-721a-460f-bddc-27539a284273.html](https://eqllib.readthedocs.io/en/latest/analytics/ec5180c9-721a-460f-bddc-27539a284273.html)</li><li>[https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1197/T1197.md](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1197/T1197.md)</li></ul>  |
| **Author**               | Endgame, JHasenbusch (ported to sigma for oscd.community) |


## Detection Rules

### Sigma rule

```
title: Suspicious Bitsadmin Job via PowerShell
id: f67dbfce-93bc-440d-86ad-a95ae8858c90
status: experimental
description: Detect download by BITS jobs via PowerShell
references:
    - https://eqllib.readthedocs.io/en/latest/analytics/ec5180c9-721a-460f-bddc-27539a284273.html
    - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1197/T1197.md
author: Endgame, JHasenbusch (ported to sigma for oscd.community)
date: 2018/10/30
modified: 2019/11/11
tags:
    - attack.defense_evasion
    - attack.persistence
    - attack.t1197
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\powershell.exe'
        CommandLine|contains: 'Start-BitsTransfer'
    condition: selection
fields:
    - ComputerName
    - User
    - CommandLine
falsepositives:
    - Unknown
level: medium

```





### es-qs
    
```
(Image.keyword:*\\\\powershell.exe AND CommandLine.keyword:*Start\\-BitsTransfer*)
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/f67dbfce-93bc-440d-86ad-a95ae8858c90 <<EOF\n{\n  "metadata": {\n    "title": "Suspicious Bitsadmin Job via PowerShell",\n    "description": "Detect download by BITS jobs via PowerShell",\n    "tags": [\n      "attack.defense_evasion",\n      "attack.persistence",\n      "attack.t1197"\n    ],\n    "query": "(Image.keyword:*\\\\\\\\powershell.exe AND CommandLine.keyword:*Start\\\\-BitsTransfer*)"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "(Image.keyword:*\\\\\\\\powershell.exe AND CommandLine.keyword:*Start\\\\-BitsTransfer*)",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Suspicious Bitsadmin Job via PowerShell\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}Hit on {{_source.@timestamp}}:\\nComputerName = {{_source.ComputerName}}\\n        User = {{_source.User}}\\n CommandLine = {{_source.CommandLine}}================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
(Image.keyword:*\\\\powershell.exe AND CommandLine.keyword:*Start\\-BitsTransfer*)
```


### splunk
    
```
(Image="*\\\\powershell.exe" CommandLine="*Start-BitsTransfer*") | table ComputerName,User,CommandLine
```


### logpoint
    
```
(event_id="1" Image="*\\\\powershell.exe" CommandLine="*Start-BitsTransfer*")
```


### grep
    
```
grep -P '^(?:.*(?=.*.*\\powershell\\.exe)(?=.*.*Start-BitsTransfer.*))'
```



