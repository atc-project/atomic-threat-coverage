| Title                    | Devtoolslauncher.exe Executes Specified Binary       |
|:-------------------------|:------------------|
| **Description**          | The Devtoolslauncher.exe executes other binary |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1218: Signed Binary Proxy Execution](https://attack.mitre.org/techniques/T1218)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1218: Signed Binary Proxy Execution](../Triggers/T1218.md)</li></ul>  |
| **Severity Level**       | critical |
| **False Positives**      | <ul><li>Legitimate use of devtoolslauncher.exe by legitimate user</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://github.com/LOLBAS-Project/LOLBAS/blob/master/yml/OtherMSBinaries/Devtoolslauncher.yml](https://github.com/LOLBAS-Project/LOLBAS/blob/master/yml/OtherMSBinaries/Devtoolslauncher.yml)</li><li>[https://twitter.com/_felamos/status/1179811992841797632](https://twitter.com/_felamos/status/1179811992841797632)</li></ul>  |
| **Author**               | Beyu Denis, oscd.community (rule), @_felamos (idea) |


## Detection Rules

### Sigma rule

```
title: Devtoolslauncher.exe Executes Specified Binary
id: cc268ac1-42d9-40fd-9ed3-8c4e1a5b87e6
status: experimental
description: The Devtoolslauncher.exe executes other binary
references:
    - https://github.com/LOLBAS-Project/LOLBAS/blob/master/yml/OtherMSBinaries/Devtoolslauncher.yml
    - https://twitter.com/_felamos/status/1179811992841797632
author: Beyu Denis, oscd.community (rule), @_felamos (idea)
date: 2019/10/12
modified: 2019/11/04
tags:
    - attack.defense_evasion
    - attack.execution
    - attack.t1218
level: critical
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\devtoolslauncher.exe'
        CommandLine|contains: 'LaunchForDeploy'
    condition: selection
falsepositives:
    - Legitimate use of devtoolslauncher.exe by legitimate user

```





### es-qs
    
```
(Image.keyword:*\\\\devtoolslauncher.exe AND CommandLine.keyword:*LaunchForDeploy*)
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/cc268ac1-42d9-40fd-9ed3-8c4e1a5b87e6 <<EOF\n{\n  "metadata": {\n    "title": "Devtoolslauncher.exe Executes Specified Binary",\n    "description": "The Devtoolslauncher.exe executes other binary",\n    "tags": [\n      "attack.defense_evasion",\n      "attack.execution",\n      "attack.t1218"\n    ],\n    "query": "(Image.keyword:*\\\\\\\\devtoolslauncher.exe AND CommandLine.keyword:*LaunchForDeploy*)"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "(Image.keyword:*\\\\\\\\devtoolslauncher.exe AND CommandLine.keyword:*LaunchForDeploy*)",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Devtoolslauncher.exe Executes Specified Binary\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
(Image.keyword:*\\\\devtoolslauncher.exe AND CommandLine.keyword:*LaunchForDeploy*)
```


### splunk
    
```
(Image="*\\\\devtoolslauncher.exe" CommandLine="*LaunchForDeploy*")
```


### logpoint
    
```
(event_id="1" Image="*\\\\devtoolslauncher.exe" CommandLine="*LaunchForDeploy*")
```


### grep
    
```
grep -P '^(?:.*(?=.*.*\\devtoolslauncher\\.exe)(?=.*.*LaunchForDeploy.*))'
```



