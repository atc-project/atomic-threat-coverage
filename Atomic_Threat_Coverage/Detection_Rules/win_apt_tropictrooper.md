| Title                    | TropicTrooper Campaign November 2018       |
|:-------------------------|:------------------|
| **Description**          | Detects TropicTrooper activity, an actor who targeted high-profile organizations in the energy and food and beverage sectors in Asia |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1085: Rundll32](https://attack.mitre.org/techniques/T1085)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1085: Rundll32](../Triggers/T1085.md)</li></ul>  |
| **Severity Level**       | high |
| **False Positives**      |  There are no documented False Positives for this Detection Rule yet  |
| **Development Status**   | stable |
| **References**           | <ul><li>[https://cloudblogs.microsoft.com/microsoftsecure/2018/11/28/windows-defender-atp-device-risk-score-exposes-new-cyberattack-drives-conditional-access-to-protect-networks/](https://cloudblogs.microsoft.com/microsoftsecure/2018/11/28/windows-defender-atp-device-risk-score-exposes-new-cyberattack-drives-conditional-access-to-protect-networks/)</li></ul>  |
| **Author**               | @41thexplorer, Microsoft Defender ATP |


## Detection Rules

### Sigma rule

```
title: TropicTrooper Campaign November 2018
id: 8c7090c3-e0a0-4944-bd08-08c3a0cecf79
author: '@41thexplorer, Microsoft Defender ATP'
status: stable
date: 2019/11/12
description: Detects TropicTrooper activity, an actor who targeted high-profile organizations in the energy and food and beverage sectors in Asia
references:
    - https://cloudblogs.microsoft.com/microsoftsecure/2018/11/28/windows-defender-atp-device-risk-score-exposes-new-cyberattack-drives-conditional-access-to-protect-networks/
tags:
    - attack.execution
    - attack.t1085
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine: '*abCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCc*'
    condition: selection
level: high

```





### es-qs
    
```
CommandLine.keyword:*abCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCc*
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/8c7090c3-e0a0-4944-bd08-08c3a0cecf79 <<EOF\n{\n  "metadata": {\n    "title": "TropicTrooper Campaign November 2018",\n    "description": "Detects TropicTrooper activity, an actor who targeted high-profile organizations in the energy and food and beverage sectors in Asia",\n    "tags": [\n      "attack.execution",\n      "attack.t1085"\n    ],\n    "query": "CommandLine.keyword:*abCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCc*"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "CommandLine.keyword:*abCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCc*",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'TropicTrooper Campaign November 2018\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
CommandLine.keyword:*abCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCc*
```


### splunk
    
```
CommandLine="*abCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCc*"
```


### logpoint
    
```
(event_id="1" CommandLine="*abCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCc*")
```


### grep
    
```
grep -P '^.*abCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCc.*'
```



