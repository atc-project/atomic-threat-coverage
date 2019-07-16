| Title                | LockerGoga Ransomware                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects a command that clears the WMI trace log which indicates LockaerGoga ransomware activity                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1064: Scripting](https://attack.mitre.org/techniques/T1064)</li></ul>  |
| Data Needed          | <ul><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1064: Scripting](../Triggers/T1064.md)</li></ul>  |
| Severity Level       | high |
| False Positives      |  There are no documented False Positives for this Detection Rule yet  |
| Development Status   |  Development Status wasn't defined for this Detection Rule yet  |
| References           | <ul><li>[https://abuse.io/lockergoga.txt](https://abuse.io/lockergoga.txt)</li></ul>  |
| Author               | Florian Roth |


## Detection Rules

### Sigma rule

```
title: LockerGoga Ransomware
description: Detects a command that clears the WMI trace log which indicates LockaerGoga ransomware activity
references:
    - https://abuse.io/lockergoga.txt
author: Florian Roth
date: 2019/03/22
tags:
    - attack.execution
    - attack.t1064    
level: high
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine: '* cl Microsoft-Windows-WMI-Activity/Trace'
    condition: selection


```





### es-qs
    
```
CommandLine.keyword:*\\ cl\\ Microsoft\\-Windows\\-WMI\\-Activity\\/Trace
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/LockerGoga-Ransomware <<EOF\n{\n  "metadata": {\n    "title": "LockerGoga Ransomware",\n    "description": "Detects a command that clears the WMI trace log which indicates LockaerGoga ransomware activity",\n    "tags": [\n      "attack.execution",\n      "attack.t1064"\n    ],\n    "query": "CommandLine.keyword:*\\\\ cl\\\\ Microsoft\\\\-Windows\\\\-WMI\\\\-Activity\\\\/Trace"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "CommandLine.keyword:*\\\\ cl\\\\ Microsoft\\\\-Windows\\\\-WMI\\\\-Activity\\\\/Trace",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'LockerGoga Ransomware\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
CommandLine:"* cl Microsoft\\-Windows\\-WMI\\-Activity\\/Trace"
```


### splunk
    
```
CommandLine="* cl Microsoft-Windows-WMI-Activity/Trace"
```


### logpoint
    
```
CommandLine="* cl Microsoft-Windows-WMI-Activity/Trace"
```


### grep
    
```
grep -P '^.* cl Microsoft-Windows-WMI-Activity/Trace'
```



