| Title                    | Query Registry       |
|:-------------------------|:------------------|
| **Description**          | Adversaries may interact with the Windows Registry to gather information about the system, configuration, and installed software. |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0007: Discovery](https://attack.mitre.org/tactics/TA0007)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1012: Query Registry](https://attack.mitre.org/techniques/T1012)</li><li>[T1007: System Service Discovery](https://attack.mitre.org/techniques/T1007)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1012: Query Registry](../Triggers/T1012.md)</li><li>[T1007: System Service Discovery](../Triggers/T1007.md)</li></ul>  |
| **Severity Level**       | low |
| **False Positives**      |  There are no documented False Positives for this Detection Rule yet  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1012/T1012.yaml](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1012/T1012.yaml)</li></ul>  |
| **Author**               | Timur Zinniatullin, oscd.community |


## Detection Rules

### Sigma rule

```
title: Query Registry
id: 970007b7-ce32-49d0-a4a4-fbef016950bd
status: experimental
description: Adversaries may interact with the Windows Registry to gather information about the system, configuration, and installed software.
author: Timur Zinniatullin, oscd.community
date: 2019/10/21
modified: 2019/11/04
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1012/T1012.yaml
logsource:
    category: process_creation
    product: windows
detection:
    selection_1:
        Image|endswith: '\reg.exe'
        CommandLine|contains: 
            - 'query'
            - 'save'
            - 'export'
    selection_2:
        CommandLine|contains:
            - 'currentVersion\windows'
            - 'currentVersion\runServicesOnce'
            - 'currentVersion\runServices'
            - 'winlogon\'
            - 'currentVersion\shellServiceObjectDelayLoad'
            - 'currentVersion\runOnce'
            - 'currentVersion\runOnceEx'
            - 'currentVersion\run'
            - 'currentVersion\policies\explorer\run'
            - 'currentcontrolset\services'
    condition: selection_1 and selection_2
fields:
    - Image
    - CommandLine
    - User
    - LogonGuid
    - Hashes
    - ParentProcessGuid
    - ParentCommandLine
level: low
tags:
    - attack.discovery
    - attack.t1012
    - attack.t1007

```





### es-qs
    
```
(Image.keyword:*\\\\reg.exe AND CommandLine.keyword:(*query* OR *save* OR *export*) AND CommandLine.keyword:(*currentVersion\\\\windows* OR *currentVersion\\\\runServicesOnce* OR *currentVersion\\\\runServices* OR *winlogon\\\\* OR *currentVersion\\\\shellServiceObjectDelayLoad* OR *currentVersion\\\\runOnce* OR *currentVersion\\\\runOnceEx* OR *currentVersion\\\\run* OR *currentVersion\\\\policies\\\\explorer\\\\run* OR *currentcontrolset\\\\services*))
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/970007b7-ce32-49d0-a4a4-fbef016950bd <<EOF\n{\n  "metadata": {\n    "title": "Query Registry",\n    "description": "Adversaries may interact with the Windows Registry to gather information about the system, configuration, and installed software.",\n    "tags": [\n      "attack.discovery",\n      "attack.t1012",\n      "attack.t1007"\n    ],\n    "query": "(Image.keyword:*\\\\\\\\reg.exe AND CommandLine.keyword:(*query* OR *save* OR *export*) AND CommandLine.keyword:(*currentVersion\\\\\\\\windows* OR *currentVersion\\\\\\\\runServicesOnce* OR *currentVersion\\\\\\\\runServices* OR *winlogon\\\\\\\\* OR *currentVersion\\\\\\\\shellServiceObjectDelayLoad* OR *currentVersion\\\\\\\\runOnce* OR *currentVersion\\\\\\\\runOnceEx* OR *currentVersion\\\\\\\\run* OR *currentVersion\\\\\\\\policies\\\\\\\\explorer\\\\\\\\run* OR *currentcontrolset\\\\\\\\services*))"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "(Image.keyword:*\\\\\\\\reg.exe AND CommandLine.keyword:(*query* OR *save* OR *export*) AND CommandLine.keyword:(*currentVersion\\\\\\\\windows* OR *currentVersion\\\\\\\\runServicesOnce* OR *currentVersion\\\\\\\\runServices* OR *winlogon\\\\\\\\* OR *currentVersion\\\\\\\\shellServiceObjectDelayLoad* OR *currentVersion\\\\\\\\runOnce* OR *currentVersion\\\\\\\\runOnceEx* OR *currentVersion\\\\\\\\run* OR *currentVersion\\\\\\\\policies\\\\\\\\explorer\\\\\\\\run* OR *currentcontrolset\\\\\\\\services*))",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Query Registry\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}Hit on {{_source.@timestamp}}:\\n            Image = {{_source.Image}}\\n      CommandLine = {{_source.CommandLine}}\\n             User = {{_source.User}}\\n        LogonGuid = {{_source.LogonGuid}}\\n           Hashes = {{_source.Hashes}}\\nParentProcessGuid = {{_source.ParentProcessGuid}}\\nParentCommandLine = {{_source.ParentCommandLine}}================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
(Image.keyword:*\\\\reg.exe AND CommandLine.keyword:(*query* *save* *export*) AND CommandLine.keyword:(*currentVersion\\\\windows* *currentVersion\\\\runServicesOnce* *currentVersion\\\\runServices* *winlogon\\\\* *currentVersion\\\\shellServiceObjectDelayLoad* *currentVersion\\\\runOnce* *currentVersion\\\\runOnceEx* *currentVersion\\\\run* *currentVersion\\\\policies\\\\explorer\\\\run* *currentcontrolset\\\\services*))
```


### splunk
    
```
(Image="*\\\\reg.exe" (CommandLine="*query*" OR CommandLine="*save*" OR CommandLine="*export*") (CommandLine="*currentVersion\\\\windows*" OR CommandLine="*currentVersion\\\\runServicesOnce*" OR CommandLine="*currentVersion\\\\runServices*" OR CommandLine="*winlogon\\\\*" OR CommandLine="*currentVersion\\\\shellServiceObjectDelayLoad*" OR CommandLine="*currentVersion\\\\runOnce*" OR CommandLine="*currentVersion\\\\runOnceEx*" OR CommandLine="*currentVersion\\\\run*" OR CommandLine="*currentVersion\\\\policies\\\\explorer\\\\run*" OR CommandLine="*currentcontrolset\\\\services*")) | table Image,CommandLine,User,LogonGuid,Hashes,ParentProcessGuid,ParentCommandLine
```


### logpoint
    
```
(event_id="1" Image="*\\\\reg.exe" CommandLine IN ["*query*", "*save*", "*export*"] CommandLine IN ["*currentVersion\\\\windows*", "*currentVersion\\\\runServicesOnce*", "*currentVersion\\\\runServices*", "*winlogon\\\\*", "*currentVersion\\\\shellServiceObjectDelayLoad*", "*currentVersion\\\\runOnce*", "*currentVersion\\\\runOnceEx*", "*currentVersion\\\\run*", "*currentVersion\\\\policies\\\\explorer\\\\run*", "*currentcontrolset\\\\services*"])
```


### grep
    
```
grep -P '^(?:.*(?=.*.*\\reg\\.exe)(?=.*(?:.*.*query.*|.*.*save.*|.*.*export.*))(?=.*(?:.*.*currentVersion\\windows.*|.*.*currentVersion\\runServicesOnce.*|.*.*currentVersion\\runServices.*|.*.*winlogon\\\\.*|.*.*currentVersion\\shellServiceObjectDelayLoad.*|.*.*currentVersion\\runOnce.*|.*.*currentVersion\\runOnceEx.*|.*.*currentVersion\\run.*|.*.*currentVersion\\policies\\explorer\\run.*|.*.*currentcontrolset\\services.*)))'
```



