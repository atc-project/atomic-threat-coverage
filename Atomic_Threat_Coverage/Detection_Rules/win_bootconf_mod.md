| Title                | Modification of Boot Configuration                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Identifies use of the bcdedit command to delete boot configuration data. This tactic is sometimes used as by malware or an attacker as a destructive technique.                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0040: Impact](https://attack.mitre.org/tactics/TA0040)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1490: Inhibit System Recovery](https://attack.mitre.org/techniques/T1490)</li></ul>  |
| Data Needed          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| Trigger              | <ul><li>[T1490: Inhibit System Recovery](../Triggers/T1490.md)</li></ul>  |
| Severity Level       | high |
| False Positives      | <ul><li>Unlikely</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1490/T1490.yaml](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1490/T1490.yaml)</li><li>[https://eqllib.readthedocs.io/en/latest/analytics/c4732632-9c1d-4980-9fa8-1d98c93f918e.html](https://eqllib.readthedocs.io/en/latest/analytics/c4732632-9c1d-4980-9fa8-1d98c93f918e.html)</li></ul>  |
| Author               | E.M. Anhaus (orignally from Atomic Blue Detections, Endgame), oscd.community |


## Detection Rules

### Sigma rule

```
title: Modification of Boot Configuration
id: 1444443e-6757-43e4-9ea4-c8fc705f79a2
description: Identifies use of the bcdedit command to delete boot configuration data. This tactic is sometimes used as by malware or an attacker as a destructive
    technique.
status: experimental
author: E.M. Anhaus (orignally from Atomic Blue Detections, Endgame), oscd.community
date: 2019/10/24
modified: 2019/11/11
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1490/T1490.yaml
    - https://eqllib.readthedocs.io/en/latest/analytics/c4732632-9c1d-4980-9fa8-1d98c93f918e.html
tags:
    - attack.impact
    - attack.t1490
logsource:
    category: process_creation
    product: windows
detection:
    selection1:
        Image|endswith: \bcdedit.exe
        CommandLine: set
    selection2:
        - CommandLine|contains|all:
            - bootstatuspolicy
            - ignoreallfailures
        - CommandLine|contains|all:
            - recoveryenabled
            - 'no'
    condition: selection1 and selection2
fields:
    - ComputerName
    - User
    - CommandLine
falsepositives:
    - Unlikely
level: high

```





### es-qs
    
```
((Image.keyword:*\\\\bcdedit.exe AND CommandLine:"set") AND ((CommandLine.keyword:*bootstatuspolicy* AND CommandLine.keyword:*ignoreallfailures*) OR (CommandLine.keyword:*recoveryenabled* AND CommandLine.keyword:*no*)))
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/1444443e-6757-43e4-9ea4-c8fc705f79a2 <<EOF\n{\n  "metadata": {\n    "title": "Modification of Boot Configuration",\n    "description": "Identifies use of the bcdedit command to delete boot configuration data. This tactic is sometimes used as by malware or an attacker as a destructive technique.",\n    "tags": [\n      "attack.impact",\n      "attack.t1490"\n    ],\n    "query": "((Image.keyword:*\\\\\\\\bcdedit.exe AND CommandLine:\\"set\\") AND ((CommandLine.keyword:*bootstatuspolicy* AND CommandLine.keyword:*ignoreallfailures*) OR (CommandLine.keyword:*recoveryenabled* AND CommandLine.keyword:*no*)))"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "((Image.keyword:*\\\\\\\\bcdedit.exe AND CommandLine:\\"set\\") AND ((CommandLine.keyword:*bootstatuspolicy* AND CommandLine.keyword:*ignoreallfailures*) OR (CommandLine.keyword:*recoveryenabled* AND CommandLine.keyword:*no*)))",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Modification of Boot Configuration\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}Hit on {{_source.@timestamp}}:\\nComputerName = {{_source.ComputerName}}\\n        User = {{_source.User}}\\n CommandLine = {{_source.CommandLine}}================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
((Image.keyword:*\\\\bcdedit.exe AND CommandLine:"set") AND ((CommandLine.keyword:*bootstatuspolicy* AND CommandLine.keyword:*ignoreallfailures*) OR (CommandLine.keyword:*recoveryenabled* AND CommandLine.keyword:*no*)))
```


### splunk
    
```
((Image="*\\\\bcdedit.exe" CommandLine="set") ((CommandLine="*bootstatuspolicy*" CommandLine="*ignoreallfailures*") OR (CommandLine="*recoveryenabled*" CommandLine="*no*"))) | table ComputerName,User,CommandLine
```


### logpoint
    
```
(event_id="1" (Image="*\\\\bcdedit.exe" CommandLine="set") ((CommandLine="*bootstatuspolicy*" CommandLine="*ignoreallfailures*") OR (CommandLine="*recoveryenabled*" CommandLine="*no*")))
```


### grep
    
```
grep -P '^(?:.*(?=.*(?:.*(?=.*.*\\bcdedit\\.exe)(?=.*set)))(?=.*(?:.*(?:.*(?:.*(?=.*.*bootstatuspolicy.*)(?=.*.*ignoreallfailures.*))|.*(?:.*(?=.*.*recoveryenabled.*)(?=.*.*no.*))))))'
```



