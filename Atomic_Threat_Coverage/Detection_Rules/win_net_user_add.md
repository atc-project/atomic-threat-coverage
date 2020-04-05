| Title                    | Net.exe User Account Creation       |
|:-------------------------|:------------------|
| **Description**          | Identifies creation of local users via the net.exe command |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0003: Persistence](https://attack.mitre.org/tactics/TA0003)</li><li>[TA0006: Credential Access](https://attack.mitre.org/tactics/TA0006)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1136: Create Account](https://attack.mitre.org/techniques/T1136)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1136: Create Account](../Triggers/T1136.md)</li></ul>  |
| **Severity Level**       | medium |
| **False Positives**      | <ul><li>Legit user creation</li><li>Better use event ids for user creation rather than command line rules</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://eqllib.readthedocs.io/en/latest/analytics/014c3f51-89c6-40f1-ac9c-5688f26090ab.html](https://eqllib.readthedocs.io/en/latest/analytics/014c3f51-89c6-40f1-ac9c-5688f26090ab.html)</li><li>[https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1136/T1136.yaml](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1136/T1136.yaml)</li></ul>  |
| **Author**               | Endgame, JHasenbusch (adapted to sigma for oscd.community) |


## Detection Rules

### Sigma rule

```
title: Net.exe User Account Creation
id: cd219ff3-fa99-45d4-8380-a7d15116c6dc
status: experimental
description: Identifies creation of local users via the net.exe command
references:
    - https://eqllib.readthedocs.io/en/latest/analytics/014c3f51-89c6-40f1-ac9c-5688f26090ab.html
    - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1136/T1136.yaml
author: Endgame, JHasenbusch (adapted to sigma for oscd.community)
date: 2018/10/30
modified: 2019/11/11
tags:
    - attack.persistence
    - attack.credential_access
    - attack.t1136
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: 
            - '\net.exe'
            - '\net1.exe'
        CommandLine|contains|all: 
            - 'user'
            - 'add'
    condition: selection
fields:
    - ComputerName
    - User
    - CommandLine
falsepositives:
    - Legit user creation
    - Better use event ids for user creation rather than command line rules
level: medium

```





### es-qs
    
```
(Image.keyword:(*\\\\net.exe OR *\\\\net1.exe) AND CommandLine.keyword:*user* AND CommandLine.keyword:*add*)
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/cd219ff3-fa99-45d4-8380-a7d15116c6dc <<EOF\n{\n  "metadata": {\n    "title": "Net.exe User Account Creation",\n    "description": "Identifies creation of local users via the net.exe command",\n    "tags": [\n      "attack.persistence",\n      "attack.credential_access",\n      "attack.t1136"\n    ],\n    "query": "(Image.keyword:(*\\\\\\\\net.exe OR *\\\\\\\\net1.exe) AND CommandLine.keyword:*user* AND CommandLine.keyword:*add*)"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "(Image.keyword:(*\\\\\\\\net.exe OR *\\\\\\\\net1.exe) AND CommandLine.keyword:*user* AND CommandLine.keyword:*add*)",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Net.exe User Account Creation\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}Hit on {{_source.@timestamp}}:\\nComputerName = {{_source.ComputerName}}\\n        User = {{_source.User}}\\n CommandLine = {{_source.CommandLine}}================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
(Image.keyword:(*\\\\net.exe *\\\\net1.exe) AND CommandLine.keyword:*user* AND CommandLine.keyword:*add*)
```


### splunk
    
```
((Image="*\\\\net.exe" OR Image="*\\\\net1.exe") CommandLine="*user*" CommandLine="*add*") | table ComputerName,User,CommandLine
```


### logpoint
    
```
(event_id="1" Image IN ["*\\\\net.exe", "*\\\\net1.exe"] CommandLine="*user*" CommandLine="*add*")
```


### grep
    
```
grep -P '^(?:.*(?=.*(?:.*.*\\net\\.exe|.*.*\\net1\\.exe))(?=.*.*user.*)(?=.*.*add.*))'
```



