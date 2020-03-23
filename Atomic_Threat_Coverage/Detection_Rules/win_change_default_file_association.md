| Title                | Change Default File Association                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | When a file is opened, the default program used to open the file (also called the file association or handler) is checked. File association selections are stored in the Windows Registry and can be edited by users, administrators, or programs that have Registry access or by administrators using the built-in assoc utility. Applications can modify the file association for a given file extension to call an arbitrary program when a file with the given extension is opened.                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0003: Persistence](https://attack.mitre.org/tactics/TA0003)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1042: Change Default File Association](https://attack.mitre.org/techniques/T1042)</li></ul>  |
| Data Needed          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| Trigger              | <ul><li>[T1042: Change Default File Association](../Triggers/T1042.md)</li></ul>  |
| Severity Level       | low |
| False Positives      | <ul><li>Admin activity</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1042/T1042.yaml](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1042/T1042.yaml)</li></ul>  |
| Author               | Timur Zinniatullin, oscd.community |


## Detection Rules

### Sigma rule

```
title: Change Default File Association
id: 3d3aa6cd-6272-44d6-8afc-7e88dfef7061
status: experimental
description: When a file is opened, the default program used to open the file (also called the file association or handler) is checked. File association selections
    are stored in the Windows Registry and can be edited by users, administrators, or programs that have Registry access or by administrators using the built-in assoc
    utility. Applications can modify the file association for a given file extension to call an arbitrary program when a file with the given extension is opened.
author: Timur Zinniatullin, oscd.community
date: 2019/10/21
modified: 2019/11/04
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1042/T1042.yaml
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains|all:
          - 'cmd'
          - '/c'
          - 'assoc'
    condition: selection
falsepositives:
    - Admin activity
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
    - attack.persistence
    - attack.t1042

```





### es-qs
    
```
(CommandLine.keyword:*cmd* AND CommandLine.keyword:*\\/c* AND CommandLine.keyword:*assoc*)
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/3d3aa6cd-6272-44d6-8afc-7e88dfef7061 <<EOF\n{\n  "metadata": {\n    "title": "Change Default File Association",\n    "description": "When a file is opened, the default program used to open the file (also called the file association or handler) is checked. File association selections are stored in the Windows Registry and can be edited by users, administrators, or programs that have Registry access or by administrators using the built-in assoc utility. Applications can modify the file association for a given file extension to call an arbitrary program when a file with the given extension is opened.",\n    "tags": [\n      "attack.persistence",\n      "attack.t1042"\n    ],\n    "query": "(CommandLine.keyword:*cmd* AND CommandLine.keyword:*\\\\/c* AND CommandLine.keyword:*assoc*)"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "(CommandLine.keyword:*cmd* AND CommandLine.keyword:*\\\\/c* AND CommandLine.keyword:*assoc*)",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Change Default File Association\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}Hit on {{_source.@timestamp}}:\\n            Image = {{_source.Image}}\\n      CommandLine = {{_source.CommandLine}}\\n             User = {{_source.User}}\\n        LogonGuid = {{_source.LogonGuid}}\\n           Hashes = {{_source.Hashes}}\\nParentProcessGuid = {{_source.ParentProcessGuid}}\\nParentCommandLine = {{_source.ParentCommandLine}}================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
(CommandLine.keyword:*cmd* AND CommandLine.keyword:*\\/c* AND CommandLine.keyword:*assoc*)
```


### splunk
    
```
(CommandLine="*cmd*" CommandLine="*/c*" CommandLine="*assoc*") | table Image,CommandLine,User,LogonGuid,Hashes,ParentProcessGuid,ParentCommandLine
```


### logpoint
    
```
(event_id="1" CommandLine="*cmd*" CommandLine="*/c*" CommandLine="*assoc*")
```


### grep
    
```
grep -P '^(?:.*(?=.*.*cmd.*)(?=.*.*/c.*)(?=.*.*assoc.*))'
```



