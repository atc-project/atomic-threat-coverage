| Title                | File or folder permissions modifications                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects a file or folder permissions modifications                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1222: File Permissions Modification](https://attack.mitre.org/techniques/T1222)</li></ul>  |
| Data Needed          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| Trigger              | <ul><li>[T1222: File Permissions Modification](../Triggers/T1222.md)</li></ul>  |
| Severity Level       | medium |
| False Positives      | <ul><li>Users interacting with the files on their own (unlikely unless power users)</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1222/T1222.yaml](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1222/T1222.yaml)</li></ul>  |
| Author               | Jakob Weinzettl, oscd.community |


## Detection Rules

### Sigma rule

```
title: File or folder permissions modifications
id: 37ae075c-271b-459b-8d7b-55ad5f993dd8
status: experimental
description: Detects a file or folder permissions modifications
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1222/T1222.yaml
author: Jakob Weinzettl, oscd.community
date: 2019/10/23
modified: 2019/11/08
tags:
    - attack.defense_evasion
    - attack.t1222
logsource:
    category: process_creation
    product: windows
detection:
    selection:
      - Image|endswith: '\takeown.exe'
      - Image|endswith: 
            - '\cacls.exe'
            - '\icacls.exe'
        CommandLine|contains: '/grant'
      - Image|endswith: '\attrib.exe'
        CommandLine|contains: '-r'
    condition: selection
falsepositives:
    - Users interacting with the files on their own (unlikely unless power users)
level: medium

```





### es-qs
    
```
(Image.keyword:*\\\\takeown.exe OR (Image.keyword:(*\\\\cacls.exe OR *\\\\icacls.exe) AND CommandLine.keyword:*\\/grant*) OR (Image.keyword:*\\\\attrib.exe AND CommandLine.keyword:*\\-r*))
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/File-or-folder-permissions-modifications <<EOF\n{\n  "metadata": {\n    "title": "File or folder permissions modifications",\n    "description": "Detects a file or folder permissions modifications",\n    "tags": [\n      "attack.defense_evasion",\n      "attack.t1222"\n    ],\n    "query": "(Image.keyword:*\\\\\\\\takeown.exe OR (Image.keyword:(*\\\\\\\\cacls.exe OR *\\\\\\\\icacls.exe) AND CommandLine.keyword:*\\\\/grant*) OR (Image.keyword:*\\\\\\\\attrib.exe AND CommandLine.keyword:*\\\\-r*))"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "(Image.keyword:*\\\\\\\\takeown.exe OR (Image.keyword:(*\\\\\\\\cacls.exe OR *\\\\\\\\icacls.exe) AND CommandLine.keyword:*\\\\/grant*) OR (Image.keyword:*\\\\\\\\attrib.exe AND CommandLine.keyword:*\\\\-r*))",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'File or folder permissions modifications\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
(Image.keyword:*\\\\takeown.exe OR (Image.keyword:(*\\\\cacls.exe *\\\\icacls.exe) AND CommandLine.keyword:*\\/grant*) OR (Image.keyword:*\\\\attrib.exe AND CommandLine.keyword:*\\-r*))
```


### splunk
    
```
(Image="*\\\\takeown.exe" OR ((Image="*\\\\cacls.exe" OR Image="*\\\\icacls.exe") CommandLine="*/grant*") OR (Image="*\\\\attrib.exe" CommandLine="*-r*"))
```


### logpoint
    
```
(event_id="1" (Image="*\\\\takeown.exe" OR (Image IN ["*\\\\cacls.exe", "*\\\\icacls.exe"] CommandLine="*/grant*") OR (Image="*\\\\attrib.exe" CommandLine="*-r*")))
```


### grep
    
```
grep -P '^(?:.*(?:.*.*\\takeown\\.exe|.*(?:.*(?=.*(?:.*.*\\cacls\\.exe|.*.*\\icacls\\.exe))(?=.*.*/grant.*))|.*(?:.*(?=.*.*\\attrib\\.exe)(?=.*.*-r.*))))'
```



