| Title                | Shadow copies deletion using operating systems utilities                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Shadow Copies deletion using operating systems utilities                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li><li>[TA0040: Impact](https://attack.mitre.org/tactics/TA0040)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1070: Indicator Removal on Host](https://attack.mitre.org/techniques/T1070)</li><li>[T1490: Inhibit System Recovery](https://attack.mitre.org/techniques/T1490)</li></ul>  |
| Data Needed          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1070: Indicator Removal on Host](../Triggers/T1070.md)</li><li>[T1490: Inhibit System Recovery](../Triggers/T1490.md)</li></ul>  |
| Severity Level       | medium |
| False Positives      | <ul><li>Legitimate Administrator deletes Shadow Copies using operating systems utilities for legitimate reason</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[https://www.slideshare.net/heirhabarov/hunting-for-credentials-dumping-in-windows-environment](https://www.slideshare.net/heirhabarov/hunting-for-credentials-dumping-in-windows-environment)</li><li>[https://blog.talosintelligence.com/2017/05/wannacry.html](https://blog.talosintelligence.com/2017/05/wannacry.html)</li><li>[https://securingtomorrow.mcafee.com/other-blogs/mcafee-labs/new-teslacrypt-ransomware-arrives-via-spam/](https://securingtomorrow.mcafee.com/other-blogs/mcafee-labs/new-teslacrypt-ransomware-arrives-via-spam/)</li></ul>  |
| Author               | Florian Roth, Michael Haag, Teymur Kheirkhabarov, Daniil Yugoslavskiy, oscd.community |


## Detection Rules

### Sigma rule

```
title: Shadow copies deletion using operating systems utilities
id: c947b146-0abc-4c87-9c64-b17e9d7274a2
description: Shadow Copies deletion using operating systems utilities
author: Florian Roth, Michael Haag, Teymur Kheirkhabarov, Daniil Yugoslavskiy, oscd.community
date: 2019/10/22
references:
    - https://www.slideshare.net/heirhabarov/hunting-for-credentials-dumping-in-windows-environment
    - https://blog.talosintelligence.com/2017/05/wannacry.html
    - https://securingtomorrow.mcafee.com/other-blogs/mcafee-labs/new-teslacrypt-ransomware-arrives-via-spam/
tags:
    - attack.defense_evasion
    - attack.impact
    - attack.t1070
    - attack.t1490
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        NewProcessName|endswith:
            - '\powershell.exe'
            - '\wmic.exe'
            - '\vssadmin.exe'
        CommandLine|contains|all:
            - shadow
            - delete
    condition: selection
falsepositives:
    - Legitimate Administrator deletes Shadow Copies using operating systems utilities for legitimate reason
status: experimental
level: medium

```





### es-qs
    
```
(NewProcessName.keyword:(*\\\\powershell.exe OR *\\\\wmic.exe OR *\\\\vssadmin.exe) AND CommandLine.keyword:*shadow* AND CommandLine.keyword:*delete*)
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/Shadow-copies-deletion-using-operating-systems-utilities <<EOF\n{\n  "metadata": {\n    "title": "Shadow copies deletion using operating systems utilities",\n    "description": "Shadow Copies deletion using operating systems utilities",\n    "tags": [\n      "attack.defense_evasion",\n      "attack.impact",\n      "attack.t1070",\n      "attack.t1490"\n    ],\n    "query": "(NewProcessName.keyword:(*\\\\\\\\powershell.exe OR *\\\\\\\\wmic.exe OR *\\\\\\\\vssadmin.exe) AND CommandLine.keyword:*shadow* AND CommandLine.keyword:*delete*)"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "(NewProcessName.keyword:(*\\\\\\\\powershell.exe OR *\\\\\\\\wmic.exe OR *\\\\\\\\vssadmin.exe) AND CommandLine.keyword:*shadow* AND CommandLine.keyword:*delete*)",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Shadow copies deletion using operating systems utilities\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
(NewProcessName.keyword:(*\\\\powershell.exe *\\\\wmic.exe *\\\\vssadmin.exe) AND CommandLine.keyword:*shadow* AND CommandLine.keyword:*delete*)
```


### splunk
    
```
((NewProcessName="*\\\\powershell.exe" OR NewProcessName="*\\\\wmic.exe" OR NewProcessName="*\\\\vssadmin.exe") CommandLine="*shadow*" CommandLine="*delete*")
```


### logpoint
    
```
(event_id="1" NewProcessName IN ["*\\\\powershell.exe", "*\\\\wmic.exe", "*\\\\vssadmin.exe"] CommandLine="*shadow*" CommandLine="*delete*")
```


### grep
    
```
grep -P '^(?:.*(?=.*(?:.*.*\\powershell\\.exe|.*.*\\wmic\\.exe|.*.*\\vssadmin\\.exe))(?=.*.*shadow.*)(?=.*.*delete.*))'
```



