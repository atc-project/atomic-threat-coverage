| Title                | Suspicious Svchost Process                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects a suspicious svchost process start                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1036: Masquerading](https://attack.mitre.org/techniques/T1036)</li></ul>  |
| Data Needed          | <ul><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1036: Masquerading](../Triggers/T1036.md)</li></ul>  |
| Severity Level       | high |
| False Positives      | <ul><li>Unknown</li></ul>  |
| Development Status   | experimental |
| References           |  There are no documented References for this Detection Rule yet  |
| Author               | Florian Roth |


## Detection Rules

### Sigma rule

```
title: Suspicious Svchost Process
status: experimental
description: Detects a suspicious svchost process start
tags:
    - attack.defense_evasion
    - attack.t1036
author: Florian Roth
date: 2017/08/15
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image: '*\svchost.exe'
    filter:
        ParentImage:
            - '*\services.exe'
            - '*\MsMpEng.exe'
            - '*\Mrt.exe'
            - '*\rpcnet.exe'
    filter_null:
        ParentImage: null
    condition: selection and not filter and not filter_null
fields:
    - CommandLine
    - ParentCommandLine
falsepositives:
    - Unknown
level: high

```





### es-qs
    
```
((Image.keyword:*\\\\svchost.exe AND (NOT (ParentImage.keyword:(*\\\\services.exe *\\\\MsMpEng.exe *\\\\Mrt.exe *\\\\rpcnet.exe)))) AND (NOT (NOT _exists_:ParentImage)))
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/Suspicious-Svchost-Process <<EOF\n{\n  "metadata": {\n    "title": "Suspicious Svchost Process",\n    "description": "Detects a suspicious svchost process start",\n    "tags": [\n      "attack.defense_evasion",\n      "attack.t1036"\n    ],\n    "query": "((Image.keyword:*\\\\\\\\svchost.exe AND (NOT (ParentImage.keyword:(*\\\\\\\\services.exe *\\\\\\\\MsMpEng.exe *\\\\\\\\Mrt.exe *\\\\\\\\rpcnet.exe)))) AND (NOT (NOT _exists_:ParentImage)))"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "((Image.keyword:*\\\\\\\\svchost.exe AND (NOT (ParentImage.keyword:(*\\\\\\\\services.exe *\\\\\\\\MsMpEng.exe *\\\\\\\\Mrt.exe *\\\\\\\\rpcnet.exe)))) AND (NOT (NOT _exists_:ParentImage)))",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Suspicious Svchost Process\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}Hit on {{_source.@timestamp}}:\\n      CommandLine = {{_source.CommandLine}}\\nParentCommandLine = {{_source.ParentCommandLine}}================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
((Image:"*\\\\svchost.exe" AND NOT (ParentImage:("*\\\\services.exe" "*\\\\MsMpEng.exe" "*\\\\Mrt.exe" "*\\\\rpcnet.exe"))) AND NOT (NOT _exists_:ParentImage))
```


### splunk
    
```
((Image="*\\\\svchost.exe" NOT ((ParentImage="*\\\\services.exe" OR ParentImage="*\\\\MsMpEng.exe" OR ParentImage="*\\\\Mrt.exe" OR ParentImage="*\\\\rpcnet.exe"))) NOT (NOT ParentImage="*")) | table CommandLine,ParentCommandLine
```


### logpoint
    
```
((Image="*\\\\svchost.exe"  -(ParentImage IN ["*\\\\services.exe", "*\\\\MsMpEng.exe", "*\\\\Mrt.exe", "*\\\\rpcnet.exe"]))  -(-ParentImage=*))
```


### grep
    
```
grep -P '^(?:.*(?=.*(?:.*(?=.*.*\\svchost\\.exe)(?=.*(?!.*(?:.*(?=.*(?:.*.*\\services\\.exe|.*.*\\MsMpEng\\.exe|.*.*\\Mrt\\.exe|.*.*\\rpcnet\\.exe)))))))(?=.*(?!.*(?:.*(?=.*(?!ParentImage))))))'
```



