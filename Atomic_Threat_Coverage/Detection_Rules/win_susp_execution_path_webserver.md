| Title                | Execution in Webserver Root Folder                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects a suspicious program execution in a web service root folder (filter out false positives)                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0003: Persistence](https://attack.mitre.org/tactics/TA0003)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1100: Web Shell](https://attack.mitre.org/techniques/T1100)</li></ul>  |
| Data Needed          | <ul><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1100: Web Shell](../Triggers/T1100.md)</li></ul>  |
| Severity Level       | medium |
| False Positives      | <ul><li>Various applications</li><li>Tools that include ping or nslookup command invocations</li></ul>  |
| Development Status   | experimental |
| References           |  There are no documented References for this Detection Rule yet  |
| Author               | Florian Roth |


## Detection Rules

### Sigma rule

```
title: Execution in Webserver Root Folder
status: experimental
description: Detects a suspicious program execution in a web service root folder (filter out false positives)
author: Florian Roth
tags:
    - attack.persistence
    - attack.t1100
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image:
            - '*\wwwroot\\*'
            - '*\wmpub\\*'
            - '*\htdocs\\*'
    filter:
        Image:
            - '*bin\\*'
            - '*\Tools\\*'
            - '*\SMSComponent\\*'
        ParentImage:
            - '*\services.exe'
    condition: selection and not filter
fields:
    - CommandLine
    - ParentCommandLine
falsepositives:
    - Various applications
    - Tools that include ping or nslookup command invocations
level: medium

```





### es-qs
    
```
(Image.keyword:(*\\\\wwwroot\\\\* *\\\\wmpub\\\\* *\\\\htdocs\\\\*) AND (NOT (Image.keyword:(*bin\\\\* *\\\\Tools\\\\* *\\\\SMSComponent\\\\*) AND ParentImage.keyword:(*\\\\services.exe))))
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/Execution-in-Webserver-Root-Folder <<EOF\n{\n  "metadata": {\n    "title": "Execution in Webserver Root Folder",\n    "description": "Detects a suspicious program execution in a web service root folder (filter out false positives)",\n    "tags": [\n      "attack.persistence",\n      "attack.t1100"\n    ],\n    "query": "(Image.keyword:(*\\\\\\\\wwwroot\\\\\\\\* *\\\\\\\\wmpub\\\\\\\\* *\\\\\\\\htdocs\\\\\\\\*) AND (NOT (Image.keyword:(*bin\\\\\\\\* *\\\\\\\\Tools\\\\\\\\* *\\\\\\\\SMSComponent\\\\\\\\*) AND ParentImage.keyword:(*\\\\\\\\services.exe))))"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "(Image.keyword:(*\\\\\\\\wwwroot\\\\\\\\* *\\\\\\\\wmpub\\\\\\\\* *\\\\\\\\htdocs\\\\\\\\*) AND (NOT (Image.keyword:(*bin\\\\\\\\* *\\\\\\\\Tools\\\\\\\\* *\\\\\\\\SMSComponent\\\\\\\\*) AND ParentImage.keyword:(*\\\\\\\\services.exe))))",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Execution in Webserver Root Folder\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}Hit on {{_source.@timestamp}}:\\n      CommandLine = {{_source.CommandLine}}\\nParentCommandLine = {{_source.ParentCommandLine}}================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
(Image:("*\\\\wwwroot\\\\*" "*\\\\wmpub\\\\*" "*\\\\htdocs\\\\*") AND NOT (Image:("*bin\\\\*" "*\\\\Tools\\\\*" "*\\\\SMSComponent\\\\*") AND ParentImage:("*\\\\services.exe")))
```


### splunk
    
```
((Image="*\\\\wwwroot\\\\*" OR Image="*\\\\wmpub\\\\*" OR Image="*\\\\htdocs\\\\*") NOT ((Image="*bin\\\\*" OR Image="*\\\\Tools\\\\*" OR Image="*\\\\SMSComponent\\\\*") (ParentImage="*\\\\services.exe"))) | table CommandLine,ParentCommandLine
```


### logpoint
    
```
(Image IN ["*\\\\wwwroot\\\\*", "*\\\\wmpub\\\\*", "*\\\\htdocs\\\\*"]  -(Image IN ["*bin\\\\*", "*\\\\Tools\\\\*", "*\\\\SMSComponent\\\\*"] ParentImage IN ["*\\\\services.exe"]))
```


### grep
    
```
grep -P '^(?:.*(?=.*(?:.*.*\\wwwroot\\\\.*|.*.*\\wmpub\\\\.*|.*.*\\htdocs\\\\.*))(?=.*(?!.*(?:.*(?=.*(?:.*.*bin\\\\.*|.*.*\\Tools\\\\.*|.*.*\\SMSComponent\\\\.*))(?=.*(?:.*.*\\services\\.exe))))))'
```



