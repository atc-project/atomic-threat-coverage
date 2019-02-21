| Title                | Execution in Webserver Root Folder                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects a suspicious program execution in a web service root folder (filter out false positives)                                                                                                                                           |
| ATT&amp;CK Tactic    | <ul></ul>  |
| ATT&amp;CK Technique | <ul></ul>                             |
| Data Needed          | <ul><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>                                                         |
| Trigger              |  There is no Trigger for this technique yet.  |
| Severity Level       | medium                                                                                                                                                 |
| False Positives      | <ul><li>Various applications</li><li>Tools that include ping or nslookup command invocations</li></ul>                                                                  |
| Development Status   | experimental                                                                                                                                                |
| References           | <ul></ul>                                                          |
| Author               | Florian Roth                                                                                                                                                |


## Detection Rules

### Sigma rule

```
title: Execution in Webserver Root Folder
status: experimental
description: Detects a suspicious program execution in a web service root folder (filter out false positives)
author: Florian Roth
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        EventID: 1
        Image: 
            - '*\wwwroot\*'
            - '*\wmpub\*'
            - '*\htdocs\*'          
    filter:
        Image: 
            - '*bin\*'
            - '*\Tools\*'
            - '*\SMSComponent\*'
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




### esqs
    
```
((EventID:"1" AND Image.keyword:(*\\\\wwwroot\\* *\\\\wmpub\\* *\\\\htdocs\\*)) AND NOT (Image.keyword:(*bin\\* *\\\\Tools\\* *\\\\SMSComponent\\*) AND ParentImage.keyword:(*\\\\services.exe)))
```


### xpackwatcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_xpack/watcher/watch/Execution-in-Webserver-Root-Folder <<EOF\n{\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "query_string": {\n              "query": "((EventID:\\"1\\" AND Image.keyword:(*\\\\\\\\wwwroot\\\\* *\\\\\\\\wmpub\\\\* *\\\\\\\\htdocs\\\\*)) AND NOT (Image.keyword:(*bin\\\\* *\\\\\\\\Tools\\\\* *\\\\\\\\SMSComponent\\\\*) AND ParentImage.keyword:(*\\\\\\\\services.exe)))",\n              "analyze_wildcard": true\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": null,\n        "subject": "Sigma Rule \'Execution in Webserver Root Folder\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}Hit on {{_source.@timestamp}}:\\n      CommandLine = {{_source.CommandLine}}\\nParentCommandLine = {{_source.ParentCommandLine}}================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
((EventID:"1" AND Image:("*\\\\wwwroot\\*" "*\\\\wmpub\\*" "*\\\\htdocs\\*")) AND NOT (Image:("*bin\\*" "*\\\\Tools\\*" "*\\\\SMSComponent\\*") AND ParentImage:("*\\\\services.exe")))
```


### splunk
    
```
((EventID="1" (Image="*\\\\wwwroot\\*" OR Image="*\\\\wmpub\\*" OR Image="*\\\\htdocs\\*")) NOT ((Image="*bin\\*" OR Image="*\\\\Tools\\*" OR Image="*\\\\SMSComponent\\*") (ParentImage="*\\\\services.exe"))) | table CommandLine,ParentCommandLine
```


### logpoint
    
```
((EventID="1" Image IN ["*\\\\wwwroot\\*", "*\\\\wmpub\\*", "*\\\\htdocs\\*"])  -(Image IN ["*bin\\*", "*\\\\Tools\\*", "*\\\\SMSComponent\\*"] ParentImage IN ["*\\\\services.exe"]))
```


### grep
    
```
grep -P '^(?:.*(?=.*(?:.*(?=.*1)(?=.*(?:.*.*\\wwwroot\\.*|.*.*\\wmpub\\.*|.*.*\\htdocs\\.*))))(?=.*(?!.*(?:.*(?=.*(?:.*.*bin\\.*|.*.*\\Tools\\.*|.*.*\\SMSComponent\\.*))(?=.*(?:.*.*\\services\\.exe))))))'
```


