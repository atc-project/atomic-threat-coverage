| Title                | Suspicious File Characteristics due to Missing Fields                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects Executables without FileVersion,Description,Product,Company likely created with py2exe                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1064: Scripting](https://attack.mitre.org/techniques/T1064)</li></ul>  |
| Data Needed          | <ul><li>[DN_0011_7_windows_sysmon_image_loaded](../Data_Needed/DN_0011_7_windows_sysmon_image_loaded.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1064: Scripting](../Triggers/T1064.md)</li></ul>  |
| Severity Level       | high |
| False Positives      | <ul><li>Unknown</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[https://securelist.com/muddywater/88059/](https://securelist.com/muddywater/88059/)</li><li>[https://www.virustotal.com/#/file/276a765a10f98cda1a38d3a31e7483585ca3722ecad19d784441293acf1b7beb/detection](https://www.virustotal.com/#/file/276a765a10f98cda1a38d3a31e7483585ca3722ecad19d784441293acf1b7beb/detection)</li></ul>  |
| Author               | Markus Neis |


## Detection Rules

### Sigma rule

```
title: Suspicious File Characteristics due to Missing Fields
description: Detects Executables without FileVersion,Description,Product,Company likely created with py2exe
status: experimental
references:
    - https://securelist.com/muddywater/88059/
    - https://www.virustotal.com/#/file/276a765a10f98cda1a38d3a31e7483585ca3722ecad19d784441293acf1b7beb/detection
author: Markus Neis
date: 2018/11/22
tags:
    - attack.defense_evasion
    - attack.execution
    - attack.t1064
logsource:
    product: windows
    service: sysmon
detection:
    selection1:
        Description: '\?'
        FileVersion: '\?'
    selection2:
        Description: '\?'
        Product: '\?'
    selection3:
        Description: '\?'
        Company: '\?' 
    condition: 1 of them
fields:
    - CommandLine
    - ParentCommandLine
falsepositives:
    - Unknown
level: high

```





### es-qs
    
```
(Description:"\\?" AND (FileVersion:"\\?" OR Product:"\\?" OR Company:"\\?"))
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/Suspicious-File-Characteristics-due-to-Missing-Fields <<EOF\n{\n  "metadata": {\n    "title": "Suspicious File Characteristics due to Missing Fields",\n    "description": "Detects Executables without FileVersion,Description,Product,Company likely created with py2exe",\n    "tags": [\n      "attack.defense_evasion",\n      "attack.execution",\n      "attack.t1064"\n    ],\n    "query": "(Description:\\"\\\\?\\" AND (FileVersion:\\"\\\\?\\" OR Product:\\"\\\\?\\" OR Company:\\"\\\\?\\"))"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "(Description:\\"\\\\?\\" AND (FileVersion:\\"\\\\?\\" OR Product:\\"\\\\?\\" OR Company:\\"\\\\?\\"))",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Suspicious File Characteristics due to Missing Fields\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}Hit on {{_source.@timestamp}}:\\n      CommandLine = {{_source.CommandLine}}\\nParentCommandLine = {{_source.ParentCommandLine}}================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
(Description:"\\?" AND (FileVersion:"\\?" OR Product:"\\?" OR Company:"\\?"))
```


### splunk
    
```
(Description="\\?" (FileVersion="\\?" OR Product="\\?" OR Company="\\?")) | table CommandLine,ParentCommandLine
```


### logpoint
    
```
(Description="\\?" (FileVersion="\\?" OR Product="\\?" OR Company="\\?"))
```


### grep
    
```
grep -P '^(?:.*(?=.*\\?)(?=.*(?:.*(?:.*\\?|.*\\?|.*\\?))))'
```



