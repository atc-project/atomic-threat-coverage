| Title                | Possible Ransomware or unauthorized MBR modifications                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects, possibly, malicious unauthorized usage of bcdedit.exe                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li><li>[TA0003: Persistence](https://attack.mitre.org/tactics/TA0003)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1070: Indicator Removal on Host](https://attack.mitre.org/techniques/T1070)</li><li>[T1067: Bootkit](https://attack.mitre.org/techniques/T1067)</li></ul>  |
| Data Needed          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1070: Indicator Removal on Host](../Triggers/T1070.md)</li><li>[T1067: Bootkit](../Triggers/T1067.md)</li></ul>  |
| Severity Level       | medium |
| False Positives      |  There are no documented False Positives for this Detection Rule yet  |
| Development Status   | experimental |
| References           | <ul><li>[https://docs.microsoft.com/en-us/windows-hardware/drivers/devtest/bcdedit--set](https://docs.microsoft.com/en-us/windows-hardware/drivers/devtest/bcdedit--set)</li></ul>  |
| Author               | @neu5ron |


## Detection Rules

### Sigma rule

```
title: Possible Ransomware or unauthorized MBR modifications
status: experimental
description: Detects, possibly, malicious unauthorized usage of bcdedit.exe
references:
    - https://docs.microsoft.com/en-us/windows-hardware/drivers/devtest/bcdedit--set
author: '@neu5ron'
date: 2019/02/07
tags:
    - attack.defense_evasion
    - attack.t1070
    - attack.persistence
    - attack.t1067
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        NewProcessName: '*\bcdedit.exe'
        ProcessCommandLine:
            - '*delete*'
            - '*deletevalue*'
            - '*import*'
    condition: selection
level: medium

```





### es-qs
    
```
(NewProcessName.keyword:*\\\\bcdedit.exe AND ProcessCommandLine.keyword:(*delete* *deletevalue* *import*))
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/Possible-Ransomware-or-unauthorized-MBR-modifications <<EOF\n{\n  "metadata": {\n    "title": "Possible Ransomware or unauthorized MBR modifications",\n    "description": "Detects, possibly, malicious unauthorized usage of bcdedit.exe",\n    "tags": [\n      "attack.defense_evasion",\n      "attack.t1070",\n      "attack.persistence",\n      "attack.t1067"\n    ],\n    "query": "(NewProcessName.keyword:*\\\\\\\\bcdedit.exe AND ProcessCommandLine.keyword:(*delete* *deletevalue* *import*))"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "(NewProcessName.keyword:*\\\\\\\\bcdedit.exe AND ProcessCommandLine.keyword:(*delete* *deletevalue* *import*))",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Possible Ransomware or unauthorized MBR modifications\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
(NewProcessName:"*\\\\bcdedit.exe" AND ProcessCommandLine:("*delete*" "*deletevalue*" "*import*"))
```


### splunk
    
```
(NewProcessName="*\\\\bcdedit.exe" (ProcessCommandLine="*delete*" OR ProcessCommandLine="*deletevalue*" OR ProcessCommandLine="*import*"))
```


### logpoint
    
```
(NewProcessName="*\\\\bcdedit.exe" ProcessCommandLine IN ["*delete*", "*deletevalue*", "*import*"])
```


### grep
    
```
grep -P '^(?:.*(?=.*.*\\bcdedit\\.exe)(?=.*(?:.*.*delete.*|.*.*deletevalue.*|.*.*import.*)))'
```



