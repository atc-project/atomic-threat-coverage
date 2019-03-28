| Title                | Possible Ransomware or unauthorized MBR modifications                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects, possibly, malicious unauthorized usage of bcdedit.exe                                                                                                                                           |
| ATT&amp;CK Tactic    | <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li><li>[TA0003: Persistence](https://attack.mitre.org/tactics/TA0003)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1070: Indicator Removal on Host](https://attack.mitre.org/techniques/T1070)</li><li>[T1067: Bootkit](https://attack.mitre.org/techniques/T1067)</li></ul>                             |
| Data Needed          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li></ul>                                                         |
| Trigger              | <ul><li>[T1070: Indicator Removal on Host](../Triggers/T1070.md)</li><li>[T1067: Bootkit](../Triggers/T1067.md)</li></ul>  |
| Severity Level       | medium                                                                                                                                                 |
| False Positives      | <ul></ul>                                                                  |
| Development Status   | experimental                                                                                                                                                |
| References           | <ul><li>[https://docs.microsoft.com/en-us/windows-hardware/drivers/devtest/bcdedit--set](https://docs.microsoft.com/en-us/windows-hardware/drivers/devtest/bcdedit--set)</li></ul>                                                          |
| Author               | @neu5ron                                                                                                                                                |


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
        NewProcessName: '*\fsutil.exe'
        ProcessCommandLine:
            - '*delete*'
            - '*deletevalue*'
            - '*import*'
    condition: selection
level: medium

```





### es-qs
    
```
(NewProcessName.keyword:*\\\\fsutil.exe AND ProcessCommandLine.keyword:(*delete* *deletevalue* *import*))
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_xpack/watcher/watch/Possible-Ransomware-or-unauthorized-MBR-modifications <<EOF\n{\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "query_string": {\n              "query": "(NewProcessName.keyword:*\\\\\\\\fsutil.exe AND ProcessCommandLine.keyword:(*delete* *deletevalue* *import*))",\n              "analyze_wildcard": true\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": null,\n        "subject": "Sigma Rule \'Possible Ransomware or unauthorized MBR modifications\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
(NewProcessName:"*\\\\fsutil.exe" AND ProcessCommandLine:("*delete*" "*deletevalue*" "*import*"))
```


### splunk
    
```
(NewProcessName="*\\\\fsutil.exe" (ProcessCommandLine="*delete*" OR ProcessCommandLine="*deletevalue*" OR ProcessCommandLine="*import*"))
```


### logpoint
    
```
(NewProcessName="*\\\\fsutil.exe" ProcessCommandLine IN ["*delete*", "*deletevalue*", "*import*"])
```


### grep
    
```
grep -P '^(?:.*(?=.*.*\\fsutil\\.exe)(?=.*(?:.*.*delete.*|.*.*deletevalue.*|.*.*import.*)))'
```



