| Title                | Mimikatz through Windows Remote Management                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects usage of mimikatz through WinRM protocol by monitoring access to lsass process by wsmprovhost.exe.                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0006: Credential Access](https://attack.mitre.org/tactics/TA0006)</li><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1003: Credential Dumping](https://attack.mitre.org/techniques/T1003)</li><li>[T1028: Windows Remote Management](https://attack.mitre.org/techniques/T1028)</li></ul>  |
| Data Needed          | <ul><li>[DN_0014_10_windows_sysmon_ProcessAccess](../Data_Needed/DN_0014_10_windows_sysmon_ProcessAccess.md)</li></ul>  |
| Trigger              | <ul><li>[T1003: Credential Dumping](../Triggers/T1003.md)</li><li>[T1028: Windows Remote Management](../Triggers/T1028.md)</li></ul>  |
| Severity Level       | high |
| False Positives      | <ul><li>low</li></ul>  |
| Development Status   | stable |
| References           | <ul><li>[https://pentestlab.blog/2018/05/15/lateral-movement-winrm/](https://pentestlab.blog/2018/05/15/lateral-movement-winrm/)</li></ul>  |
| Author               | Patryk Prauze - ING Tech |
| Other Tags           | <ul><li>attack.s0005</li></ul> | 

## Detection Rules

### Sigma rule

```
title: Mimikatz through Windows Remote Management
id: aa35a627-33fb-4d04-a165-d33b4afca3e8
description: Detects usage of mimikatz through WinRM protocol by monitoring access to lsass process by wsmprovhost.exe.
references:
    - https://pentestlab.blog/2018/05/15/lateral-movement-winrm/
status: stable
author: Patryk Prauze - ING Tech
date: 2019/05/20
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        EventID: 10
        TargetImage: 'C:\windows\system32\lsass.exe'
        SourceImage: 'C:\Windows\system32\wsmprovhost.exe'
    condition: selection
tags:
    - attack.credential_access
    - attack.execution
    - attack.t1003
    - attack.t1028
    - attack.s0005
falsepositives:
    - low
level: high

```





### es-qs
    
```
(EventID:"10" AND TargetImage:"C\\:\\\\windows\\\\system32\\\\lsass.exe" AND SourceImage:"C\\:\\\\Windows\\\\system32\\\\wsmprovhost.exe")
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/aa35a627-33fb-4d04-a165-d33b4afca3e8 <<EOF\n{\n  "metadata": {\n    "title": "Mimikatz through Windows Remote Management",\n    "description": "Detects usage of mimikatz through WinRM protocol by monitoring access to lsass process by wsmprovhost.exe.",\n    "tags": [\n      "attack.credential_access",\n      "attack.execution",\n      "attack.t1003",\n      "attack.t1028",\n      "attack.s0005"\n    ],\n    "query": "(EventID:\\"10\\" AND TargetImage:\\"C\\\\:\\\\\\\\windows\\\\\\\\system32\\\\\\\\lsass.exe\\" AND SourceImage:\\"C\\\\:\\\\\\\\Windows\\\\\\\\system32\\\\\\\\wsmprovhost.exe\\")"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "(EventID:\\"10\\" AND TargetImage:\\"C\\\\:\\\\\\\\windows\\\\\\\\system32\\\\\\\\lsass.exe\\" AND SourceImage:\\"C\\\\:\\\\\\\\Windows\\\\\\\\system32\\\\\\\\wsmprovhost.exe\\")",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Mimikatz through Windows Remote Management\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
(EventID:"10" AND TargetImage:"C\\:\\\\windows\\\\system32\\\\lsass.exe" AND SourceImage:"C\\:\\\\Windows\\\\system32\\\\wsmprovhost.exe")
```


### splunk
    
```
(EventID="10" TargetImage="C:\\\\windows\\\\system32\\\\lsass.exe" SourceImage="C:\\\\Windows\\\\system32\\\\wsmprovhost.exe")
```


### logpoint
    
```
(event_id="10" TargetImage="C:\\\\windows\\\\system32\\\\lsass.exe" SourceImage="C:\\\\Windows\\\\system32\\\\wsmprovhost.exe")
```


### grep
    
```
grep -P '^(?:.*(?=.*10)(?=.*C:\\windows\\system32\\lsass\\.exe)(?=.*C:\\Windows\\system32\\wsmprovhost\\.exe))'
```



