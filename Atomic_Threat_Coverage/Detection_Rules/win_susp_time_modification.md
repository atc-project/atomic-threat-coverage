| Title                | Unauthorized System Time Modification                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detect scenarios where a potentially unauthorized application or user is modifying the system time.                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1099: Timestomp](https://attack.mitre.org/techniques/T1099)</li></ul>  |
| Data Needed          |  There is no documented Data Needed for this Detection Rule yet  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1099: Timestomp](../Triggers/T1099.md)</li></ul>  |
| Severity Level       | high |
| False Positives      | <ul><li>HyperV or other virtualization technologies with binary not listed in filter portion of detection</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[Private Cuckoo Sandbox (from many years ago, no longer have hash, NDA as well)](Private Cuckoo Sandbox (from many years ago, no longer have hash, NDA as well))</li><li>[Live environment caused by malware](Live environment caused by malware)</li></ul>  |
| Author               | @neu5ron |


## Detection Rules

### Sigma rule

```
title: Unauthorized System Time Modification
status: experimental
description: Detect scenarios where a potentially unauthorized application or user is modifying the system time.
author: '@neu5ron'
references:
    - Private Cuckoo Sandbox (from many years ago, no longer have hash, NDA as well)
    - Live environment caused by malware
date: 2019/02/05
tags:
    - attack.defense_evasion
    - attack.t1099
logsource:
    product: windows
    service: security
    definition: 'Requirements: Audit Policy : System > Audit Security State Change, Group Policy : Computer Configuration\Windows Settings\Security Settings\Advanced Audit Policy Configuration\Audit Policies\System\Audit Security State Change'
detection:
    selection:
        EventID: 4616
    filter1:
        ProcessName: 'C:\Program Files\VMware\VMware Tools\vmtoolsd.exe'
    filter2:
        ProcessName: 'C:\Windows\System32\VBoxService.exe'
    filter3:
        ProcessName: 'C:\Windows\System32\svchost.exe'
        SubjectUserSid: 'S-1-5-19'
    condition: selection and not ( filter1 or filter2 or filter3 )
falsepositives:
    - HyperV or other virtualization technologies with binary not listed in filter portion of detection
level: high

```





### es-qs
    
```
(EventID:"4616" AND (NOT (((ProcessName:"C\\:\\\\Program\\ Files\\\\VMware\\\\VMware\\ Tools\\\\vmtoolsd.exe" OR ProcessName:"C\\:\\\\Windows\\\\System32\\\\VBoxService.exe") OR (ProcessName:"C\\:\\\\Windows\\\\System32\\\\svchost.exe" AND SubjectUserSid:"S\\-1\\-5\\-19")))))
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/Unauthorized-System-Time-Modification <<EOF\n{\n  "metadata": {\n    "title": "Unauthorized System Time Modification",\n    "description": "Detect scenarios where a potentially unauthorized application or user is modifying the system time.",\n    "tags": [\n      "attack.defense_evasion",\n      "attack.t1099"\n    ],\n    "query": "(EventID:\\"4616\\" AND (NOT (((ProcessName:\\"C\\\\:\\\\\\\\Program\\\\ Files\\\\\\\\VMware\\\\\\\\VMware\\\\ Tools\\\\\\\\vmtoolsd.exe\\" OR ProcessName:\\"C\\\\:\\\\\\\\Windows\\\\\\\\System32\\\\\\\\VBoxService.exe\\") OR (ProcessName:\\"C\\\\:\\\\\\\\Windows\\\\\\\\System32\\\\\\\\svchost.exe\\" AND SubjectUserSid:\\"S\\\\-1\\\\-5\\\\-19\\")))))"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "(EventID:\\"4616\\" AND (NOT (((ProcessName:\\"C\\\\:\\\\\\\\Program\\\\ Files\\\\\\\\VMware\\\\\\\\VMware\\\\ Tools\\\\\\\\vmtoolsd.exe\\" OR ProcessName:\\"C\\\\:\\\\\\\\Windows\\\\\\\\System32\\\\\\\\VBoxService.exe\\") OR (ProcessName:\\"C\\\\:\\\\\\\\Windows\\\\\\\\System32\\\\\\\\svchost.exe\\" AND SubjectUserSid:\\"S\\\\-1\\\\-5\\\\-19\\")))))",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Unauthorized System Time Modification\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
(EventID:"4616" AND NOT (((ProcessName:"C\\:\\\\Program Files\\\\VMware\\\\VMware Tools\\\\vmtoolsd.exe" OR ProcessName:"C\\:\\\\Windows\\\\System32\\\\VBoxService.exe") OR (ProcessName:"C\\:\\\\Windows\\\\System32\\\\svchost.exe" AND SubjectUserSid:"S\\-1\\-5\\-19"))))
```


### splunk
    
```
(EventID="4616" NOT (((ProcessName="C:\\\\Program Files\\\\VMware\\\\VMware Tools\\\\vmtoolsd.exe" OR ProcessName="C:\\\\Windows\\\\System32\\\\VBoxService.exe") OR (ProcessName="C:\\\\Windows\\\\System32\\\\svchost.exe" SubjectUserSid="S-1-5-19"))))
```


### logpoint
    
```
(EventID="4616"  -(((ProcessName="C:\\\\Program Files\\\\VMware\\\\VMware Tools\\\\vmtoolsd.exe" OR ProcessName="C:\\\\Windows\\\\System32\\\\VBoxService.exe") OR (ProcessName="C:\\\\Windows\\\\System32\\\\svchost.exe" SubjectUserSid="S-1-5-19"))))
```


### grep
    
```
grep -P '^(?:.*(?=.*4616)(?=.*(?!.*(?:.*(?:.*(?:.*(?:.*(?:.*C:\\Program Files\\VMware\\VMware Tools\\vmtoolsd\\.exe|.*C:\\Windows\\System32\\VBoxService\\.exe))|.*(?:.*(?=.*C:\\Windows\\System32\\svchost\\.exe)(?=.*S-1-5-19))))))))'
```



