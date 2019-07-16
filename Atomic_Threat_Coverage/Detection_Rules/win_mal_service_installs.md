| Title                | Malicious Service Installations                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects known malicious service installs that only appear in cases of lateral movement, credential dumping and other suspicious activity                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0003: Persistence](https://attack.mitre.org/tactics/TA0003)</li><li>[TA0004: Privilege Escalation](https://attack.mitre.org/tactics/TA0004)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1050: New Service](https://attack.mitre.org/techniques/T1050)</li></ul>  |
| Data Needed          | <ul><li>[DN_0005_7045_windows_service_insatalled](../Data_Needed/DN_0005_7045_windows_service_insatalled.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1050: New Service](../Triggers/T1050.md)</li></ul>  |
| Severity Level       | critical |
| False Positives      | <ul><li>Penetration testing</li></ul>  |
| Development Status   |  Development Status wasn't defined for this Detection Rule yet  |
| References           |  There are no documented References for this Detection Rule yet  |
| Author               | Florian Roth |
| Other Tags           | <ul><li>car.2013-09-005</li><li>car.2013-09-005</li></ul> | 

## Detection Rules

### Sigma rule

```
title: Malicious Service Installations
description: Detects known malicious service installs that only appear in cases of lateral movement, credential dumping and other suspicious activity
author: Florian Roth
tags:
    - attack.persistence
    - attack.privilege_escalation
    - attack.t1050
    - car.2013-09-005
logsource:
    product: windows
    service: system
detection:
    selection:
        EventID: 7045
    malsvc_wce:
        ServiceName: 
            - 'WCESERVICE'
            - 'WCE SERVICE'
    malsvc_paexec:
        ServiceFileName: '*\PAExec*'
    malsvc_winexe:
        ServiceFileName: 'winexesvc.exe*'
    malsvc_pwdumpx:
        ServiceFileName: '*\DumpSvc.exe'
    malsvc_wannacry:
        ServiceName: 'mssecsvc2.0'
    malsvc_persistence:
        ServiceFileName: '* net user *'
    malsvc_others:
        ServiceName:
            - 'pwdump*'
            - 'gsecdump*'
            - 'cachedump*'
    condition: selection and 1 of malsvc_*
falsepositives: 
    - Penetration testing
level: critical

```





### es-qs
    
```
(EventID:"7045" AND (ServiceName:("WCESERVICE" "WCE\\ SERVICE") OR ServiceFileName.keyword:*\\\\PAExec* OR ServiceFileName.keyword:winexesvc.exe* OR ServiceFileName.keyword:*\\\\DumpSvc.exe OR ServiceName:"mssecsvc2.0" OR ServiceFileName.keyword:*\\ net\\ user\\ * OR ServiceName.keyword:(pwdump* gsecdump* cachedump*)))
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/Malicious-Service-Installations <<EOF\n{\n  "metadata": {\n    "title": "Malicious Service Installations",\n    "description": "Detects known malicious service installs that only appear in cases of lateral movement, credential dumping and other suspicious activity",\n    "tags": [\n      "attack.persistence",\n      "attack.privilege_escalation",\n      "attack.t1050",\n      "car.2013-09-005"\n    ],\n    "query": "(EventID:\\"7045\\" AND (ServiceName:(\\"WCESERVICE\\" \\"WCE\\\\ SERVICE\\") OR ServiceFileName.keyword:*\\\\\\\\PAExec* OR ServiceFileName.keyword:winexesvc.exe* OR ServiceFileName.keyword:*\\\\\\\\DumpSvc.exe OR ServiceName:\\"mssecsvc2.0\\" OR ServiceFileName.keyword:*\\\\ net\\\\ user\\\\ * OR ServiceName.keyword:(pwdump* gsecdump* cachedump*)))"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "(EventID:\\"7045\\" AND (ServiceName:(\\"WCESERVICE\\" \\"WCE\\\\ SERVICE\\") OR ServiceFileName.keyword:*\\\\\\\\PAExec* OR ServiceFileName.keyword:winexesvc.exe* OR ServiceFileName.keyword:*\\\\\\\\DumpSvc.exe OR ServiceName:\\"mssecsvc2.0\\" OR ServiceFileName.keyword:*\\\\ net\\\\ user\\\\ * OR ServiceName.keyword:(pwdump* gsecdump* cachedump*)))",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Malicious Service Installations\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
(EventID:"7045" AND (ServiceName:("WCESERVICE" "WCE SERVICE") OR ServiceFileName:"*\\\\PAExec*" OR ServiceFileName:"winexesvc.exe*" OR ServiceFileName:"*\\\\DumpSvc.exe" OR ServiceName:"mssecsvc2.0" OR ServiceFileName:"* net user *" OR ServiceName:("pwdump*" "gsecdump*" "cachedump*")))
```


### splunk
    
```
(EventID="7045" ((ServiceName="WCESERVICE" OR ServiceName="WCE SERVICE") OR ServiceFileName="*\\\\PAExec*" OR ServiceFileName="winexesvc.exe*" OR ServiceFileName="*\\\\DumpSvc.exe" OR ServiceName="mssecsvc2.0" OR ServiceFileName="* net user *" OR (ServiceName="pwdump*" OR ServiceName="gsecdump*" OR ServiceName="cachedump*")))
```


### logpoint
    
```
(EventID="7045" (ServiceName IN ["WCESERVICE", "WCE SERVICE"] OR ServiceFileName="*\\\\PAExec*" OR ServiceFileName="winexesvc.exe*" OR ServiceFileName="*\\\\DumpSvc.exe" OR ServiceName="mssecsvc2.0" OR ServiceFileName="* net user *" OR ServiceName IN ["pwdump*", "gsecdump*", "cachedump*"]))
```


### grep
    
```
grep -P '^(?:.*(?=.*7045)(?=.*(?:.*(?:.*(?:.*WCESERVICE|.*WCE SERVICE)|.*.*\\PAExec.*|.*winexesvc\\.exe.*|.*.*\\DumpSvc\\.exe|.*mssecsvc2\\.0|.*.* net user .*|.*(?:.*pwdump.*|.*gsecdump.*|.*cachedump.*)))))'
```



