| Title                | Possible SPN Enumeration                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects Service Principal Name Enumeration used for Kerberoasting                                                                                                                                           |
| ATT&amp;CK Tactic    | <ul><li>[TA0006: Credential Access](https://attack.mitre.org/tactics/TA0006)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1208: Kerberoasting](https://attack.mitre.org/techniques/T1208)</li></ul>                             |
| Data Needed          | <ul><li>[DN_0001_4688_windows_process_creation](../Data_Needed/DN_0001_4688_windows_process_creation.md)</li><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>                                                         |
| Trigger              | <ul><li>[T1208: Kerberoasting](../Triggers/T1208.md)</li></ul>  |
| Severity Level       | medium                                                                                                                                                 |
| False Positives      | <ul><li>Administrator Activity</li></ul>                                                                  |
| Development Status   | experimental                                                                                                                                                |
| References           | <ul><li>[https://p16.praetorian.com/blog/how-to-use-kerberoasting-t1208-for-privilege-escalation](https://p16.praetorian.com/blog/how-to-use-kerberoasting-t1208-for-privilege-escalation)</li></ul>                                                          |
| Author               | Markus Neis                                                                                                                                                |


## Detection Rules

### Sigma rule

```
---
action: global
title: Possible SPN Enumeration 
description: Detects Service Principal Name Enumeration used for Kerberoasting
status: experimental
references:
    - https://p16.praetorian.com/blog/how-to-use-kerberoasting-t1208-for-privilege-escalation
author: Markus Neis
date: 2018/11/14
tags:
    - attack.credential_access
    - attack.t1208
detection:
    selection:
         Image: '*\setspn.exe'
    selection1:
        Description: '*Query or reset the computer* SPN attribute*'
    cmd:
        CommandLine: '*-q*'
    condition: (selection or selection1) and cmd 
falsepositives: 
    - Administrator Activity 
level: medium
---
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        EventID: 1
---
logsource:
    product: windows
    service: security
    description: 'Requirements: Audit Policy : Detailed Tracking > Audit Process creation, Group Policy : Administrative Templates\System\Audit Process Creation'
detection:
    selection:
        EventID: 4688


```





### Kibana query

```
(((EventID:"1" AND Image.keyword:*\\\\setspn.exe) OR Description.keyword:*Query\\ or\\ reset\\ the\\ computer*\\ SPN\\ attribute*) AND CommandLine.keyword:*\\-q*)\n(((EventID:"4688" AND Image.keyword:*\\\\setspn.exe) OR Description.keyword:*Query\\ or\\ reset\\ the\\ computer*\\ SPN\\ attribute*) AND CommandLine.keyword:*\\-q*)
```





### X-Pack Watcher

```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_xpack/watcher/watch/Possible-SPN-Enumeration <<EOF\n{\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "query_string": {\n              "query": "(((EventID:\\"1\\" AND Image.keyword:*\\\\\\\\setspn.exe) OR Description.keyword:*Query\\\\ or\\\\ reset\\\\ the\\\\ computer*\\\\ SPN\\\\ attribute*) AND CommandLine.keyword:*\\\\-q*)",\n              "analyze_wildcard": true\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": null,\n        "subject": "Sigma Rule \'Possible SPN Enumeration\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\ncurl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_xpack/watcher/watch/Possible-SPN-Enumeration-2 <<EOF\n{\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "query_string": {\n              "query": "(((EventID:\\"4688\\" AND Image.keyword:*\\\\\\\\setspn.exe) OR Description.keyword:*Query\\\\ or\\\\ reset\\\\ the\\\\ computer*\\\\ SPN\\\\ attribute*) AND CommandLine.keyword:*\\\\-q*)",\n              "analyze_wildcard": true\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": null,\n        "subject": "Sigma Rule \'Possible SPN Enumeration\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```





### Graylog

```
(((EventID:"1" AND Image:"*\\\\setspn.exe") OR Description:"*Query or reset the computer* SPN attribute*") AND CommandLine:"*\\-q*")\n(((EventID:"4688" AND Image:"*\\\\setspn.exe") OR Description:"*Query or reset the computer* SPN attribute*") AND CommandLine:"*\\-q*")
```

