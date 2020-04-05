| Title                    | User Couldn't Call a Privileged Service 'LsaRegisterLogonProcess'       |
|:-------------------------|:------------------|
| **Description**          | The 'LsaRegisterLogonProcess' function verifies that the application making the function call is a logon process by checking that it has the SeTcbPrivilege privilege set. Possible Rubeus tries to get a handle to LSA. |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0008: Lateral Movement](https://attack.mitre.org/tactics/TA0008)</li><li>[TA0004: Privilege Escalation](https://attack.mitre.org/tactics/TA0004)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1208: Kerberoasting](https://attack.mitre.org/techniques/T1208)</li></ul>  |
| **Data Needed**          |  There is no documented Data Needed for this Detection Rule yet  |
| **Trigger**              | <ul><li>[T1208: Kerberoasting](../Triggers/T1208.md)</li></ul>  |
| **Severity Level**       | high |
| **False Positives**      | <ul><li>Unkown</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://posts.specterops.io/hunting-in-active-directory-unconstrained-delegation-forests-trusts-71f2b33688e1](https://posts.specterops.io/hunting-in-active-directory-unconstrained-delegation-forests-trusts-71f2b33688e1)</li></ul>  |
| **Author**               | Roberto Rodriguez (source), Ilyas Ochkov (rule), oscd.community |


## Detection Rules

### Sigma rule

```
title: User Couldn't Call a Privileged Service 'LsaRegisterLogonProcess'
id: 6daac7fc-77d1-449a-a71a-e6b4d59a0e54
description: The 'LsaRegisterLogonProcess' function verifies that the application making the function call is a logon process by checking that it has the SeTcbPrivilege
    privilege set. Possible Rubeus tries to get a handle to LSA.
status: experimental
references:
    - https://posts.specterops.io/hunting-in-active-directory-unconstrained-delegation-forests-trusts-71f2b33688e1
tags:
    - attack.lateral_movement
    - attack.privilege_escalation
    - attack.t1208
author: Roberto Rodriguez (source), Ilyas Ochkov (rule), oscd.community
date: 2019/10/24
logsource:
    product: windows
    service: security
detection:
    selection:
        - EventID: 4673
          Service: 'LsaRegisterLogonProcess()'
          Keywords: '0x8010000000000000'   #failure
    condition: selection
falsepositives:
    - Unkown
level: high

```





### es-qs
    
```
(EventID:"4673" AND Service:"LsaRegisterLogonProcess\\(\\)" AND Keywords:"0x8010000000000000")
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/6daac7fc-77d1-449a-a71a-e6b4d59a0e54 <<EOF\n{\n  "metadata": {\n    "title": "User Couldn\'t Call a Privileged Service \'LsaRegisterLogonProcess\'",\n    "description": "The \'LsaRegisterLogonProcess\' function verifies that the application making the function call is a logon process by checking that it has the SeTcbPrivilege privilege set. Possible Rubeus tries to get a handle to LSA.",\n    "tags": [\n      "attack.lateral_movement",\n      "attack.privilege_escalation",\n      "attack.t1208"\n    ],\n    "query": "(EventID:\\"4673\\" AND Service:\\"LsaRegisterLogonProcess\\\\(\\\\)\\" AND Keywords:\\"0x8010000000000000\\")"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "(EventID:\\"4673\\" AND Service:\\"LsaRegisterLogonProcess\\\\(\\\\)\\" AND Keywords:\\"0x8010000000000000\\")",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'User Couldn\'t Call a Privileged Service \'LsaRegisterLogonProcess\'\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
(EventID:"4673" AND Service:"LsaRegisterLogonProcess\\(\\)" AND Keywords:"0x8010000000000000")
```


### splunk
    
```
(EventID="4673" Service="LsaRegisterLogonProcess()" Keywords="0x8010000000000000")
```


### logpoint
    
```
(event_source="Microsoft-Windows-Security-Auditing" event_id="4673" Service="LsaRegisterLogonProcess()" Keywords="0x8010000000000000")
```


### grep
    
```
grep -P '^(?:.*(?=.*4673)(?=.*LsaRegisterLogonProcess\\(\\))(?=.*0x8010000000000000))'
```



