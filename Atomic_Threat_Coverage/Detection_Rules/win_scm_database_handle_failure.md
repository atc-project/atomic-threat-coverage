| Title                | T1000 SCM Database Handle Failure                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects non-system users failing to get a handle of the SCM database.                                                                                                                                           |
| ATT&amp;CK Tactic    |   This Detection Rule wasn't mapped to ATT&amp;CK Tactic yet  |
| ATT&amp;CK Technique |  This Detection Rule wasn't mapped to ATT&amp;CK Technique yet  |
| Data Needed          | <ul><li>[DN_0058_4656_handle_to_an_object_was_requested](../Data_Needed/DN_0058_4656_handle_to_an_object_was_requested.md)</li></ul>  |
| Trigger              |  There is no documented Trigger for this Detection Rule yet  |
| Severity Level       | critical |
| False Positives      | <ul><li>Unknown</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[https://github.com/Cyb3rWard0g/ThreatHunter-Playbook/tree/master/playbooks/windows/07_discovery/T1000_local_admin_check/local_admin_remote_check_openscmanager.md](https://github.com/Cyb3rWard0g/ThreatHunter-Playbook/tree/master/playbooks/windows/07_discovery/T1000_local_admin_check/local_admin_remote_check_openscmanager.md)</li></ul>  |
| Author               | Roberto Rodriguez @Cyb3rWard0g |


## Detection Rules

### Sigma rule

```
title: T1000 SCM Database Handle Failure
id: 13addce7-47b2-4ca0-a98f-1de964d1d669
description: Detects non-system users failing to get a handle of the SCM database.
status: experimental
date: 2019/08/12
author: Roberto Rodriguez @Cyb3rWard0g
references:
    - https://github.com/Cyb3rWard0g/ThreatHunter-Playbook/tree/master/playbooks/windows/07_discovery/T1000_local_admin_check/local_admin_remote_check_openscmanager.md
logsource:
    product: windows
    service: security
detection:
    selection: 
        EventID: 4656
        ObjectType: 'SC_MANAGER OBJECT'
        ObjectName: 'servicesactive'
        Keywords: "Audit Failure"
        SubjectLogonId: "0x3e4"
    condition: selection
falsepositives:
    - Unknown
level: critical
```





### es-qs
    
```
(EventID:"4656" AND ObjectType:"SC_MANAGER\\ OBJECT" AND ObjectName:"servicesactive" AND Keywords:"Audit\\ Failure" AND SubjectLogonId:"0x3e4")
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/T1000-SCM-Database-Handle-Failure <<EOF\n{\n  "metadata": {\n    "title": "T1000 SCM Database Handle Failure",\n    "description": "Detects non-system users failing to get a handle of the SCM database.",\n    "tags": "",\n    "query": "(EventID:\\"4656\\" AND ObjectType:\\"SC_MANAGER\\\\ OBJECT\\" AND ObjectName:\\"servicesactive\\" AND Keywords:\\"Audit\\\\ Failure\\" AND SubjectLogonId:\\"0x3e4\\")"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "(EventID:\\"4656\\" AND ObjectType:\\"SC_MANAGER\\\\ OBJECT\\" AND ObjectName:\\"servicesactive\\" AND Keywords:\\"Audit\\\\ Failure\\" AND SubjectLogonId:\\"0x3e4\\")",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'T1000 SCM Database Handle Failure\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
(EventID:"4656" AND ObjectType:"SC_MANAGER OBJECT" AND ObjectName:"servicesactive" AND Keywords:"Audit Failure" AND SubjectLogonId:"0x3e4")
```


### splunk
    
```
(EventID="4656" ObjectType="SC_MANAGER OBJECT" ObjectName="servicesactive" Keywords="Audit Failure" SubjectLogonId="0x3e4")
```


### logpoint
    
```
(event_source="Microsoft-Windows-Security-Auditing" event_id="4656" ObjectType="SC_MANAGER OBJECT" ObjectName="servicesactive" Keywords="Audit Failure" SubjectLogonId="0x3e4")
```


### grep
    
```
grep -P '^(?:.*(?=.*4656)(?=.*SC_MANAGER OBJECT)(?=.*servicesactive)(?=.*Audit Failure)(?=.*0x3e4))'
```



