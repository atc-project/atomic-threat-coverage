| Title                    | SCM Database Privileged Operation       |
|:-------------------------|:------------------|
| **Description**          | Detects non-system users performing privileged operation os the SCM database |
| **ATT&amp;CK Tactic**    |   This Detection Rule wasn't mapped to ATT&amp;CK Tactic yet  |
| **ATT&amp;CK Technique** |  This Detection Rule wasn't mapped to ATT&amp;CK Technique yet  |
| **Data Needed**          |  There is no documented Data Needed for this Detection Rule yet  |
| **Trigger**              |  There is no documented Trigger for this Detection Rule yet  |
| **Severity Level**       | critical |
| **False Positives**      | <ul><li>Unknown</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://github.com/Cyb3rWard0g/ThreatHunter-Playbook/tree/master/playbooks/windows/07_discovery/T1000_local_admin_check/local_admin_remote_check_openscmanager.md](https://github.com/Cyb3rWard0g/ThreatHunter-Playbook/tree/master/playbooks/windows/07_discovery/T1000_local_admin_check/local_admin_remote_check_openscmanager.md)</li></ul>  |
| **Author**               | Roberto Rodriguez @Cyb3rWard0g |


## Detection Rules

### Sigma rule

```
title: SCM Database Privileged Operation
id: dae8171c-5ec6-4396-b210-8466585b53e9
description: Detects non-system users performing privileged operation os the SCM database
status: experimental
date: 2019/08/15
author: Roberto Rodriguez @Cyb3rWard0g
references:
    - https://github.com/Cyb3rWard0g/ThreatHunter-Playbook/tree/master/playbooks/windows/07_discovery/T1000_local_admin_check/local_admin_remote_check_openscmanager.md
logsource:
    product: windows
    service: security
detection:
    selection: 
        EventID: 4674
        ObjectType: 'SC_MANAGER OBJECT'
        ObjectName: 'servicesactive'
        PrivilegeList: 'SeTakeOwnershipPrivilege'
        SubjectLogonId: "0x3e4"
    condition: selection
falsepositives:
    - Unknown
level: critical

```





### powershell
    
```
Get-WinEvent -LogName Security | where {($_.ID -eq "4674" -and $_.message -match "ObjectType.*SC_MANAGER OBJECT" -and $_.message -match "ObjectName.*servicesactive" -and $_.message -match "PrivilegeList.*SeTakeOwnershipPrivilege" -and $_.message -match "SubjectLogonId.*0x3e4") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.channel:"Security" AND winlog.event_id:"4674" AND winlog.event_data.ObjectType:"SC_MANAGER\\ OBJECT" AND winlog.event_data.ObjectName:"servicesactive" AND PrivilegeList:"SeTakeOwnershipPrivilege" AND SubjectLogonId:"0x3e4")
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/dae8171c-5ec6-4396-b210-8466585b53e9 <<EOF\n{\n  "metadata": {\n    "title": "SCM Database Privileged Operation",\n    "description": "Detects non-system users performing privileged operation os the SCM database",\n    "tags": "",\n    "query": "(winlog.channel:\\"Security\\" AND winlog.event_id:\\"4674\\" AND winlog.event_data.ObjectType:\\"SC_MANAGER\\\\ OBJECT\\" AND winlog.event_data.ObjectName:\\"servicesactive\\" AND PrivilegeList:\\"SeTakeOwnershipPrivilege\\" AND SubjectLogonId:\\"0x3e4\\")"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "(winlog.channel:\\"Security\\" AND winlog.event_id:\\"4674\\" AND winlog.event_data.ObjectType:\\"SC_MANAGER\\\\ OBJECT\\" AND winlog.event_data.ObjectName:\\"servicesactive\\" AND PrivilegeList:\\"SeTakeOwnershipPrivilege\\" AND SubjectLogonId:\\"0x3e4\\")",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": [\n          "winlogbeat-*"\n        ]\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'SCM Database Privileged Operation\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
(EventID:"4674" AND ObjectType:"SC_MANAGER OBJECT" AND ObjectName:"servicesactive" AND PrivilegeList:"SeTakeOwnershipPrivilege" AND SubjectLogonId:"0x3e4")
```


### splunk
    
```
(source="WinEventLog:Security" EventCode="4674" ObjectType="SC_MANAGER OBJECT" ObjectName="servicesactive" PrivilegeList="SeTakeOwnershipPrivilege" SubjectLogonId="0x3e4")
```


### logpoint
    
```
(event_source="Microsoft-Windows-Security-Auditing" event_id="4674" ObjectType="SC_MANAGER OBJECT" ObjectName="servicesactive" PrivilegeList="SeTakeOwnershipPrivilege" SubjectLogonId="0x3e4")
```


### grep
    
```
grep -P '^(?:.*(?=.*4674)(?=.*SC_MANAGER OBJECT)(?=.*servicesactive)(?=.*SeTakeOwnershipPrivilege)(?=.*0x3e4))'
```



