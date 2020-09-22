| Title                    | Suspicious LDAP-Attributes Used       |
|:-------------------------|:------------------|
| **Description**          | Detects the usage of particular AttributeLDAPDisplayNames, which are known for data exchange via LDAP by the tool LDAPFragger and are additionally not commonly used in companies. |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0011: Command and Control](https://attack.mitre.org/tactics/TA0011)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1071: Application Layer Protocol](https://attack.mitre.org/techniques/T1071)</li><li>[T1001.003: Protocol Impersonation](https://attack.mitre.org/techniques/T1001.003)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0026_5136_windows_directory_service_object_was_modified](../Data_Needed/DN_0026_5136_windows_directory_service_object_was_modified.md)</li></ul>  |
| **Trigger**              |  There is no documented Trigger for this Detection Rule yet  |
| **Severity Level**       | high |
| **False Positives**      | <ul><li>Companies, who may use these default LDAP-Attributes for personal information</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://medium.com/@ivecodoe/detecting-ldapfragger-a-newly-released-cobalt-strike-beacon-using-ldap-for-c2-communication-c274a7f00961](https://medium.com/@ivecodoe/detecting-ldapfragger-a-newly-released-cobalt-strike-beacon-using-ldap-for-c2-communication-c274a7f00961)</li><li>[https://blog.fox-it.com/2020/03/19/ldapfragger-command-and-control-over-ldap-attributes/](https://blog.fox-it.com/2020/03/19/ldapfragger-command-and-control-over-ldap-attributes/)</li><li>[https://github.com/fox-it/LDAPFragger](https://github.com/fox-it/LDAPFragger)</li></ul>  |
| **Author**               | xknow @xknow_infosec |


## Detection Rules

### Sigma rule

```
title: Suspicious LDAP-Attributes Used
id: d00a9a72-2c09-4459-ad03-5e0a23351e36
description: Detects the usage of particular AttributeLDAPDisplayNames, which are known for data exchange via LDAP by the tool LDAPFragger and are additionally not commonly used in companies.
status: experimental
date: 2019/03/24
modified: 2020/08/23
author: xknow @xknow_infosec
references:
    - https://medium.com/@ivecodoe/detecting-ldapfragger-a-newly-released-cobalt-strike-beacon-using-ldap-for-c2-communication-c274a7f00961
    - https://blog.fox-it.com/2020/03/19/ldapfragger-command-and-control-over-ldap-attributes/
    - https://github.com/fox-it/LDAPFragger
tags:
    - attack.t1071          # an old one
    - attack.t1001.003
    - attack.command_and_control
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 5136
        AttributeValue: '*'
        AttributeLDAPDisplayName:
            - 'primaryInternationalISDNNumber'
            - 'otherFacsimileTelephoneNumber'
            - 'primaryTelexNumber'
    condition: selection
falsepositives:
    - Companies, who may use these default LDAP-Attributes for personal information
level: high

```





### powershell
    
```
Get-WinEvent -LogName Security | where {($_.ID -eq "5136" -and $_.message -match "AttributeValue.*.*" -and ($_.message -match "primaryInternationalISDNNumber" -or $_.message -match "otherFacsimileTelephoneNumber" -or $_.message -match "primaryTelexNumber")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.channel:"Security" AND winlog.event_id:"5136" AND AttributeValue.keyword:* AND winlog.event_data.AttributeLDAPDisplayName:("primaryInternationalISDNNumber" OR "otherFacsimileTelephoneNumber" OR "primaryTelexNumber"))
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/d00a9a72-2c09-4459-ad03-5e0a23351e36 <<EOF\n{\n  "metadata": {\n    "title": "Suspicious LDAP-Attributes Used",\n    "description": "Detects the usage of particular AttributeLDAPDisplayNames, which are known for data exchange via LDAP by the tool LDAPFragger and are additionally not commonly used in companies.",\n    "tags": [\n      "attack.t1071",\n      "attack.t1001.003",\n      "attack.command_and_control"\n    ],\n    "query": "(winlog.channel:\\"Security\\" AND winlog.event_id:\\"5136\\" AND AttributeValue.keyword:* AND winlog.event_data.AttributeLDAPDisplayName:(\\"primaryInternationalISDNNumber\\" OR \\"otherFacsimileTelephoneNumber\\" OR \\"primaryTelexNumber\\"))"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "(winlog.channel:\\"Security\\" AND winlog.event_id:\\"5136\\" AND AttributeValue.keyword:* AND winlog.event_data.AttributeLDAPDisplayName:(\\"primaryInternationalISDNNumber\\" OR \\"otherFacsimileTelephoneNumber\\" OR \\"primaryTelexNumber\\"))",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": [\n          "winlogbeat-*"\n        ]\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "throttle_period": "15m",\n      "email": {\n        "profile": "standard",\n        "from": "root@localhost",\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Suspicious LDAP-Attributes Used\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
(EventID:"5136" AND AttributeValue.keyword:* AND AttributeLDAPDisplayName:("primaryInternationalISDNNumber" "otherFacsimileTelephoneNumber" "primaryTelexNumber"))
```


### splunk
    
```
(source="WinEventLog:Security" EventCode="5136" AttributeValue="*" (AttributeLDAPDisplayName="primaryInternationalISDNNumber" OR AttributeLDAPDisplayName="otherFacsimileTelephoneNumber" OR AttributeLDAPDisplayName="primaryTelexNumber"))
```


### logpoint
    
```
(event_source="Microsoft-Windows-Security-Auditing" event_id="5136" AttributeValue="*" AttributeLDAPDisplayName IN ["primaryInternationalISDNNumber", "otherFacsimileTelephoneNumber", "primaryTelexNumber"])
```


### grep
    
```
grep -P '^(?:.*(?=.*5136)(?=.*.*)(?=.*(?:.*primaryInternationalISDNNumber|.*otherFacsimileTelephoneNumber|.*primaryTelexNumber)))'
```



