| Title                | Powerview Add-DomainObjectAcl DCSync AD Extend Right                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | backdooring domain object to grant the rights associated with DCSync to a regular user or machine account using Powerview\Add-DomainObjectAcl DCSync Extended Right cmdlet, will allow to re-obtain the pwd hashes of any user/computer                                                                                                                                           |
| ATT&amp;CK Tactic    | <ul><li>[TA0006: Credential Access](https://attack.mitre.org/tactics/TA0006)</li><li>[TA0003: Persistence](https://attack.mitre.org/tactics/TA0003)</li></ul>  |
| ATT&amp;CK Technique | <ul></ul>                             |
| Data Needed          | <ul><li>[DN_0026_5136_windows_directory_service_object_was_modified](../Data_Needed/DN_0026_5136_windows_directory_service_object_was_modified.md)</li></ul>                                                         |
| Trigger              |  There is no Trigger for this technique yet.  |
| Severity Level       | critical                                                                                                                                                 |
| False Positives      | <ul><li>New Domain Controller computer account, check user SIDs witin the value attribute of event 5136 and verify if it's a regular user or DC computer account.</li></ul>                                                                  |
| Development Status   | experimental                                                                                                                                                |
| References           | <ul><li>[https://twitter.com/menasec1/status/1111556090137903104](https://twitter.com/menasec1/status/1111556090137903104)</li><li>[https://www.specterops.io/assets/resources/an_ace_up_the_sleeve.pdf](https://www.specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)</li></ul>                                                          |
| Author               | Samir Bousseaden                                                                                                                                                |


## Detection Rules

### Sigma rule

```
title: Powerview Add-DomainObjectAcl DCSync AD Extend Right
description: backdooring domain object to grant the rights associated with DCSync to a regular user or machine account using Powerview\Add-DomainObjectAcl DCSync Extended Right cmdlet, will allow to re-obtain the pwd hashes of any user/computer
status: experimental
date: 2019/04/03
author: Samir Bousseaden
references:
    - https://twitter.com/menasec1/status/1111556090137903104
    - https://www.specterops.io/assets/resources/an_ace_up_the_sleeve.pdf
tags:
    - attack.credential_access
    - attack.persistence
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 5136
        LDAPDisplayName: 'ntSecurityDescriptor'
        Value: 
         - '*1131f6ad-9c07-11d1-f79f-00c04fc2dcd2*'
         - '*1131f6aa-9c07-11d1-f79f-00c04fc2dcd2*'
    condition: selection
falsepositives:
    - New Domain Controller computer account, check user SIDs witin the value attribute of event 5136 and verify if it's a regular user or DC computer account.
level: critical

```





### es-qs
    
```
(EventID:"5136" AND LDAPDisplayName:"ntSecurityDescriptor" AND Value.keyword:(*1131f6ad\\-9c07\\-11d1\\-f79f\\-00c04fc2dcd2* *1131f6aa\\-9c07\\-11d1\\-f79f\\-00c04fc2dcd2*))
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_xpack/watcher/watch/Powerview-Add-DomainObjectAcl-DCSync-AD-Extend-Right <<EOF\n{\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "query_string": {\n              "query": "(EventID:\\"5136\\" AND LDAPDisplayName:\\"ntSecurityDescriptor\\" AND Value.keyword:(*1131f6ad\\\\-9c07\\\\-11d1\\\\-f79f\\\\-00c04fc2dcd2* *1131f6aa\\\\-9c07\\\\-11d1\\\\-f79f\\\\-00c04fc2dcd2*))",\n              "analyze_wildcard": true\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": null,\n        "subject": "Sigma Rule \'Powerview Add-DomainObjectAcl DCSync AD Extend Right\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
(EventID:"5136" AND LDAPDisplayName:"ntSecurityDescriptor" AND Value:("*1131f6ad\\-9c07\\-11d1\\-f79f\\-00c04fc2dcd2*" "*1131f6aa\\-9c07\\-11d1\\-f79f\\-00c04fc2dcd2*"))
```


### splunk
    
```
(EventID="5136" LDAPDisplayName="ntSecurityDescriptor" (Value="*1131f6ad-9c07-11d1-f79f-00c04fc2dcd2*" OR Value="*1131f6aa-9c07-11d1-f79f-00c04fc2dcd2*"))
```


### logpoint
    
```
(EventID="5136" LDAPDisplayName="ntSecurityDescriptor" Value IN ["*1131f6ad-9c07-11d1-f79f-00c04fc2dcd2*", "*1131f6aa-9c07-11d1-f79f-00c04fc2dcd2*"])
```


### grep
    
```
grep -P '^(?:.*(?=.*5136)(?=.*ntSecurityDescriptor)(?=.*(?:.*.*1131f6ad-9c07-11d1-f79f-00c04fc2dcd2.*|.*.*1131f6aa-9c07-11d1-f79f-00c04fc2dcd2.*)))'
```



