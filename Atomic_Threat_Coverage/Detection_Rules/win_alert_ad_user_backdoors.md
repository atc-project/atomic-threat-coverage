| Title                | Active Directory User Backdoors                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects scenarios where one can control another users or computers account without having to use their credentials.                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0006: Credential Access](https://attack.mitre.org/tactics/TA0006)</li><li>[TA0003: Persistence](https://attack.mitre.org/tactics/TA0003)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1098: Account Manipulation](https://attack.mitre.org/techniques/T1098)</li></ul>  |
| Data Needed          | <ul><li>[DN_0027_4738_user_account_was_changed](../Data_Needed/DN_0027_4738_user_account_was_changed.md)</li><li>[DN_0026_5136_windows_directory_service_object_was_modified](../Data_Needed/DN_0026_5136_windows_directory_service_object_was_modified.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1098: Account Manipulation](../Triggers/T1098.md)</li></ul>  |
| Severity Level       | high |
| False Positives      | <ul><li>Unknown</li></ul>  |
| Development Status   |  Development Status wasn't defined for this Detection Rule yet  |
| References           | <ul><li>[https://msdn.microsoft.com/en-us/library/cc220234.aspx](https://msdn.microsoft.com/en-us/library/cc220234.aspx)</li><li>[https://adsecurity.org/?p=3466](https://adsecurity.org/?p=3466)</li><li>[https://www.harmj0y.net/blog/redteaming/another-word-on-delegation/](https://www.harmj0y.net/blog/redteaming/another-word-on-delegation/)</li></ul>  |
| Author               | @neu5ron |


## Detection Rules

### Sigma rule

```
title: Active Directory User Backdoors
description: Detects scenarios where one can control another users or computers account without having to use their credentials.
references:
    - https://msdn.microsoft.com/en-us/library/cc220234.aspx
    - https://adsecurity.org/?p=3466
    - https://www.harmj0y.net/blog/redteaming/another-word-on-delegation/
author: '@neu5ron'
tags:
    - attack.t1098
    - attack.credential_access
    - attack.persistence
logsource:
    product: windows
    service: security
    definition1: 'Requirements: Audit Policy : Account Management > Audit User Account Management, Group Policy : Computer Configuration\Windows Settings\Security Settings\Advanced Audit Policy Configuration\Audit Policies\Account Management\Audit User Account Management'
    definition2: 'Requirements: Audit Policy : DS Access > Audit Directory Service Changes, Group Policy : Computer Configuration\Windows Settings\Security Settings\Advanced Audit Policy Configuration\Audit Policies\DS Access\Audit Directory Service Changes'
detection:
    selection1:
        EventID: 4738
    filter1:
        AllowedToDelegateTo: null
    selection2:
        EventID: 5136
        AttributeLDAPDisplayName: 'msDS-AllowedToDelegateTo'
    selection3:
        EventID: 5136
        ObjectClass: 'user'
        AttributeLDAPDisplayName: 'servicePrincipalName'
    selection4:
        EventID: 5136
        AttributeLDAPDisplayName: 'msDS-AllowedToActOnBehalfOfOtherIdentity'        
    condition: (selection1 and not filter1) or selection2 or selection3 or selection4
falsepositives: 
    - Unknown
level: high

```





### es-qs
    
```
((((EventID:"4738" AND (NOT (NOT _exists_:AllowedToDelegateTo))) OR (EventID:"5136" AND AttributeLDAPDisplayName:"msDS\\-AllowedToDelegateTo")) OR (EventID:"5136" AND ObjectClass:"user" AND AttributeLDAPDisplayName:"servicePrincipalName")) OR (EventID:"5136" AND AttributeLDAPDisplayName:"msDS\\-AllowedToActOnBehalfOfOtherIdentity"))
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/Active-Directory-User-Backdoors <<EOF\n{\n  "metadata": {\n    "title": "Active Directory User Backdoors",\n    "description": "Detects scenarios where one can control another users or computers account without having to use their credentials.",\n    "tags": [\n      "attack.t1098",\n      "attack.credential_access",\n      "attack.persistence"\n    ],\n    "query": "((((EventID:\\"4738\\" AND (NOT (NOT _exists_:AllowedToDelegateTo))) OR (EventID:\\"5136\\" AND AttributeLDAPDisplayName:\\"msDS\\\\-AllowedToDelegateTo\\")) OR (EventID:\\"5136\\" AND ObjectClass:\\"user\\" AND AttributeLDAPDisplayName:\\"servicePrincipalName\\")) OR (EventID:\\"5136\\" AND AttributeLDAPDisplayName:\\"msDS\\\\-AllowedToActOnBehalfOfOtherIdentity\\"))"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "((((EventID:\\"4738\\" AND (NOT (NOT _exists_:AllowedToDelegateTo))) OR (EventID:\\"5136\\" AND AttributeLDAPDisplayName:\\"msDS\\\\-AllowedToDelegateTo\\")) OR (EventID:\\"5136\\" AND ObjectClass:\\"user\\" AND AttributeLDAPDisplayName:\\"servicePrincipalName\\")) OR (EventID:\\"5136\\" AND AttributeLDAPDisplayName:\\"msDS\\\\-AllowedToActOnBehalfOfOtherIdentity\\"))",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Active Directory User Backdoors\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
((((EventID:"4738" AND NOT (NOT _exists_:AllowedToDelegateTo)) OR (EventID:"5136" AND AttributeLDAPDisplayName:"msDS\\-AllowedToDelegateTo")) OR (EventID:"5136" AND ObjectClass:"user" AND AttributeLDAPDisplayName:"servicePrincipalName")) OR (EventID:"5136" AND AttributeLDAPDisplayName:"msDS\\-AllowedToActOnBehalfOfOtherIdentity"))
```


### splunk
    
```
((((EventID="4738" NOT (NOT AllowedToDelegateTo="*")) OR (EventID="5136" AttributeLDAPDisplayName="msDS-AllowedToDelegateTo")) OR (EventID="5136" ObjectClass="user" AttributeLDAPDisplayName="servicePrincipalName")) OR (EventID="5136" AttributeLDAPDisplayName="msDS-AllowedToActOnBehalfOfOtherIdentity"))
```


### logpoint
    
```
((((EventID="4738"  -(-AllowedToDelegateTo=*)) OR (EventID="5136" AttributeLDAPDisplayName="msDS-AllowedToDelegateTo")) OR (EventID="5136" ObjectClass="user" AttributeLDAPDisplayName="servicePrincipalName")) OR (EventID="5136" AttributeLDAPDisplayName="msDS-AllowedToActOnBehalfOfOtherIdentity"))
```


### grep
    
```
grep -P '^(?:.*(?:.*(?:.*(?:.*(?:.*(?:.*(?:.*(?=.*4738)(?=.*(?!.*(?:.*(?=.*(?!AllowedToDelegateTo))))))|.*(?:.*(?=.*5136)(?=.*msDS-AllowedToDelegateTo))))|.*(?:.*(?=.*5136)(?=.*user)(?=.*servicePrincipalName))))|.*(?:.*(?=.*5136)(?=.*msDS-AllowedToActOnBehalfOfOtherIdentity))))'
```



