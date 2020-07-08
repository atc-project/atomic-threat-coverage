| Title                    | Active Directory User Backdoors       |
|:-------------------------|:------------------|
| **Description**          | Detects scenarios where one can control another users or computers account without having to use their credentials. |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0006: Credential Access](https://attack.mitre.org/tactics/TA0006)</li><li>[TA0003: Persistence](https://attack.mitre.org/tactics/TA0003)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1098: Account Manipulation](https://attack.mitre.org/techniques/T1098)</li></ul>  |
| **Data Needed**          |  There is no documented Data Needed for this Detection Rule yet  |
| **Trigger**              | <ul><li>[T1098: Account Manipulation](../Triggers/T1098.md)</li></ul>  |
| **Severity Level**       | high |
| **False Positives**      | <ul><li>Unknown</li></ul>  |
| **Development Status**   |  Development Status wasn't defined for this Detection Rule yet  |
| **References**           | <ul><li>[https://msdn.microsoft.com/en-us/library/cc220234.aspx](https://msdn.microsoft.com/en-us/library/cc220234.aspx)</li><li>[https://adsecurity.org/?p=3466](https://adsecurity.org/?p=3466)</li><li>[https://www.harmj0y.net/blog/redteaming/another-word-on-delegation/](https://www.harmj0y.net/blog/redteaming/another-word-on-delegation/)</li></ul>  |
| **Author**               | @neu5ron |


## Detection Rules

### Sigma rule

```
title: Active Directory User Backdoors
id: 300bac00-e041-4ee2-9c36-e262656a6ecc
description: Detects scenarios where one can control another users or computers account without having to use their credentials.
references:
    - https://msdn.microsoft.com/en-us/library/cc220234.aspx
    - https://adsecurity.org/?p=3466
    - https://www.harmj0y.net/blog/redteaming/another-word-on-delegation/
author: '@neu5ron'
date: 2017/04/13
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
    filter_null:
        AllowedToDelegateTo: null
    filter1:
        AllowedToDelegateTo: '-'
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
    condition: (selection1 and not filter1 and not filter_null) or selection2 or selection3 or selection4
falsepositives:
    - Unknown
level: high

```





### powershell
    
```
Get-WinEvent -LogName Security | where {(((((($_.ID -eq "4738" -and  -not ($_.message -match "AllowedToDelegateTo.*-")) -and  -not (-not AllowedToDelegateTo="*")) -or ($_.ID -eq "5136" -and $_.message -match "AttributeLDAPDisplayName.*msDS-AllowedToDelegateTo")) -or ($_.ID -eq "5136" -and $_.message -match "ObjectClass.*user" -and $_.message -match "AttributeLDAPDisplayName.*servicePrincipalName")) -or ($_.ID -eq "5136" -and $_.message -match "AttributeLDAPDisplayName.*msDS-AllowedToActOnBehalfOfOtherIdentity"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.channel:"Security" AND ((((winlog.channel:"Security" AND (winlog.event_id:"4738" AND (NOT (winlog.event_data.AllowedToDelegateTo:"\-"))) AND (NOT (NOT _exists_:winlog.event_data.AllowedToDelegateTo))) OR (winlog.event_id:"5136" AND winlog.event_data.AttributeLDAPDisplayName:"msDS\-AllowedToDelegateTo")) OR (winlog.event_id:"5136" AND winlog.event_data.ObjectClass:"user" AND winlog.event_data.AttributeLDAPDisplayName:"servicePrincipalName")) OR (winlog.event_id:"5136" AND winlog.event_data.AttributeLDAPDisplayName:"msDS\-AllowedToActOnBehalfOfOtherIdentity")))
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/300bac00-e041-4ee2-9c36-e262656a6ecc <<EOF
{
  "metadata": {
    "title": "Active Directory User Backdoors",
    "description": "Detects scenarios where one can control another users or computers account without having to use their credentials.",
    "tags": [
      "attack.t1098",
      "attack.credential_access",
      "attack.persistence"
    ],
    "query": "(winlog.channel:\"Security\" AND ((((winlog.channel:\"Security\" AND (winlog.event_id:\"4738\" AND (NOT (winlog.event_data.AllowedToDelegateTo:\"\\-\"))) AND (NOT (NOT _exists_:winlog.event_data.AllowedToDelegateTo))) OR (winlog.event_id:\"5136\" AND winlog.event_data.AttributeLDAPDisplayName:\"msDS\\-AllowedToDelegateTo\")) OR (winlog.event_id:\"5136\" AND winlog.event_data.ObjectClass:\"user\" AND winlog.event_data.AttributeLDAPDisplayName:\"servicePrincipalName\")) OR (winlog.event_id:\"5136\" AND winlog.event_data.AttributeLDAPDisplayName:\"msDS\\-AllowedToActOnBehalfOfOtherIdentity\")))"
  },
  "trigger": {
    "schedule": {
      "interval": "30m"
    }
  },
  "input": {
    "search": {
      "request": {
        "body": {
          "size": 0,
          "query": {
            "bool": {
              "must": [
                {
                  "query_string": {
                    "query": "(winlog.channel:\"Security\" AND ((((winlog.channel:\"Security\" AND (winlog.event_id:\"4738\" AND (NOT (winlog.event_data.AllowedToDelegateTo:\"\\-\"))) AND (NOT (NOT _exists_:winlog.event_data.AllowedToDelegateTo))) OR (winlog.event_id:\"5136\" AND winlog.event_data.AttributeLDAPDisplayName:\"msDS\\-AllowedToDelegateTo\")) OR (winlog.event_id:\"5136\" AND winlog.event_data.ObjectClass:\"user\" AND winlog.event_data.AttributeLDAPDisplayName:\"servicePrincipalName\")) OR (winlog.event_id:\"5136\" AND winlog.event_data.AttributeLDAPDisplayName:\"msDS\\-AllowedToActOnBehalfOfOtherIdentity\")))",
                    "analyze_wildcard": true
                  }
                }
              ],
              "filter": {
                "range": {
                  "timestamp": {
                    "gte": "now-30m/m"
                  }
                }
              }
            }
          }
        },
        "indices": [
          "winlogbeat-*"
        ]
      }
    }
  },
  "condition": {
    "compare": {
      "ctx.payload.hits.total": {
        "not_eq": 0
      }
    }
  },
  "actions": {
    "send_email": {
      "throttle_period": "15m",
      "email": {
        "profile": "standard",
        "from": "root@localhost",
        "to": "root@localhost",
        "subject": "Sigma Rule 'Active Directory User Backdoors'",
        "body": "Hits:\n{{#ctx.payload.hits.hits}}{{_source}}\n================================================================================\n{{/ctx.payload.hits.hits}}",
        "attachments": {
          "data.json": {
            "data": {
              "format": "json"
            }
          }
        }
      }
    }
  }
}
EOF

```


### graylog
    
```
(((((EventID:"4738" AND (NOT (AllowedToDelegateTo:"\-"))) AND (NOT (NOT _exists_:AllowedToDelegateTo))) OR (EventID:"5136" AND AttributeLDAPDisplayName:"msDS\-AllowedToDelegateTo")) OR (EventID:"5136" AND ObjectClass:"user" AND AttributeLDAPDisplayName:"servicePrincipalName")) OR (EventID:"5136" AND AttributeLDAPDisplayName:"msDS\-AllowedToActOnBehalfOfOtherIdentity"))
```


### splunk
    
```
(source="WinEventLog:Security" ((((source="WinEventLog:Security" (EventCode="4738" NOT (AllowedToDelegateTo="-")) NOT (NOT AllowedToDelegateTo="*")) OR (EventCode="5136" AttributeLDAPDisplayName="msDS-AllowedToDelegateTo")) OR (EventCode="5136" ObjectClass="user" AttributeLDAPDisplayName="servicePrincipalName")) OR (EventCode="5136" AttributeLDAPDisplayName="msDS-AllowedToActOnBehalfOfOtherIdentity")))
```


### logpoint
    
```
(event_source="Microsoft-Windows-Security-Auditing" ((((event_source="Microsoft-Windows-Security-Auditing" (event_id="4738"  -(AllowedToDelegateTo="-"))  -(-AllowedToDelegateTo=*)) OR (event_id="5136" AttributeLDAPDisplayName="msDS-AllowedToDelegateTo")) OR (event_id="5136" ObjectClass="user" AttributeLDAPDisplayName="servicePrincipalName")) OR (event_id="5136" AttributeLDAPDisplayName="msDS-AllowedToActOnBehalfOfOtherIdentity")))
```


### grep
    
```
grep -P '^(?:.*(?:.*(?:.*(?:.*(?:.*(?:.*(?:.*(?=.*(?:.*(?=.*4738)(?=.*(?!.*(?:.*(?=.*-))))))(?=.*(?!.*(?:.*(?=.*(?!AllowedToDelegateTo))))))|.*(?:.*(?=.*5136)(?=.*msDS-AllowedToDelegateTo))))|.*(?:.*(?=.*5136)(?=.*user)(?=.*servicePrincipalName))))|.*(?:.*(?=.*5136)(?=.*msDS-AllowedToActOnBehalfOfOtherIdentity))))'
```



