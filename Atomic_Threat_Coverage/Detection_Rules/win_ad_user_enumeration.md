| Title                    | AD User Enumeration       |
|:-------------------------|:------------------|
| **Description**          | Detects access to a domain user from a non-machine account |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0007: Discovery](https://attack.mitre.org/tactics/TA0007)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1087: Account Discovery](https://attack.mitre.org/techniques/T1087)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0030_4662_operation_was_performed_on_an_object](../Data_Needed/DN_0030_4662_operation_was_performed_on_an_object.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1087: Account Discovery](../Triggers/T1087.md)</li></ul>  |
| **Severity Level**       | medium |
| **False Positives**      | <ul><li>Administrators configuring new users.</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://www.specterops.io/assets/resources/an_ace_up_the_sleeve.pdf](https://www.specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)</li><li>[http://www.stuffithoughtiknew.com/2019/02/detecting-bloodhound.html](http://www.stuffithoughtiknew.com/2019/02/detecting-bloodhound.html)</li><li>[https://docs.microsoft.com/en-us/windows/win32/adschema/attributes-all](https://docs.microsoft.com/en-us/windows/win32/adschema/attributes-all)</li></ul>  |
| **Author**               | Maxime Thiebaut (@0xThiebaut) |


## Detection Rules

### Sigma rule

```
title: AD User Enumeration
id: ab6bffca-beff-4baa-af11-6733f296d57a
description: Detects access to a domain user from a non-machine account
status: experimental
date: 2020/03/30
author: Maxime Thiebaut (@0xThiebaut)
references:
    - https://www.specterops.io/assets/resources/an_ace_up_the_sleeve.pdf
    - http://www.stuffithoughtiknew.com/2019/02/detecting-bloodhound.html
    - https://docs.microsoft.com/en-us/windows/win32/adschema/attributes-all # For further investigation of the accessed properties
tags:
    - attack.discovery
    - attack.t1087
logsource:
    product: windows
    service: security
    definition: Requires the "Read all properties" permission on the user object to be audited for the "Everyone" principal
detection:
    selection:
        EventID: 4662
        ObjectType|contains: # Using contains as the data commonly is structured as "%{bf967aba-0de6-11d0-a285-00aa003049e2}"
            - 'bf967aba-0de6-11d0-a285-00aa003049e2' # The user class (https://docs.microsoft.com/en-us/windows/win32/adschema/c-user)
    filter:
        - SubjectUserName|endswith: '$' # Exclude machine accounts
        - SubjectUserName|startswith: 'MSOL_' # https://docs.microsoft.com/en-us/azure/active-directory/hybrid/reference-connect-accounts-permissions#ad-ds-connector-account
    condition: selection and not filter
falsepositives:
    - Administrators configuring new users.
level: medium

```





### powershell
    
```
Get-WinEvent -LogName Security | where {(($_.ID -eq "4662" -and ($_.message -match "ObjectType.*.*bf967aba-0de6-11d0-a285-00aa003049e2.*")) -and  -not ($_.message -match "SubjectUserName.*.*$" -or $_.message -match "SubjectUserName.*MSOL_.*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.channel:"Security" AND (winlog.event_id:"4662" AND winlog.event_data.ObjectType.keyword:(*bf967aba\-0de6\-11d0\-a285\-00aa003049e2*)) AND (NOT (winlog.event_data.SubjectUserName.keyword:*$ OR winlog.event_data.SubjectUserName.keyword:MSOL_*)))
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/ab6bffca-beff-4baa-af11-6733f296d57a <<EOF
{
  "metadata": {
    "title": "AD User Enumeration",
    "description": "Detects access to a domain user from a non-machine account",
    "tags": [
      "attack.discovery",
      "attack.t1087"
    ],
    "query": "(winlog.channel:\"Security\" AND (winlog.event_id:\"4662\" AND winlog.event_data.ObjectType.keyword:(*bf967aba\\-0de6\\-11d0\\-a285\\-00aa003049e2*)) AND (NOT (winlog.event_data.SubjectUserName.keyword:*$ OR winlog.event_data.SubjectUserName.keyword:MSOL_*)))"
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
                    "query": "(winlog.channel:\"Security\" AND (winlog.event_id:\"4662\" AND winlog.event_data.ObjectType.keyword:(*bf967aba\\-0de6\\-11d0\\-a285\\-00aa003049e2*)) AND (NOT (winlog.event_data.SubjectUserName.keyword:*$ OR winlog.event_data.SubjectUserName.keyword:MSOL_*)))",
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
      "email": {
        "to": "root@localhost",
        "subject": "Sigma Rule 'AD User Enumeration'",
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
((EventID:"4662" AND ObjectType.keyword:(*bf967aba\-0de6\-11d0\-a285\-00aa003049e2*)) AND (NOT (SubjectUserName.keyword:*$ OR SubjectUserName.keyword:MSOL_*)))
```


### splunk
    
```
(source="WinEventLog:Security" (EventCode="4662" (ObjectType="*bf967aba-0de6-11d0-a285-00aa003049e2*")) NOT (SubjectUserName="*$" OR SubjectUserName="MSOL_*"))
```


### logpoint
    
```
(event_source="Microsoft-Windows-Security-Auditing" (event_id="4662" ObjectType IN ["*bf967aba-0de6-11d0-a285-00aa003049e2*"])  -(SubjectUserName="*$" OR SubjectUserName="MSOL_*"))
```


### grep
    
```
grep -P '^(?:.*(?=.*(?:.*(?=.*4662)(?=.*(?:.*.*bf967aba-0de6-11d0-a285-00aa003049e2.*))))(?=.*(?!.*(?:.*(?:.*(?=.*.*\$)|.*(?=.*MSOL_.*))))))'
```



