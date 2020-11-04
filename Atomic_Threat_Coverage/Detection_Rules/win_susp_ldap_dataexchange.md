| Title                    | Suspicious LDAP-Attributes Used       |
|:-------------------------|:------------------|
| **Description**          | detects the usage of particular AttributeLDAPDisplayNames, which are known for data exchange via LDAP by the tool LDAPFragger and are additionally not commonly used in companies. |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0003: Persistence](https://attack.mitre.org/tactics/TA0003)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1041: Exfiltration Over C2 Channel](https://attack.mitre.org/techniques/T1041)</li></ul>  |
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
description: detects the usage of particular AttributeLDAPDisplayNames, which are known for data exchange via LDAP by the tool LDAPFragger and are additionally not commonly used in companies.
status: experimental
date: 2019/03/24
author: xknow @xknow_infosec
references:
    - https://medium.com/@ivecodoe/detecting-ldapfragger-a-newly-released-cobalt-strike-beacon-using-ldap-for-c2-communication-c274a7f00961
    - https://blog.fox-it.com/2020/03/19/ldapfragger-command-and-control-over-ldap-attributes/
    - https://github.com/fox-it/LDAPFragger
tags:
    - attack.t1041
    - attack.persistence
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
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/d00a9a72-2c09-4459-ad03-5e0a23351e36 <<EOF
{
  "metadata": {
    "title": "Suspicious LDAP-Attributes Used",
    "description": "detects the usage of particular AttributeLDAPDisplayNames, which are known for data exchange via LDAP by the tool LDAPFragger and are additionally not commonly used in companies.",
    "tags": [
      "attack.t1041",
      "attack.persistence"
    ],
    "query": "(winlog.channel:\"Security\" AND winlog.event_id:\"5136\" AND AttributeValue.keyword:* AND winlog.event_data.AttributeLDAPDisplayName:(\"primaryInternationalISDNNumber\" OR \"otherFacsimileTelephoneNumber\" OR \"primaryTelexNumber\"))"
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
                    "query": "(winlog.channel:\"Security\" AND winlog.event_id:\"5136\" AND AttributeValue.keyword:* AND winlog.event_data.AttributeLDAPDisplayName:(\"primaryInternationalISDNNumber\" OR \"otherFacsimileTelephoneNumber\" OR \"primaryTelexNumber\"))",
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
        "subject": "Sigma Rule 'Suspicious LDAP-Attributes Used'",
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



