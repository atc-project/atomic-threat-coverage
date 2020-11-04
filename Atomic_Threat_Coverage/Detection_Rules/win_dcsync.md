| Title                    | Mimikatz DC Sync       |
|:-------------------------|:------------------|
| **Description**          | Detects Mimikatz DC sync security events |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0006: Credential Access](https://attack.mitre.org/tactics/TA0006)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1003: OS Credential Dumping](https://attack.mitre.org/techniques/T1003)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0030_4662_operation_was_performed_on_an_object](../Data_Needed/DN_0030_4662_operation_was_performed_on_an_object.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1003: OS Credential Dumping](../Triggers/T1003.md)</li></ul>  |
| **Severity Level**       | high |
| **False Positives**      | <ul><li>Valid DC Sync that is not covered by the filters; please report</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://twitter.com/gentilkiwi/status/1003236624925413376](https://twitter.com/gentilkiwi/status/1003236624925413376)</li><li>[https://gist.github.com/gentilkiwi/dcc132457408cf11ad2061340dcb53c2](https://gist.github.com/gentilkiwi/dcc132457408cf11ad2061340dcb53c2)</li></ul>  |
| **Author**               | Benjamin Delpy, Florian Roth |
| Other Tags           | <ul><li>attack.s0002</li></ul> | 

## Detection Rules

### Sigma rule

```
title: Mimikatz DC Sync
id: 611eab06-a145-4dfa-a295-3ccc5c20f59a
description: Detects Mimikatz DC sync security events
status: experimental
date: 2018/06/03
modified: 2019/10/08
author: Benjamin Delpy, Florian Roth
references:
    - https://twitter.com/gentilkiwi/status/1003236624925413376
    - https://gist.github.com/gentilkiwi/dcc132457408cf11ad2061340dcb53c2
tags:
    - attack.credential_access
    - attack.s0002
    - attack.t1003
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4662
        Properties: 
            - '*Replicating Directory Changes All*'
            - '*1131f6ad-9c07-11d1-f79f-00c04fc2dcd2*'
    filter1:
        SubjectDomainName: 'Window Manager'
    filter2: 
        SubjectUserName:
            - 'NT AUTHORITY*'
            - '*$'
    condition: selection and not filter1 and not filter2
falsepositives:
    - Valid DC Sync that is not covered by the filters; please report
level: high


```





### powershell
    
```
Get-WinEvent -LogName Security | where {((($_.ID -eq "4662" -and ($_.message -match "Properties.*.*Replicating Directory Changes All.*" -or $_.message -match "Properties.*.*1131f6ad-9c07-11d1-f79f-00c04fc2dcd2.*")) -and  -not ($_.message -match "SubjectDomainName.*Window Manager")) -and  -not (($_.message -match "SubjectUserName.*NT AUTHORITY.*" -or $_.message -match "SubjectUserName.*.*$"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.channel:"Security" AND ((winlog.event_id:"4662" AND winlog.event_data.Properties.keyword:(*Replicating\ Directory\ Changes\ All* OR *1131f6ad\-9c07\-11d1\-f79f\-00c04fc2dcd2*)) AND (NOT (SubjectDomainName:"Window\ Manager"))) AND (NOT (winlog.event_data.SubjectUserName.keyword:(NT\ AUTHORITY* OR *$))))
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/611eab06-a145-4dfa-a295-3ccc5c20f59a <<EOF
{
  "metadata": {
    "title": "Mimikatz DC Sync",
    "description": "Detects Mimikatz DC sync security events",
    "tags": [
      "attack.credential_access",
      "attack.s0002",
      "attack.t1003"
    ],
    "query": "(winlog.channel:\"Security\" AND ((winlog.event_id:\"4662\" AND winlog.event_data.Properties.keyword:(*Replicating\\ Directory\\ Changes\\ All* OR *1131f6ad\\-9c07\\-11d1\\-f79f\\-00c04fc2dcd2*)) AND (NOT (SubjectDomainName:\"Window\\ Manager\"))) AND (NOT (winlog.event_data.SubjectUserName.keyword:(NT\\ AUTHORITY* OR *$))))"
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
                    "query": "(winlog.channel:\"Security\" AND ((winlog.event_id:\"4662\" AND winlog.event_data.Properties.keyword:(*Replicating\\ Directory\\ Changes\\ All* OR *1131f6ad\\-9c07\\-11d1\\-f79f\\-00c04fc2dcd2*)) AND (NOT (SubjectDomainName:\"Window\\ Manager\"))) AND (NOT (winlog.event_data.SubjectUserName.keyword:(NT\\ AUTHORITY* OR *$))))",
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
        "subject": "Sigma Rule 'Mimikatz DC Sync'",
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
(((EventID:"4662" AND Properties.keyword:(*Replicating Directory Changes All* *1131f6ad\-9c07\-11d1\-f79f\-00c04fc2dcd2*)) AND (NOT (SubjectDomainName:"Window Manager"))) AND (NOT (SubjectUserName.keyword:(NT AUTHORITY* *$))))
```


### splunk
    
```
(source="WinEventLog:Security" ((EventCode="4662" (Properties="*Replicating Directory Changes All*" OR Properties="*1131f6ad-9c07-11d1-f79f-00c04fc2dcd2*")) NOT (SubjectDomainName="Window Manager")) NOT ((SubjectUserName="NT AUTHORITY*" OR SubjectUserName="*$")))
```


### logpoint
    
```
(event_source="Microsoft-Windows-Security-Auditing" ((event_id="4662" Properties IN ["*Replicating Directory Changes All*", "*1131f6ad-9c07-11d1-f79f-00c04fc2dcd2*"])  -(SubjectDomainName="Window Manager"))  -(SubjectUserName IN ["NT AUTHORITY*", "*$"]))
```


### grep
    
```
grep -P '^(?:.*(?=.*(?:.*(?=.*(?:.*(?=.*4662)(?=.*(?:.*.*Replicating Directory Changes All.*|.*.*1131f6ad-9c07-11d1-f79f-00c04fc2dcd2.*))))(?=.*(?!.*(?:.*(?=.*Window Manager))))))(?=.*(?!.*(?:.*(?=.*(?:.*NT AUTHORITY.*|.*.*\$))))))'
```



