| Title                    | Pass the Hash Activity       |
|:-------------------------|:------------------|
| **Description**          | Detects the attack technique pass the hash which is used to move laterally inside the network |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0008: Lateral Movement](https://attack.mitre.org/tactics/TA0008)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1075: Pass the Hash](https://attack.mitre.org/techniques/T1075)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0004_4624_windows_account_logon](../Data_Needed/DN_0004_4624_windows_account_logon.md)</li><li>[DN_0057_4625_account_failed_to_logon](../Data_Needed/DN_0057_4625_account_failed_to_logon.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1075: Pass the Hash](../Triggers/T1075.md)</li></ul>  |
| **Severity Level**       | medium |
| **False Positives**      | <ul><li>Administrator activity</li><li>Penetration tests</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://github.com/iadgov/Event-Forwarding-Guidance/tree/master/Events](https://github.com/iadgov/Event-Forwarding-Guidance/tree/master/Events)</li></ul>  |
| **Author**               | Ilias el Matani (rule), The Information Assurance Directorate at the NSA (method) |
| Other Tags           | <ul><li>car.2016-04-004</li></ul> | 

## Detection Rules

### Sigma rule

```
title: Pass the Hash Activity
id: f8d98d6c-7a07-4d74-b064-dd4a3c244528
status: experimental
description: Detects the attack technique pass the hash which is used to move laterally inside the network
references:
    - https://github.com/iadgov/Event-Forwarding-Guidance/tree/master/Events
author: Ilias el Matani (rule), The Information Assurance Directorate at the NSA (method)
date: 2017/03/08
tags:
    - attack.lateral_movement
    - attack.t1075
    - car.2016-04-004
logsource:
    product: windows
    service: security
    definition: The successful use of PtH for lateral movement between workstations would trigger event ID 4624, a failed logon attempt would trigger an event ID 4625
detection:
    selection:
        - EventID: 4624
          LogonType: '3'
          LogonProcessName: 'NtLmSsp'
          WorkstationName: '%Workstations%'
          ComputerName: '%Workstations%'
        - EventID: 4625
          LogonType: '3'
          LogonProcessName: 'NtLmSsp'
          WorkstationName: '%Workstations%'
          ComputerName: '%Workstations%'
    filter:
        AccountName: 'ANONYMOUS LOGON'
    condition: selection and not filter
falsepositives:
    - Administrator activity
    - Penetration tests
level: medium

```





### powershell
    
```
Get-WinEvent -LogName Security | where {(($_.message -match "LogonType.*3" -and $_.message -match "LogonProcessName.*NtLmSsp" -and $_.message -match "WorkstationName.*%Workstations%" -and $_.message -match "ComputerName.*%Workstations%" -and ($_.ID -eq "4624" -or $_.ID -eq "4625")) -and  -not ($_.message -match "AccountName.*ANONYMOUS LOGON")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.channel:"Security" AND (winlog.event_data.LogonType:"3" AND winlog.event_data.LogonProcessName:"NtLmSsp" AND winlog.event_data.WorkstationName:"%Workstations%" AND winlog.computer_name:"%Workstations%" AND (winlog.event_id:"4624" OR winlog.event_id:"4625")) AND (NOT (winlog.event_data.AccountName:"ANONYMOUS\ LOGON")))
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/f8d98d6c-7a07-4d74-b064-dd4a3c244528 <<EOF
{
  "metadata": {
    "title": "Pass the Hash Activity",
    "description": "Detects the attack technique pass the hash which is used to move laterally inside the network",
    "tags": [
      "attack.lateral_movement",
      "attack.t1075",
      "car.2016-04-004"
    ],
    "query": "(winlog.channel:\"Security\" AND (winlog.event_data.LogonType:\"3\" AND winlog.event_data.LogonProcessName:\"NtLmSsp\" AND winlog.event_data.WorkstationName:\"%Workstations%\" AND winlog.computer_name:\"%Workstations%\" AND (winlog.event_id:\"4624\" OR winlog.event_id:\"4625\")) AND (NOT (winlog.event_data.AccountName:\"ANONYMOUS\\ LOGON\")))"
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
                    "query": "(winlog.channel:\"Security\" AND (winlog.event_data.LogonType:\"3\" AND winlog.event_data.LogonProcessName:\"NtLmSsp\" AND winlog.event_data.WorkstationName:\"%Workstations%\" AND winlog.computer_name:\"%Workstations%\" AND (winlog.event_id:\"4624\" OR winlog.event_id:\"4625\")) AND (NOT (winlog.event_data.AccountName:\"ANONYMOUS\\ LOGON\")))",
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
        "subject": "Sigma Rule 'Pass the Hash Activity'",
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
((LogonType:"3" AND LogonProcessName:"NtLmSsp" AND WorkstationName:"%Workstations%" AND ComputerName:"%Workstations%" AND (EventID:"4624" OR EventID:"4625")) AND (NOT (AccountName:"ANONYMOUS LOGON")))
```


### splunk
    
```
(source="WinEventLog:Security" (LogonType="3" LogonProcessName="NtLmSsp" WorkstationName="%Workstations%" ComputerName="%Workstations%" (EventCode="4624" OR EventCode="4625")) NOT (AccountName="ANONYMOUS LOGON"))
```


### logpoint
    
```
(event_source="Microsoft-Windows-Security-Auditing" (logon_type="3" logon_process="NtLmSsp" WorkstationName="%Workstations%" ComputerName="%Workstations%" (event_id="4624" OR event_id="4625"))  -(AccountName="ANONYMOUS LOGON"))
```


### grep
    
```
grep -P '^(?:.*(?=.*(?:.*(?=.*3)(?=.*NtLmSsp)(?=.*%Workstations%)(?=.*%Workstations%)(?=.*(?:.*(?:.*4624|.*4625)))))(?=.*(?!.*(?:.*(?=.*ANONYMOUS LOGON)))))'
```



