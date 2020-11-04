| Title                    | UAC Bypass via Sdclt       |
|:-------------------------|:------------------|
| **Description**          | Detects changes to HKCU:\Software\Classes\exefile\shell\runas\command\isolatedCommand |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li><li>[TA0004: Privilege Escalation](https://attack.mitre.org/tactics/TA0004)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1088: Bypass User Account Control](https://attack.mitre.org/techniques/T1088)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0017_13_windows_sysmon_RegistryEvent](../Data_Needed/DN_0017_13_windows_sysmon_RegistryEvent.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1088: Bypass User Account Control](../Triggers/T1088.md)</li></ul>  |
| **Severity Level**       | high |
| **False Positives**      | <ul><li>unknown</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://enigma0x3.net/2017/03/17/fileless-uac-bypass-using-sdclt-exe/](https://enigma0x3.net/2017/03/17/fileless-uac-bypass-using-sdclt-exe/)</li></ul>  |
| **Author**               | Omer Yampel |
| Other Tags           | <ul><li>car.2019-04-001</li></ul> | 

## Detection Rules

### Sigma rule

```
title: UAC Bypass via Sdclt
id: 5b872a46-3b90-45c1-8419-f675db8053aa
status: experimental
description: Detects changes to HKCU:\Software\Classes\exefile\shell\runas\command\isolatedCommand
references:
    - https://enigma0x3.net/2017/03/17/fileless-uac-bypass-using-sdclt-exe/
author: Omer Yampel
date: 2017/03/17
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        EventID: 13
        # usrclass.dat is mounted on HKU\USERSID_Classes\...
        TargetObject: 'HKU\\*_Classes\exefile\shell\runas\command\isolatedCommand'
    condition: selection
tags:
    - attack.defense_evasion
    - attack.privilege_escalation
    - attack.t1088
    - car.2019-04-001
falsepositives:
    - unknown
level: high

```





### powershell
    
```
Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "13" -and $_.message -match "TargetObject.*HKU\\.*_Classes\\exefile\\shell\\runas\\command\\isolatedCommand") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.channel:"Microsoft\-Windows\-Sysmon\/Operational" AND winlog.event_id:"13" AND winlog.event_data.TargetObject.keyword:HKU\\*_Classes\\exefile\\shell\\runas\\command\\isolatedCommand)
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/5b872a46-3b90-45c1-8419-f675db8053aa <<EOF
{
  "metadata": {
    "title": "UAC Bypass via Sdclt",
    "description": "Detects changes to HKCU:\\Software\\Classes\\exefile\\shell\\runas\\command\\isolatedCommand",
    "tags": [
      "attack.defense_evasion",
      "attack.privilege_escalation",
      "attack.t1088",
      "car.2019-04-001"
    ],
    "query": "(winlog.channel:\"Microsoft\\-Windows\\-Sysmon\\/Operational\" AND winlog.event_id:\"13\" AND winlog.event_data.TargetObject.keyword:HKU\\\\*_Classes\\\\exefile\\\\shell\\\\runas\\\\command\\\\isolatedCommand)"
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
                    "query": "(winlog.channel:\"Microsoft\\-Windows\\-Sysmon\\/Operational\" AND winlog.event_id:\"13\" AND winlog.event_data.TargetObject.keyword:HKU\\\\*_Classes\\\\exefile\\\\shell\\\\runas\\\\command\\\\isolatedCommand)",
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
        "subject": "Sigma Rule 'UAC Bypass via Sdclt'",
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
(EventID:"13" AND TargetObject.keyword:HKU\\*_Classes\\exefile\\shell\\runas\\command\\isolatedCommand)
```


### splunk
    
```
(source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode="13" TargetObject="HKU\\*_Classes\\exefile\\shell\\runas\\command\\isolatedCommand")
```


### logpoint
    
```
(event_id="13" TargetObject="HKU\\*_Classes\\exefile\\shell\\runas\\command\\isolatedCommand")
```


### grep
    
```
grep -P '^(?:.*(?=.*13)(?=.*HKU\\.*_Classes\exefile\shell\runas\command\isolatedCommand))'
```



