| Title                    | UAC Bypass via Event Viewer       |
|:-------------------------|:------------------|
| **Description**          | Detects UAC bypass method using Windows event viewer |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li><li>[TA0004: Privilege Escalation](https://attack.mitre.org/tactics/TA0004)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1088: Bypass User Account Control](https://attack.mitre.org/techniques/T1088)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li><li>[DN_0017_13_windows_sysmon_RegistryEvent](../Data_Needed/DN_0017_13_windows_sysmon_RegistryEvent.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1088: Bypass User Account Control](../Triggers/T1088.md)</li></ul>  |
| **Severity Level**       | critical |
| **False Positives**      | <ul><li>unknown</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://enigma0x3.net/2016/08/15/fileless-uac-bypass-using-eventvwr-exe-and-registry-hijacking/](https://enigma0x3.net/2016/08/15/fileless-uac-bypass-using-eventvwr-exe-and-registry-hijacking/)</li><li>[https://www.hybrid-analysis.com/sample/e122bc8bf291f15cab182a5d2d27b8db1e7019e4e96bb5cdbd1dfe7446f3f51f?environmentId=100](https://www.hybrid-analysis.com/sample/e122bc8bf291f15cab182a5d2d27b8db1e7019e4e96bb5cdbd1dfe7446f3f51f?environmentId=100)</li></ul>  |
| **Author**               | Florian Roth |
| Other Tags           | <ul><li>car.2019-04-001</li></ul> | 

## Detection Rules

### Sigma rule

```
title: UAC Bypass via Event Viewer
id: 7c81fec3-1c1d-43b0-996a-46753041b1b6
status: experimental
description: Detects UAC bypass method using Windows event viewer
references:
    - https://enigma0x3.net/2016/08/15/fileless-uac-bypass-using-eventvwr-exe-and-registry-hijacking/
    - https://www.hybrid-analysis.com/sample/e122bc8bf291f15cab182a5d2d27b8db1e7019e4e96bb5cdbd1dfe7446f3f51f?environmentId=100
author: Florian Roth
date: 2017/03/19
logsource:
    product: windows
    service: sysmon
detection:
    methregistry:
        EventID: 13
        TargetObject: 'HKU\\*\mscfile\shell\open\command'
    methprocess:
        EventID: 1 # Migration to process_creation requires multipart YAML
        ParentImage: '*\eventvwr.exe'
    filterprocess:
        Image: '*\mmc.exe'
    condition: methregistry or ( methprocess and not filterprocess )
fields:
    - CommandLine
    - ParentCommandLine
tags:
    - attack.defense_evasion
    - attack.privilege_escalation
    - attack.t1088
    - car.2019-04-001
falsepositives:
    - unknown
level: critical

```





### powershell
    
```
Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {((($_.ID -eq "13" -and $_.message -match "TargetObject.*HKU\\.*\\mscfile\\shell\\open\\command") -or (($_.ID -eq "1" -and $_.message -match "ParentImage.*.*\\eventvwr.exe") -and  -not ($_.message -match "Image.*.*\\mmc.exe")))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.channel:"Microsoft\-Windows\-Sysmon\/Operational" AND ((winlog.event_id:"13" AND winlog.event_data.TargetObject.keyword:HKU\\*\\mscfile\\shell\\open\\command) OR (winlog.channel:"Microsoft\-Windows\-Sysmon\/Operational" AND (winlog.event_id:"1" AND winlog.event_data.ParentImage.keyword:*\\eventvwr.exe) AND (NOT (winlog.event_data.Image.keyword:*\\mmc.exe)))))
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/7c81fec3-1c1d-43b0-996a-46753041b1b6 <<EOF
{
  "metadata": {
    "title": "UAC Bypass via Event Viewer",
    "description": "Detects UAC bypass method using Windows event viewer",
    "tags": [
      "attack.defense_evasion",
      "attack.privilege_escalation",
      "attack.t1088",
      "car.2019-04-001"
    ],
    "query": "(winlog.channel:\"Microsoft\\-Windows\\-Sysmon\\/Operational\" AND ((winlog.event_id:\"13\" AND winlog.event_data.TargetObject.keyword:HKU\\\\*\\\\mscfile\\\\shell\\\\open\\\\command) OR (winlog.channel:\"Microsoft\\-Windows\\-Sysmon\\/Operational\" AND (winlog.event_id:\"1\" AND winlog.event_data.ParentImage.keyword:*\\\\eventvwr.exe) AND (NOT (winlog.event_data.Image.keyword:*\\\\mmc.exe)))))"
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
                    "query": "(winlog.channel:\"Microsoft\\-Windows\\-Sysmon\\/Operational\" AND ((winlog.event_id:\"13\" AND winlog.event_data.TargetObject.keyword:HKU\\\\*\\\\mscfile\\\\shell\\\\open\\\\command) OR (winlog.channel:\"Microsoft\\-Windows\\-Sysmon\\/Operational\" AND (winlog.event_id:\"1\" AND winlog.event_data.ParentImage.keyword:*\\\\eventvwr.exe) AND (NOT (winlog.event_data.Image.keyword:*\\\\mmc.exe)))))",
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
        "subject": "Sigma Rule 'UAC Bypass via Event Viewer'",
        "body": "Hits:\n{{#ctx.payload.hits.hits}}Hit on {{_source.@timestamp}}:\n      CommandLine = {{_source.CommandLine}}\nParentCommandLine = {{_source.ParentCommandLine}}================================================================================\n{{/ctx.payload.hits.hits}}",
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
((EventID:"13" AND TargetObject.keyword:HKU\\*\\mscfile\\shell\\open\\command) OR ((EventID:"1" AND ParentImage.keyword:*\\eventvwr.exe) AND (NOT (Image.keyword:*\\mmc.exe))))
```


### splunk
    
```
(source="WinEventLog:Microsoft-Windows-Sysmon/Operational" ((EventCode="13" TargetObject="HKU\\*\\mscfile\\shell\\open\\command") OR (source="WinEventLog:Microsoft-Windows-Sysmon/Operational" (EventCode="1" ParentImage="*\\eventvwr.exe") NOT (Image="*\\mmc.exe")))) | table CommandLine,ParentCommandLine
```


### logpoint
    
```
((event_id="13" TargetObject="HKU\\*\\mscfile\\shell\\open\\command") OR ((event_id="1" ParentImage="*\\eventvwr.exe")  -(Image="*\\mmc.exe")))
```


### grep
    
```
grep -P '^(?:.*(?:.*(?:.*(?=.*13)(?=.*HKU\\.*\mscfile\shell\open\command))|.*(?:.*(?=.*(?:.*(?=.*1)(?=.*.*\eventvwr\.exe)))(?=.*(?!.*(?:.*(?=.*.*\mmc\.exe)))))))'
```



