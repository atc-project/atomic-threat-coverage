| Title                    | LSASS Memory Dump File Creation       |
|:-------------------------|:------------------|
| **Description**          | LSASS memory dump creation using operating systems utilities. Procdump will use process name in output file if no name is specified |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0006: Credential Access](https://attack.mitre.org/tactics/TA0006)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1003: OS Credential Dumping](https://attack.mitre.org/techniques/T1003)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0015_11_windows_sysmon_FileCreate](../Data_Needed/DN_0015_11_windows_sysmon_FileCreate.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1003: OS Credential Dumping](../Triggers/T1003.md)</li></ul>  |
| **Severity Level**       | medium |
| **False Positives**      | <ul><li>Dumping lsass memory for forensic investigation purposes by legitimate incident responder or forensic invetigator</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://www.slideshare.net/heirhabarov/hunting-for-credentials-dumping-in-windows-environment](https://www.slideshare.net/heirhabarov/hunting-for-credentials-dumping-in-windows-environment)</li></ul>  |
| **Author**               | Teymur Kheirkhabarov, oscd.community |


## Detection Rules

### Sigma rule

```
title: LSASS Memory Dump File Creation
id: 5e3d3601-0662-4af0-b1d2-36a05e90c40a
description: LSASS memory dump creation using operating systems utilities. Procdump will use process name in output file if no name is specified
author: Teymur Kheirkhabarov, oscd.community
references:
    - https://www.slideshare.net/heirhabarov/hunting-for-credentials-dumping-in-windows-environment
date: 2019/10/22
modified: 2019/11/13
tags:
    - attack.credential_access
    - attack.t1003
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        EventID: 11
        TargetFilename|contains: 'lsass'
        TargetFilename|endswith: 'dmp'
    condition: selection
fields:
    - ComputerName
    - TargetFileName
falsepositives:
    - Dumping lsass memory for forensic investigation purposes by legitimate incident responder or forensic invetigator
level: medium
status: experimental

```





### powershell
    
```
Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "11" -and $_.message -match "TargetFilename.*.*lsass.*" -and $_.message -match "TargetFilename.*.*dmp") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.channel:"Microsoft\-Windows\-Sysmon\/Operational" AND winlog.event_id:"11" AND winlog.event_data.TargetFilename.keyword:*lsass* AND winlog.event_data.TargetFilename.keyword:*dmp)
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/5e3d3601-0662-4af0-b1d2-36a05e90c40a <<EOF
{
  "metadata": {
    "title": "LSASS Memory Dump File Creation",
    "description": "LSASS memory dump creation using operating systems utilities. Procdump will use process name in output file if no name is specified",
    "tags": [
      "attack.credential_access",
      "attack.t1003"
    ],
    "query": "(winlog.channel:\"Microsoft\\-Windows\\-Sysmon\\/Operational\" AND winlog.event_id:\"11\" AND winlog.event_data.TargetFilename.keyword:*lsass* AND winlog.event_data.TargetFilename.keyword:*dmp)"
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
                    "query": "(winlog.channel:\"Microsoft\\-Windows\\-Sysmon\\/Operational\" AND winlog.event_id:\"11\" AND winlog.event_data.TargetFilename.keyword:*lsass* AND winlog.event_data.TargetFilename.keyword:*dmp)",
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
        "subject": "Sigma Rule 'LSASS Memory Dump File Creation'",
        "body": "Hits:\n{{#ctx.payload.hits.hits}}Hit on {{_source.@timestamp}}:\n  ComputerName = {{_source.ComputerName}}\nTargetFileName = {{_source.TargetFileName}}================================================================================\n{{/ctx.payload.hits.hits}}",
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
(EventID:"11" AND TargetFilename.keyword:*lsass* AND TargetFilename.keyword:*dmp)
```


### splunk
    
```
(source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode="11" TargetFilename="*lsass*" TargetFilename="*dmp") | table ComputerName,TargetFileName
```


### logpoint
    
```
(event_id="11" TargetFilename="*lsass*" TargetFilename="*dmp")
```


### grep
    
```
grep -P '^(?:.*(?=.*11)(?=.*.*lsass.*)(?=.*.*dmp))'
```



