| Title                    | MSHTA Spawning Windows Shell       |
|:-------------------------|:------------------|
| **Description**          | Detects a Windows command line executable started from MSHTA. |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1170: Mshta](https://attack.mitre.org/techniques/T1170)</li><li>[T1218: Signed Binary Proxy Execution](https://attack.mitre.org/techniques/T1218)</li></ul>  |
| **Data Needed**          | <ul><li>[DN0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN0003_1_windows_sysmon_process_creation](../Data_Needed/DN0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1218: Signed Binary Proxy Execution](../Triggers/T1218.md)</li></ul>  |
| **Severity Level**       | high |
| **False Positives**      | <ul><li>Printer software / driver installations</li><li>HP software</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://www.trustedsec.com/july-2015/malicious-htas/](https://www.trustedsec.com/july-2015/malicious-htas/)</li></ul>  |
| **Author**               | Michael Haag |
| Other Tags           | <ul><li>car.2013-02-003</li><li>car.2013-03-001</li><li>car.2014-04-003</li></ul> | 

## Detection Rules

### Sigma rule

```
title: MSHTA Spawning Windows Shell
id: 03cc0c25-389f-4bf8-b48d-11878079f1ca
status: experimental
description: Detects a Windows command line executable started from MSHTA.
references:
    - https://www.trustedsec.com/july-2015/malicious-htas/
author: Michael Haag
date: 2019/01/16
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage: '*\mshta.exe'
        Image:
            - '*\cmd.exe'
            - '*\powershell.exe'
            - '*\wscript.exe'
            - '*\cscript.exe'
            - '*\sh.exe'
            - '*\bash.exe'
            - '*\reg.exe'
            - '*\regsvr32.exe'
            - '*\BITSADMIN*'
    condition: selection
fields:
    - CommandLine
    - ParentCommandLine
tags:
    - attack.defense_evasion
    - attack.execution
    - attack.t1170
    - car.2013-02-003
    - car.2013-03-001
    - car.2014-04-003
    - attack.t1218
falsepositives:
    - Printer software / driver installations
    - HP software
level: high

```





### powershell
    
```
Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and $_.message -match "ParentImage.*.*\\mshta.exe" -and ($_.message -match "Image.*.*\\cmd.exe" -or $_.message -match "Image.*.*\\powershell.exe" -or $_.message -match "Image.*.*\\wscript.exe" -or $_.message -match "Image.*.*\\cscript.exe" -or $_.message -match "Image.*.*\\sh.exe" -or $_.message -match "Image.*.*\\bash.exe" -or $_.message -match "Image.*.*\\reg.exe" -or $_.message -match "Image.*.*\\regsvr32.exe" -or $_.message -match "Image.*.*\\BITSADMIN.*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.event_data.ParentImage.keyword:*\\mshta.exe AND winlog.event_data.Image.keyword:(*\\cmd.exe OR *\\powershell.exe OR *\\wscript.exe OR *\\cscript.exe OR *\\sh.exe OR *\\bash.exe OR *\\reg.exe OR *\\regsvr32.exe OR *\\BITSADMIN*))
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/03cc0c25-389f-4bf8-b48d-11878079f1ca <<EOF
{
  "metadata": {
    "title": "MSHTA Spawning Windows Shell",
    "description": "Detects a Windows command line executable started from MSHTA.",
    "tags": [
      "attack.defense_evasion",
      "attack.execution",
      "attack.t1170",
      "car.2013-02-003",
      "car.2013-03-001",
      "car.2014-04-003",
      "attack.t1218"
    ],
    "query": "(winlog.event_data.ParentImage.keyword:*\\\\mshta.exe AND winlog.event_data.Image.keyword:(*\\\\cmd.exe OR *\\\\powershell.exe OR *\\\\wscript.exe OR *\\\\cscript.exe OR *\\\\sh.exe OR *\\\\bash.exe OR *\\\\reg.exe OR *\\\\regsvr32.exe OR *\\\\BITSADMIN*))"
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
                    "query": "(winlog.event_data.ParentImage.keyword:*\\\\mshta.exe AND winlog.event_data.Image.keyword:(*\\\\cmd.exe OR *\\\\powershell.exe OR *\\\\wscript.exe OR *\\\\cscript.exe OR *\\\\sh.exe OR *\\\\bash.exe OR *\\\\reg.exe OR *\\\\regsvr32.exe OR *\\\\BITSADMIN*))",
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
        "subject": "Sigma Rule 'MSHTA Spawning Windows Shell'",
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
(ParentImage.keyword:*\\mshta.exe AND Image.keyword:(*\\cmd.exe *\\powershell.exe *\\wscript.exe *\\cscript.exe *\\sh.exe *\\bash.exe *\\reg.exe *\\regsvr32.exe *\\BITSADMIN*))
```


### splunk
    
```
(ParentImage="*\\mshta.exe" (Image="*\\cmd.exe" OR Image="*\\powershell.exe" OR Image="*\\wscript.exe" OR Image="*\\cscript.exe" OR Image="*\\sh.exe" OR Image="*\\bash.exe" OR Image="*\\reg.exe" OR Image="*\\regsvr32.exe" OR Image="*\\BITSADMIN*")) | table CommandLine,ParentCommandLine
```


### logpoint
    
```
(event_id="1" ParentImage="*\\mshta.exe" Image IN ["*\\cmd.exe", "*\\powershell.exe", "*\\wscript.exe", "*\\cscript.exe", "*\\sh.exe", "*\\bash.exe", "*\\reg.exe", "*\\regsvr32.exe", "*\\BITSADMIN*"])
```


### grep
    
```
grep -P '^(?:.*(?=.*.*\mshta\.exe)(?=.*(?:.*.*\cmd\.exe|.*.*\powershell\.exe|.*.*\wscript\.exe|.*.*\cscript\.exe|.*.*\sh\.exe|.*.*\bash\.exe|.*.*\reg\.exe|.*.*\regsvr32\.exe|.*.*\BITSADMIN.*)))'
```



