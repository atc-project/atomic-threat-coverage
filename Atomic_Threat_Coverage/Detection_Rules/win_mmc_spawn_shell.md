| Title                    | MMC Spawning Windows Shell       |
|:-------------------------|:------------------|
| **Description**          | Detects a Windows command line executable started from MMC. |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0008: Lateral Movement](https://attack.mitre.org/tactics/TA0008)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1175: Component Object Model and Distributed COM](https://attack.mitre.org/techniques/T1175)</li></ul>  |
| **Data Needed**          | <ul><li>[DN0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN0003_1_windows_sysmon_process_creation](../Data_Needed/DN0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              |  There is no documented Trigger for this Detection Rule yet  |
| **Severity Level**       | high |
| **False Positives**      |  There are no documented False Positives for this Detection Rule yet  |
| **Development Status**   | experimental |
| **References**           |  There are no documented References for this Detection Rule yet  |
| **Author**               | Karneades, Swisscom CSIRT |
| Other Tags           | <ul><li>attack.t1059.004</li><li>attack.t1059.005</li><li>attack.t1059.003</li><li>attack.t1059.001</li></ul> | 

## Detection Rules

### Sigma rule

```
title: MMC Spawning Windows Shell
id: 05a2ab7e-ce11-4b63-86db-ab32e763e11d
status: experimental
description: Detects a Windows command line executable started from MMC.
author: Karneades, Swisscom CSIRT
date: 2019/08/05
tags:
    - attack.lateral_movement
    - attack.t1175
    - attack.t1059.004
    - attack.t1059.005
    - attack.t1059.003
    - attack.t1059.001
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage: '*\mmc.exe'
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
    - Image
    - ParentCommandLine
level: high

```





### powershell
    
```
Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and $_.message -match "ParentImage.*.*\\mmc.exe" -and ($_.message -match "Image.*.*\\cmd.exe" -or $_.message -match "Image.*.*\\powershell.exe" -or $_.message -match "Image.*.*\\wscript.exe" -or $_.message -match "Image.*.*\\cscript.exe" -or $_.message -match "Image.*.*\\sh.exe" -or $_.message -match "Image.*.*\\bash.exe" -or $_.message -match "Image.*.*\\reg.exe" -or $_.message -match "Image.*.*\\regsvr32.exe" -or $_.message -match "Image.*.*\\BITSADMIN.*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.event_data.ParentImage.keyword:*\\mmc.exe AND winlog.event_data.Image.keyword:(*\\cmd.exe OR *\\powershell.exe OR *\\wscript.exe OR *\\cscript.exe OR *\\sh.exe OR *\\bash.exe OR *\\reg.exe OR *\\regsvr32.exe OR *\\BITSADMIN*))
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/05a2ab7e-ce11-4b63-86db-ab32e763e11d <<EOF
{
  "metadata": {
    "title": "MMC Spawning Windows Shell",
    "description": "Detects a Windows command line executable started from MMC.",
    "tags": [
      "attack.lateral_movement",
      "attack.t1175",
      "attack.t1059.004",
      "attack.t1059.005",
      "attack.t1059.003",
      "attack.t1059.001"
    ],
    "query": "(winlog.event_data.ParentImage.keyword:*\\\\mmc.exe AND winlog.event_data.Image.keyword:(*\\\\cmd.exe OR *\\\\powershell.exe OR *\\\\wscript.exe OR *\\\\cscript.exe OR *\\\\sh.exe OR *\\\\bash.exe OR *\\\\reg.exe OR *\\\\regsvr32.exe OR *\\\\BITSADMIN*))"
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
                    "query": "(winlog.event_data.ParentImage.keyword:*\\\\mmc.exe AND winlog.event_data.Image.keyword:(*\\\\cmd.exe OR *\\\\powershell.exe OR *\\\\wscript.exe OR *\\\\cscript.exe OR *\\\\sh.exe OR *\\\\bash.exe OR *\\\\reg.exe OR *\\\\regsvr32.exe OR *\\\\BITSADMIN*))",
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
        "subject": "Sigma Rule 'MMC Spawning Windows Shell'",
        "body": "Hits:\n{{#ctx.payload.hits.hits}}Hit on {{_source.@timestamp}}:\n      CommandLine = {{_source.CommandLine}}\n            Image = {{_source.Image}}\nParentCommandLine = {{_source.ParentCommandLine}}================================================================================\n{{/ctx.payload.hits.hits}}",
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
(ParentImage.keyword:*\\mmc.exe AND Image.keyword:(*\\cmd.exe *\\powershell.exe *\\wscript.exe *\\cscript.exe *\\sh.exe *\\bash.exe *\\reg.exe *\\regsvr32.exe *\\BITSADMIN*))
```


### splunk
    
```
(ParentImage="*\\mmc.exe" (Image="*\\cmd.exe" OR Image="*\\powershell.exe" OR Image="*\\wscript.exe" OR Image="*\\cscript.exe" OR Image="*\\sh.exe" OR Image="*\\bash.exe" OR Image="*\\reg.exe" OR Image="*\\regsvr32.exe" OR Image="*\\BITSADMIN*")) | table CommandLine,Image,ParentCommandLine
```


### logpoint
    
```
(event_id="1" ParentImage="*\\mmc.exe" Image IN ["*\\cmd.exe", "*\\powershell.exe", "*\\wscript.exe", "*\\cscript.exe", "*\\sh.exe", "*\\bash.exe", "*\\reg.exe", "*\\regsvr32.exe", "*\\BITSADMIN*"])
```


### grep
    
```
grep -P '^(?:.*(?=.*.*\mmc\.exe)(?=.*(?:.*.*\cmd\.exe|.*.*\powershell\.exe|.*.*\wscript\.exe|.*.*\cscript\.exe|.*.*\sh\.exe|.*.*\bash\.exe|.*.*\reg\.exe|.*.*\regsvr32\.exe|.*.*\BITSADMIN.*)))'
```



