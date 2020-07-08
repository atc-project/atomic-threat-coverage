| Title                    | Covenant Launcher Indicators       |
|:-------------------------|:------------------|
| **Description**          | Detects suspicious command lines used in Covenant luanchers |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1086: PowerShell](https://attack.mitre.org/techniques/T1086)</li></ul>  |
| **Data Needed**          | <ul><li>[DN0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN0003_1_windows_sysmon_process_creation](../Data_Needed/DN0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              |  There is no documented Trigger for this Detection Rule yet  |
| **Severity Level**       | high |
| **False Positives**      |  There are no documented False Positives for this Detection Rule yet  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://posts.specterops.io/covenant-v0-5-eee0507b85ba](https://posts.specterops.io/covenant-v0-5-eee0507b85ba)</li></ul>  |
| **Author**               | Florian Roth |
| Other Tags           | <ul><li>attack.t1059.001</li></ul> | 

## Detection Rules

### Sigma rule

```
title: Covenant Launcher Indicators
id: c260b6db-48ba-4b4a-a76f-2f67644e99d2
description: Detects suspicious command lines used in Covenant luanchers
status: experimental
references:
    - https://posts.specterops.io/covenant-v0-5-eee0507b85ba
author: Florian Roth
date: 2020/06/04
tags:
  - attack.execution
  - attack.t1086
  - attack.t1059.001
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains:
            - ' -Sta -Nop -Window Hidden -Command '
            - ' -Sta -Nop -Window Hidden -EncodedCommand '
            - 'sv o (New-Object IO.MemorySteam);sv d '
            - 'mshta file.hta'
            - 'GruntHTTP'
            - '-EncodedCommand cwB2ACAAbwAgA'
    condition: selection
level: high

```





### powershell
    
```
Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and ($_.message -match "CommandLine.*.* -Sta -Nop -Window Hidden -Command .*" -or $_.message -match "CommandLine.*.* -Sta -Nop -Window Hidden -EncodedCommand .*" -or $_.message -match "CommandLine.*.*sv o (New-Object IO.MemorySteam);sv d .*" -or $_.message -match "CommandLine.*.*mshta file.hta.*" -or $_.message -match "CommandLine.*.*GruntHTTP.*" -or $_.message -match "CommandLine.*.*-EncodedCommand cwB2ACAAbwAgA.*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
winlog.event_data.CommandLine.keyword:(*\ \-Sta\ \-Nop\ \-Window\ Hidden\ \-Command\ * OR *\ \-Sta\ \-Nop\ \-Window\ Hidden\ \-EncodedCommand\ * OR *sv\ o\ \(New\-Object\ IO.MemorySteam\);sv\ d\ * OR *mshta\ file.hta* OR *GruntHTTP* OR *\-EncodedCommand\ cwB2ACAAbwAgA*)
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/c260b6db-48ba-4b4a-a76f-2f67644e99d2 <<EOF
{
  "metadata": {
    "title": "Covenant Launcher Indicators",
    "description": "Detects suspicious command lines used in Covenant luanchers",
    "tags": [
      "attack.execution",
      "attack.t1086",
      "attack.t1059.001"
    ],
    "query": "winlog.event_data.CommandLine.keyword:(*\\ \\-Sta\\ \\-Nop\\ \\-Window\\ Hidden\\ \\-Command\\ * OR *\\ \\-Sta\\ \\-Nop\\ \\-Window\\ Hidden\\ \\-EncodedCommand\\ * OR *sv\\ o\\ \\(New\\-Object\\ IO.MemorySteam\\);sv\\ d\\ * OR *mshta\\ file.hta* OR *GruntHTTP* OR *\\-EncodedCommand\\ cwB2ACAAbwAgA*)"
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
                    "query": "winlog.event_data.CommandLine.keyword:(*\\ \\-Sta\\ \\-Nop\\ \\-Window\\ Hidden\\ \\-Command\\ * OR *\\ \\-Sta\\ \\-Nop\\ \\-Window\\ Hidden\\ \\-EncodedCommand\\ * OR *sv\\ o\\ \\(New\\-Object\\ IO.MemorySteam\\);sv\\ d\\ * OR *mshta\\ file.hta* OR *GruntHTTP* OR *\\-EncodedCommand\\ cwB2ACAAbwAgA*)",
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
        "subject": "Sigma Rule 'Covenant Launcher Indicators'",
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
CommandLine.keyword:(* \-Sta \-Nop \-Window Hidden \-Command * * \-Sta \-Nop \-Window Hidden \-EncodedCommand * *sv o \(New\-Object IO.MemorySteam\);sv d * *mshta file.hta* *GruntHTTP* *\-EncodedCommand cwB2ACAAbwAgA*)
```


### splunk
    
```
(CommandLine="* -Sta -Nop -Window Hidden -Command *" OR CommandLine="* -Sta -Nop -Window Hidden -EncodedCommand *" OR CommandLine="*sv o (New-Object IO.MemorySteam);sv d *" OR CommandLine="*mshta file.hta*" OR CommandLine="*GruntHTTP*" OR CommandLine="*-EncodedCommand cwB2ACAAbwAgA*")
```


### logpoint
    
```
(event_id="1" CommandLine IN ["* -Sta -Nop -Window Hidden -Command *", "* -Sta -Nop -Window Hidden -EncodedCommand *", "*sv o (New-Object IO.MemorySteam);sv d *", "*mshta file.hta*", "*GruntHTTP*", "*-EncodedCommand cwB2ACAAbwAgA*"])
```


### grep
    
```
grep -P '^(?:.*.* -Sta -Nop -Window Hidden -Command .*|.*.* -Sta -Nop -Window Hidden -EncodedCommand .*|.*.*sv o \(New-Object IO\.MemorySteam\);sv d .*|.*.*mshta file\.hta.*|.*.*GruntHTTP.*|.*.*-EncodedCommand cwB2ACAAbwAgA.*)'
```



