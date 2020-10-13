| Title                    | Windows Defender Download Activity       |
|:-------------------------|:------------------|
| **Description**          | Detect the use of Windows Defender to download payloads |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li><li>[TA0011: Command and Control](https://attack.mitre.org/tactics/TA0011)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1218.010: Regsvr32](https://attack.mitre.org/techniques/T1218/010)</li><li>[T1105: Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1218.010: Regsvr32](../Triggers/T1218.010.md)</li><li>[T1105: Ingress Tool Transfer](../Triggers/T1105.md)</li></ul>  |
| **Severity Level**       | high |
| **False Positives**      | <ul><li>Unknown</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://twitter.com/djmtshepana/status/1301608169496612866](https://twitter.com/djmtshepana/status/1301608169496612866)</li><li>[https://lolbas-project.github.io/lolbas/Binaries/MpCmdRun/](https://lolbas-project.github.io/lolbas/Binaries/MpCmdRun/)</li></ul>  |
| **Author**               | Matthew Matchen |


## Detection Rules

### Sigma rule

```
title: Windows Defender Download Activity
id: 46123129-1024-423e-9fae-43af4a0fa9a5
status: experimental
description: Detect the use of Windows Defender to download payloads 
author: Matthew Matchen
date: 2020/09/04
references:
    - https://twitter.com/djmtshepana/status/1301608169496612866
    - https://lolbas-project.github.io/lolbas/Binaries/MpCmdRun/
tags:
    - attack.defense_evasion
    - attack.t1218.010
    - attack.command_and_control
    - attack.t1105
logsource:
    category: process_creation
    product: windows
detection:
    selection1:
        - CommandLine|contains: 'MpCmdRun.exe'
        - Description: 'Microsoft Malware Protection Command Line Utility'
    selection2:
        CommandLine|contains|all: 
            - 'DownloadFile'
            - 'url'
    condition: selection1 and selection2
fields:
    - CommandLine
falsepositives:
    - Unknown
level: high

```





### powershell
    
```
Get-WinEvent | where {(($_.message -match "CommandLine.*.*MpCmdRun.exe.*" -or $_.message -match "Description.*Microsoft Malware Protection Command Line Utility") -and ($_.message -match "CommandLine.*.*DownloadFile.*" -and $_.message -match "CommandLine.*.*url.*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
((winlog.event_data.CommandLine.keyword:*MpCmdRun.exe* OR winlog.event_data.Description:"Microsoft\ Malware\ Protection\ Command\ Line\ Utility") AND (winlog.event_data.CommandLine.keyword:*DownloadFile* AND winlog.event_data.CommandLine.keyword:*url*))
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/46123129-1024-423e-9fae-43af4a0fa9a5 <<EOF
{
  "metadata": {
    "title": "Windows Defender Download Activity",
    "description": "Detect the use of Windows Defender to download payloads",
    "tags": [
      "attack.defense_evasion",
      "attack.t1218.010",
      "attack.command_and_control",
      "attack.t1105"
    ],
    "query": "((winlog.event_data.CommandLine.keyword:*MpCmdRun.exe* OR winlog.event_data.Description:\"Microsoft\\ Malware\\ Protection\\ Command\\ Line\\ Utility\") AND (winlog.event_data.CommandLine.keyword:*DownloadFile* AND winlog.event_data.CommandLine.keyword:*url*))"
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
                    "query": "((winlog.event_data.CommandLine.keyword:*MpCmdRun.exe* OR winlog.event_data.Description:\"Microsoft\\ Malware\\ Protection\\ Command\\ Line\\ Utility\") AND (winlog.event_data.CommandLine.keyword:*DownloadFile* AND winlog.event_data.CommandLine.keyword:*url*))",
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
        "subject": "Sigma Rule 'Windows Defender Download Activity'",
        "body": "Hits:\n{{#ctx.payload.hits.hits}}Hit on {{_source.@timestamp}}:\nCommandLine = {{_source.CommandLine}}================================================================================\n{{/ctx.payload.hits.hits}}",
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
((CommandLine.keyword:*MpCmdRun.exe* OR Description:"Microsoft Malware Protection Command Line Utility") AND (CommandLine.keyword:*DownloadFile* AND CommandLine.keyword:*url*))
```


### splunk
    
```
((CommandLine="*MpCmdRun.exe*" OR Description="Microsoft Malware Protection Command Line Utility") (CommandLine="*DownloadFile*" CommandLine="*url*")) | table CommandLine
```


### logpoint
    
```
((CommandLine="*MpCmdRun.exe*" OR Description="Microsoft Malware Protection Command Line Utility") (CommandLine="*DownloadFile*" CommandLine="*url*"))
```


### grep
    
```
grep -P '^(?:.*(?=.*(?:.*(?:.*.*MpCmdRun\.exe.*|.*Microsoft Malware Protection Command Line Utility)))(?=.*(?:.*(?=.*.*DownloadFile.*)(?=.*.*url.*))))'
```



