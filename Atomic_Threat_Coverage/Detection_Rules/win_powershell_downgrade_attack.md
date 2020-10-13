| Title                    | PowerShell Downgrade Attack       |
|:-------------------------|:------------------|
| **Description**          | Detects PowerShell downgrade attack by comparing the host versions with the actually used engine version 2.0 |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1086: PowerShell](https://attack.mitre.org/techniques/T1086)</li><li>[T1059.001: PowerShell](https://attack.mitre.org/techniques/T1059/001)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1059.001: PowerShell](../Triggers/T1059.001.md)</li></ul>  |
| **Severity Level**       | medium |
| **False Positives**      | <ul><li>Penetration Test</li><li>Unknown</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[http://www.leeholmes.com/blog/2017/03/17/detecting-and-preventing-powershell-downgrade-attacks/](http://www.leeholmes.com/blog/2017/03/17/detecting-and-preventing-powershell-downgrade-attacks/)</li></ul>  |
| **Author**               | Harish Segar (rule) |


## Detection Rules

### Sigma rule

```
title: PowerShell Downgrade Attack
id: b3512211-c67e-4707-bedc-66efc7848863
related:
    - id: 6331d09b-4785-4c13-980f-f96661356249
      type: derived
status: experimental
description: Detects PowerShell downgrade attack by comparing the host versions with the actually used engine version 2.0
references:
    - http://www.leeholmes.com/blog/2017/03/17/detecting-and-preventing-powershell-downgrade-attacks/
tags:
    - attack.defense_evasion
    - attack.execution
    - attack.t1086          # an old one
    - attack.t1059.001
author: Harish Segar (rule)
date: 2020/03/20
falsepositives:
    - Penetration Test
    - Unknown
level: medium
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains:
            - ' -version 2 '
            - ' -versio 2 '
            - ' -versi 2 '
            - ' -vers 2 '
            - ' -ver 2 '
            - ' -ve 2 '
        Image|endswith: '\powershell.exe'
    condition: selection

```





### powershell
    
```
Get-WinEvent | where {(($_.message -match "CommandLine.*.* -version 2 .*" -or $_.message -match "CommandLine.*.* -versio 2 .*" -or $_.message -match "CommandLine.*.* -versi 2 .*" -or $_.message -match "CommandLine.*.* -vers 2 .*" -or $_.message -match "CommandLine.*.* -ver 2 .*" -or $_.message -match "CommandLine.*.* -ve 2 .*") -and $_.message -match "Image.*.*\\powershell.exe") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.event_data.CommandLine.keyword:(*\ \-version\ 2\ * OR *\ \-versio\ 2\ * OR *\ \-versi\ 2\ * OR *\ \-vers\ 2\ * OR *\ \-ver\ 2\ * OR *\ \-ve\ 2\ *) AND winlog.event_data.Image.keyword:*\\powershell.exe)
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/b3512211-c67e-4707-bedc-66efc7848863 <<EOF
{
  "metadata": {
    "title": "PowerShell Downgrade Attack",
    "description": "Detects PowerShell downgrade attack by comparing the host versions with the actually used engine version 2.0",
    "tags": [
      "attack.defense_evasion",
      "attack.execution",
      "attack.t1086",
      "attack.t1059.001"
    ],
    "query": "(winlog.event_data.CommandLine.keyword:(*\\ \\-version\\ 2\\ * OR *\\ \\-versio\\ 2\\ * OR *\\ \\-versi\\ 2\\ * OR *\\ \\-vers\\ 2\\ * OR *\\ \\-ver\\ 2\\ * OR *\\ \\-ve\\ 2\\ *) AND winlog.event_data.Image.keyword:*\\\\powershell.exe)"
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
                    "query": "(winlog.event_data.CommandLine.keyword:(*\\ \\-version\\ 2\\ * OR *\\ \\-versio\\ 2\\ * OR *\\ \\-versi\\ 2\\ * OR *\\ \\-vers\\ 2\\ * OR *\\ \\-ver\\ 2\\ * OR *\\ \\-ve\\ 2\\ *) AND winlog.event_data.Image.keyword:*\\\\powershell.exe)",
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
        "subject": "Sigma Rule 'PowerShell Downgrade Attack'",
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
(CommandLine.keyword:(* \-version 2 * * \-versio 2 * * \-versi 2 * * \-vers 2 * * \-ver 2 * * \-ve 2 *) AND Image.keyword:*\\powershell.exe)
```


### splunk
    
```
((CommandLine="* -version 2 *" OR CommandLine="* -versio 2 *" OR CommandLine="* -versi 2 *" OR CommandLine="* -vers 2 *" OR CommandLine="* -ver 2 *" OR CommandLine="* -ve 2 *") Image="*\\powershell.exe")
```


### logpoint
    
```
(CommandLine IN ["* -version 2 *", "* -versio 2 *", "* -versi 2 *", "* -vers 2 *", "* -ver 2 *", "* -ve 2 *"] Image="*\\powershell.exe")
```


### grep
    
```
grep -P '^(?:.*(?=.*(?:.*.* -version 2 .*|.*.* -versio 2 .*|.*.* -versi 2 .*|.*.* -vers 2 .*|.*.* -ver 2 .*|.*.* -ve 2 .*))(?=.*.*\powershell\.exe))'
```



