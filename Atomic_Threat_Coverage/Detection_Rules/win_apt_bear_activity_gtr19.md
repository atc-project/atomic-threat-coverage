| Title                    | Judgement Panda Credential Access Activity       |
|:-------------------------|:------------------|
| **Description**          | Detects Russian group activity as described in Global Threat Report 2019 by Crowdstrike |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0006: Credential Access](https://attack.mitre.org/tactics/TA0006)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1081: Credentials in Files](https://attack.mitre.org/techniques/T1081)</li><li>[T1003: OS Credential Dumping](https://attack.mitre.org/techniques/T1003)</li></ul>  |
| **Data Needed**          | <ul><li>[DN0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN0003_1_windows_sysmon_process_creation](../Data_Needed/DN0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1003: OS Credential Dumping](../Triggers/T1003.md)</li></ul>  |
| **Severity Level**       | critical |
| **False Positives**      | <ul><li>unknown</li></ul>  |
| **Development Status**   |  Development Status wasn't defined for this Detection Rule yet  |
| **References**           | <ul><li>[https://www.crowdstrike.com/resources/reports/2019-crowdstrike-global-threat-report/](https://www.crowdstrike.com/resources/reports/2019-crowdstrike-global-threat-report/)</li></ul>  |
| **Author**               | Florian Roth |
| Other Tags           | <ul><li>attack.t1552.001</li></ul> | 

## Detection Rules

### Sigma rule

```
title: Judgement Panda Credential Access Activity
id: b83f5166-9237-4b5e-9cd4-7b5d52f4d8ee
description: Detects Russian group activity as described in Global Threat Report 2019 by Crowdstrike
references:
    - https://www.crowdstrike.com/resources/reports/2019-crowdstrike-global-threat-report/
author: Florian Roth
date: 2019/02/21
tags:
    - attack.credential_access
    - attack.t1081
    - attack.t1003
    - attack.t1552.001
logsource:
    category: process_creation
    product: windows
detection:
    selection1:
        Image: '*\xcopy.exe'
        CommandLine: '* /S /E /C /Q /H \\*'
    selection2:
        Image: '*\adexplorer.exe'
        CommandLine: '* -snapshot "" c:\users\\*'
    condition: selection1 or selection2
falsepositives:
    - unknown
level: critical

```





### powershell
    
```
Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "1") -and (($_.message -match "Image.*.*\\xcopy.exe" -and $_.message -match "CommandLine.*.* /S /E /C /Q /H \\.*") -or ($_.message -match "Image.*.*\\adexplorer.exe" -and $_.message -match "CommandLine.*.* -snapshot \"\" c:\\users\\.*"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
((winlog.event_data.Image.keyword:*\\xcopy.exe AND winlog.event_data.CommandLine.keyword:*\ \/S\ \/E\ \/C\ \/Q\ \/H\ \\*) OR (winlog.event_data.Image.keyword:*\\adexplorer.exe AND winlog.event_data.CommandLine.keyword:*\ \-snapshot\ \"\"\ c\:\\users\\*))
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/b83f5166-9237-4b5e-9cd4-7b5d52f4d8ee <<EOF
{
  "metadata": {
    "title": "Judgement Panda Credential Access Activity",
    "description": "Detects Russian group activity as described in Global Threat Report 2019 by Crowdstrike",
    "tags": [
      "attack.credential_access",
      "attack.t1081",
      "attack.t1003",
      "attack.t1552.001"
    ],
    "query": "((winlog.event_data.Image.keyword:*\\\\xcopy.exe AND winlog.event_data.CommandLine.keyword:*\\ \\/S\\ \\/E\\ \\/C\\ \\/Q\\ \\/H\\ \\\\*) OR (winlog.event_data.Image.keyword:*\\\\adexplorer.exe AND winlog.event_data.CommandLine.keyword:*\\ \\-snapshot\\ \\\"\\\"\\ c\\:\\\\users\\\\*))"
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
                    "query": "((winlog.event_data.Image.keyword:*\\\\xcopy.exe AND winlog.event_data.CommandLine.keyword:*\\ \\/S\\ \\/E\\ \\/C\\ \\/Q\\ \\/H\\ \\\\*) OR (winlog.event_data.Image.keyword:*\\\\adexplorer.exe AND winlog.event_data.CommandLine.keyword:*\\ \\-snapshot\\ \\\"\\\"\\ c\\:\\\\users\\\\*))",
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
        "subject": "Sigma Rule 'Judgement Panda Credential Access Activity'",
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
((Image.keyword:*\\xcopy.exe AND CommandLine.keyword:* \/S \/E \/C \/Q \/H \\*) OR (Image.keyword:*\\adexplorer.exe AND CommandLine.keyword:* \-snapshot \"\" c\:\\users\\*))
```


### splunk
    
```
((Image="*\\xcopy.exe" CommandLine="* /S /E /C /Q /H \\*") OR (Image="*\\adexplorer.exe" CommandLine="* -snapshot \"\" c:\\users\\*"))
```


### logpoint
    
```
(event_id="1" ((Image="*\\xcopy.exe" CommandLine="* /S /E /C /Q /H \\*") OR (Image="*\\adexplorer.exe" CommandLine="* -snapshot \"\" c:\\users\\*")))
```


### grep
    
```
grep -P '^(?:.*(?:.*(?:.*(?=.*.*\xcopy\.exe)(?=.*.* /S /E /C /Q /H \\.*))|.*(?:.*(?=.*.*\adexplorer\.exe)(?=.*.* -snapshot "" c:\users\\.*))))'
```



