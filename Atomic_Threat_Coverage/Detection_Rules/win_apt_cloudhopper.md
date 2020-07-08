| Title                    | WMIExec VBS Script       |
|:-------------------------|:------------------|
| **Description**          | Detects suspicious file execution by wscript and cscript |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1064: Scripting](https://attack.mitre.org/techniques/T1064)</li></ul>  |
| **Data Needed**          | <ul><li>[DN0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN0003_1_windows_sysmon_process_creation](../Data_Needed/DN0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              |  There is no documented Trigger for this Detection Rule yet  |
| **Severity Level**       | critical |
| **False Positives**      | <ul><li>Unlikely</li></ul>  |
| **Development Status**   |  Development Status wasn't defined for this Detection Rule yet  |
| **References**           | <ul><li>[https://www.pwc.co.uk/cyber-security/pdf/cloud-hopper-annex-b-final.pdf](https://www.pwc.co.uk/cyber-security/pdf/cloud-hopper-annex-b-final.pdf)</li></ul>  |
| **Author**               | Florian Roth |
| Other Tags           | <ul><li>attack.g0045</li><li>attack.t1059.005</li></ul> | 

## Detection Rules

### Sigma rule

```
title: WMIExec VBS Script
id: 966e4016-627f-44f7-8341-f394905c361f
description: Detects suspicious file execution by wscript and cscript
author: Florian Roth
date: 2017/04/07
references:
    - https://www.pwc.co.uk/cyber-security/pdf/cloud-hopper-annex-b-final.pdf
tags:
    - attack.execution
    - attack.g0045
    - attack.t1064
    - attack.t1059.005
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image: '*\cscript.exe'
        CommandLine: '*.vbs /shell *'
    condition: selection
fields:
    - CommandLine
    - ParentCommandLine
falsepositives:
    - Unlikely
level: critical

```





### powershell
    
```
Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and $_.message -match "Image.*.*\\cscript.exe" -and $_.message -match "CommandLine.*.*.vbs /shell .*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.event_data.Image.keyword:*\\cscript.exe AND winlog.event_data.CommandLine.keyword:*.vbs\ \/shell\ *)
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/966e4016-627f-44f7-8341-f394905c361f <<EOF
{
  "metadata": {
    "title": "WMIExec VBS Script",
    "description": "Detects suspicious file execution by wscript and cscript",
    "tags": [
      "attack.execution",
      "attack.g0045",
      "attack.t1064",
      "attack.t1059.005"
    ],
    "query": "(winlog.event_data.Image.keyword:*\\\\cscript.exe AND winlog.event_data.CommandLine.keyword:*.vbs\\ \\/shell\\ *)"
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
                    "query": "(winlog.event_data.Image.keyword:*\\\\cscript.exe AND winlog.event_data.CommandLine.keyword:*.vbs\\ \\/shell\\ *)",
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
        "subject": "Sigma Rule 'WMIExec VBS Script'",
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
(Image.keyword:*\\cscript.exe AND CommandLine.keyword:*.vbs \/shell *)
```


### splunk
    
```
(Image="*\\cscript.exe" CommandLine="*.vbs /shell *") | table CommandLine,ParentCommandLine
```


### logpoint
    
```
(event_id="1" Image="*\\cscript.exe" CommandLine="*.vbs /shell *")
```


### grep
    
```
grep -P '^(?:.*(?=.*.*\cscript\.exe)(?=.*.*\.vbs /shell .*))'
```



