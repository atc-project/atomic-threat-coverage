| Title                    | WSF/JSE/JS/VBA/VBE File Execution       |
|:-------------------------|:------------------|
| **Description**          | Detects suspicious file execution by wscript and cscript |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1059.005: Visual Basic](https://attack.mitre.org/techniques/T1059/005)</li><li>[T1059.007: JavaScript/JScript](https://attack.mitre.org/techniques/T1059/007)</li><li>[T1064: Scripting](https://attack.mitre.org/techniques/T1064)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1059.005: Visual Basic](../Triggers/T1059.005.md)</li></ul>  |
| **Severity Level**       | medium |
| **False Positives**      | <ul><li>Will need to be tuned. I recommend adding the user profile path in CommandLine if it is getting too noisy.</li></ul>  |
| **Development Status**   | experimental |
| **References**           |  There are no documented References for this Detection Rule yet  |
| **Author**               | Michael Haag |


## Detection Rules

### Sigma rule

```
title: WSF/JSE/JS/VBA/VBE File Execution
id: 1e33157c-53b1-41ad-bbcc-780b80b58288
status: experimental
description: Detects suspicious file execution by wscript and cscript
author: Michael Haag
date: 2019/01/16
modified: 2020/08/28
tags:
    - attack.execution
    - attack.t1059.005
    - attack.t1059.007
    - attack.t1064      # an old one     
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith:
            - '\wscript.exe'
            - '\cscript.exe'
        CommandLine|contains:
            - '.jse'
            - '.vbe'
            - '.js'
            - '.vba'
    condition: selection
fields:
    - CommandLine
    - ParentCommandLine
falsepositives:
    - Will need to be tuned. I recommend adding the user profile path in CommandLine if it is getting too noisy.
level: medium

```





### powershell
    
```
Get-WinEvent | where {(($_.message -match "Image.*.*\\wscript.exe" -or $_.message -match "Image.*.*\\cscript.exe") -and ($_.message -match "CommandLine.*.*.jse.*" -or $_.message -match "CommandLine.*.*.vbe.*" -or $_.message -match "CommandLine.*.*.js.*" -or $_.message -match "CommandLine.*.*.vba.*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.event_data.Image.keyword:(*\\wscript.exe OR *\\cscript.exe) AND winlog.event_data.CommandLine.keyword:(*.jse* OR *.vbe* OR *.js* OR *.vba*))
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/1e33157c-53b1-41ad-bbcc-780b80b58288 <<EOF
{
  "metadata": {
    "title": "WSF/JSE/JS/VBA/VBE File Execution",
    "description": "Detects suspicious file execution by wscript and cscript",
    "tags": [
      "attack.execution",
      "attack.t1059.005",
      "attack.t1059.007",
      "attack.t1064"
    ],
    "query": "(winlog.event_data.Image.keyword:(*\\\\wscript.exe OR *\\\\cscript.exe) AND winlog.event_data.CommandLine.keyword:(*.jse* OR *.vbe* OR *.js* OR *.vba*))"
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
                    "query": "(winlog.event_data.Image.keyword:(*\\\\wscript.exe OR *\\\\cscript.exe) AND winlog.event_data.CommandLine.keyword:(*.jse* OR *.vbe* OR *.js* OR *.vba*))",
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
        "subject": "Sigma Rule 'WSF/JSE/JS/VBA/VBE File Execution'",
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
(Image.keyword:(*\\wscript.exe *\\cscript.exe) AND CommandLine.keyword:(*.jse* *.vbe* *.js* *.vba*))
```


### splunk
    
```
((Image="*\\wscript.exe" OR Image="*\\cscript.exe") (CommandLine="*.jse*" OR CommandLine="*.vbe*" OR CommandLine="*.js*" OR CommandLine="*.vba*")) | table CommandLine,ParentCommandLine
```


### logpoint
    
```
(Image IN ["*\\wscript.exe", "*\\cscript.exe"] CommandLine IN ["*.jse*", "*.vbe*", "*.js*", "*.vba*"])
```


### grep
    
```
grep -P '^(?:.*(?=.*(?:.*.*\wscript\.exe|.*.*\cscript\.exe))(?=.*(?:.*.*\.jse.*|.*.*\.vbe.*|.*.*\.js.*|.*.*\.vba.*)))'
```



