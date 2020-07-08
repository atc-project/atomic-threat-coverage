| Title                    | Suspicious PowerShell Invocations - Generic       |
|:-------------------------|:------------------|
| **Description**          | Detects suspicious PowerShell invocation command parameters |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1086: PowerShell](https://attack.mitre.org/techniques/T1086)</li></ul>  |
| **Data Needed**          | <ul><li>[DN0036_4104_windows_powershell_script_block](../Data_Needed/DN0036_4104_windows_powershell_script_block.md)</li><li>[DN0037_4103_windows_powershell_executing_pipeline](../Data_Needed/DN0037_4103_windows_powershell_executing_pipeline.md)</li></ul>  |
| **Trigger**              |  There is no documented Trigger for this Detection Rule yet  |
| **Severity Level**       | high |
| **False Positives**      | <ul><li>Penetration tests</li><li>Very special / sneaky PowerShell scripts</li></ul>  |
| **Development Status**   | experimental |
| **References**           |  There are no documented References for this Detection Rule yet  |
| **Author**               | Florian Roth (rule) |
| Other Tags           | <ul><li>attack.t1059.001</li></ul> | 

## Detection Rules

### Sigma rule

```
title: Suspicious PowerShell Invocations - Generic
id: 3d304fda-78aa-43ed-975c-d740798a49c1
status: experimental
description: Detects suspicious PowerShell invocation command parameters
tags:
    - attack.execution
    - attack.t1086
    - attack.t1059.001
author: Florian Roth (rule)
date: 2017/03/12
logsource:
    product: windows
    service: powershell
detection:
    encoded:
        - ' -enc '
        - ' -EncodedCommand '
    hidden:
        - ' -w hidden '
        - ' -window hidden '
        - ' -windowstyle hidden '
    noninteractive:
        - ' -noni '
        - ' -noninteractive '
    condition: all of them
falsepositives:
    - Penetration tests
    - Very special / sneaky PowerShell scripts
level: high

```





### powershell
    
```
Get-WinEvent -LogName Microsoft-Windows-PowerShell/Operational | where {(($_.message -match " -enc " -or $_.message -match " -EncodedCommand ") -and ($_.message -match " -w hidden " -or $_.message -match " -window hidden " -or $_.message -match " -windowstyle hidden ") -and ($_.message -match " -noni " -or $_.message -match " -noninteractive ")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(\*.keyword:(*\ \-enc\ * OR *\ \-EncodedCommand\ *) AND \*.keyword:(*\ \-w\ hidden\ * OR *\ \-window\ hidden\ * OR *\ \-windowstyle\ hidden\ *) AND \*.keyword:(*\ \-noni\ * OR *\ \-noninteractive\ *))
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/3d304fda-78aa-43ed-975c-d740798a49c1 <<EOF
{
  "metadata": {
    "title": "Suspicious PowerShell Invocations - Generic",
    "description": "Detects suspicious PowerShell invocation command parameters",
    "tags": [
      "attack.execution",
      "attack.t1086",
      "attack.t1059.001"
    ],
    "query": "(\\*.keyword:(*\\ \\-enc\\ * OR *\\ \\-EncodedCommand\\ *) AND \\*.keyword:(*\\ \\-w\\ hidden\\ * OR *\\ \\-window\\ hidden\\ * OR *\\ \\-windowstyle\\ hidden\\ *) AND \\*.keyword:(*\\ \\-noni\\ * OR *\\ \\-noninteractive\\ *))"
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
                    "query": "(\\*.keyword:(*\\ \\-enc\\ * OR *\\ \\-EncodedCommand\\ *) AND \\*.keyword:(*\\ \\-w\\ hidden\\ * OR *\\ \\-window\\ hidden\\ * OR *\\ \\-windowstyle\\ hidden\\ *) AND \\*.keyword:(*\\ \\-noni\\ * OR *\\ \\-noninteractive\\ *))",
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
        "subject": "Sigma Rule 'Suspicious PowerShell Invocations - Generic'",
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
(\*.keyword:(* \-enc * OR * \-EncodedCommand *) AND \*.keyword:(* \-w hidden * OR * \-window hidden * OR * \-windowstyle hidden *) AND \*.keyword:(* \-noni * OR * \-noninteractive *))
```


### splunk
    
```
(source="WinEventLog:Microsoft-Windows-PowerShell/Operational" (" -enc " OR " -EncodedCommand ") (" -w hidden " OR " -window hidden " OR " -windowstyle hidden ") (" -noni " OR " -noninteractive "))
```


### logpoint
    
```
((" -enc " OR " -EncodedCommand ") (" -w hidden " OR " -window hidden " OR " -windowstyle hidden ") (" -noni " OR " -noninteractive "))
```


### grep
    
```
grep -P '^(?:.*(?=.*(?:.*(?:.* -enc |.* -EncodedCommand )))(?=.*(?:.*(?:.* -w hidden |.* -window hidden |.* -windowstyle hidden )))(?=.*(?:.*(?:.* -noni |.* -noninteractive ))))'
```



