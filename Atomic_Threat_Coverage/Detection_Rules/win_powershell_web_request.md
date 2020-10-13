| Title                    | Windows PowerShell Web Request       |
|:-------------------------|:------------------|
| **Description**          | Detects the use of various web request methods (including aliases) via Windows PowerShell |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1059.001: PowerShell](https://attack.mitre.org/techniques/T1059/001)</li><li>[T1086: PowerShell](https://attack.mitre.org/techniques/T1086)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li><li>[DN_0036_4104_windows_powershell_script_block](../Data_Needed/DN_0036_4104_windows_powershell_script_block.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1059.001: PowerShell](../Triggers/T1059.001.md)</li></ul>  |
| **Severity Level**       | medium |
| **False Positives**      | <ul><li>Use of Get-Command and Get-Help modules to reference Invoke-WebRequest and Start-BitsTransfer.</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://4sysops.com/archives/use-powershell-to-download-a-file-with-http-https-and-ftp/](https://4sysops.com/archives/use-powershell-to-download-a-file-with-http-https-and-ftp/)</li><li>[https://blog.jourdant.me/post/3-ways-to-download-files-with-powershell](https://blog.jourdant.me/post/3-ways-to-download-files-with-powershell)</li></ul>  |
| **Author**               | James Pemberton / @4A616D6573 |


## Detection Rules

### Sigma rule

```
action: global
title: Windows PowerShell Web Request
id: 9fc51a3c-81b3-4fa7-b35f-7c02cf10fd2d
status: experimental
description: Detects the use of various web request methods (including aliases) via Windows PowerShell
references:
    - https://4sysops.com/archives/use-powershell-to-download-a-file-with-http-https-and-ftp/
    - https://blog.jourdant.me/post/3-ways-to-download-files-with-powershell
author: James Pemberton / @4A616D6573
date: 2019/10/24
modified: 2020/08/24
tags:
    - attack.execution
    - attack.t1059.001
    - attack.t1086  #an old one
detection:
    condition: selection
falsepositives:
    - Use of Get-Command and Get-Help modules to reference Invoke-WebRequest and Start-BitsTransfer.
level: medium
---
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains:
            - 'Invoke-WebRequest'
            - 'iwr '
            - 'wget '
            - 'curl '
            - 'Net.WebClient'
            - 'Start-BitsTransfer'
---
logsource:
    product: windows
    service: powershell
detection:
    selection:
        EventID: 4104
        ScriptBlockText|contains:
            - 'Invoke-WebRequest'
            - 'iwr '
            - 'wget '
            - 'curl '
            - 'Net.WebClient'
            - 'Start-BitsTransfer'

```





### powershell
    
```
Get-WinEvent | where {($_.message -match "CommandLine.*.*Invoke-WebRequest.*" -or $_.message -match "CommandLine.*.*iwr .*" -or $_.message -match "CommandLine.*.*wget .*" -or $_.message -match "CommandLine.*.*curl .*" -or $_.message -match "CommandLine.*.*Net.WebClient.*" -or $_.message -match "CommandLine.*.*Start-BitsTransfer.*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
Get-WinEvent -LogName Microsoft-Windows-PowerShell/Operational | where {($_.ID -eq "4104" -and ($_.message -match "ScriptBlockText.*.*Invoke-WebRequest.*" -or $_.message -match "ScriptBlockText.*.*iwr .*" -or $_.message -match "ScriptBlockText.*.*wget .*" -or $_.message -match "ScriptBlockText.*.*curl .*" -or $_.message -match "ScriptBlockText.*.*Net.WebClient.*" -or $_.message -match "ScriptBlockText.*.*Start-BitsTransfer.*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
winlog.event_data.CommandLine.keyword:(*Invoke\-WebRequest* OR *iwr\ * OR *wget\ * OR *curl\ * OR *Net.WebClient* OR *Start\-BitsTransfer*)
(winlog.event_id:"4104" AND ScriptBlockText.keyword:(*Invoke\-WebRequest* OR *iwr\ * OR *wget\ * OR *curl\ * OR *Net.WebClient* OR *Start\-BitsTransfer*))
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/9fc51a3c-81b3-4fa7-b35f-7c02cf10fd2d <<EOF
{
  "metadata": {
    "title": "Windows PowerShell Web Request",
    "description": "Detects the use of various web request methods (including aliases) via Windows PowerShell",
    "tags": [
      "attack.execution",
      "attack.t1059.001",
      "attack.t1086"
    ],
    "query": "winlog.event_data.CommandLine.keyword:(*Invoke\\-WebRequest* OR *iwr\\ * OR *wget\\ * OR *curl\\ * OR *Net.WebClient* OR *Start\\-BitsTransfer*)"
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
                    "query": "winlog.event_data.CommandLine.keyword:(*Invoke\\-WebRequest* OR *iwr\\ * OR *wget\\ * OR *curl\\ * OR *Net.WebClient* OR *Start\\-BitsTransfer*)",
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
        "subject": "Sigma Rule 'Windows PowerShell Web Request'",
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
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/9fc51a3c-81b3-4fa7-b35f-7c02cf10fd2d-2 <<EOF
{
  "metadata": {
    "title": "Windows PowerShell Web Request",
    "description": "Detects the use of various web request methods (including aliases) via Windows PowerShell",
    "tags": [
      "attack.execution",
      "attack.t1059.001",
      "attack.t1086"
    ],
    "query": "(winlog.event_id:\"4104\" AND ScriptBlockText.keyword:(*Invoke\\-WebRequest* OR *iwr\\ * OR *wget\\ * OR *curl\\ * OR *Net.WebClient* OR *Start\\-BitsTransfer*))"
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
                    "query": "(winlog.event_id:\"4104\" AND ScriptBlockText.keyword:(*Invoke\\-WebRequest* OR *iwr\\ * OR *wget\\ * OR *curl\\ * OR *Net.WebClient* OR *Start\\-BitsTransfer*))",
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
        "subject": "Sigma Rule 'Windows PowerShell Web Request'",
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
CommandLine.keyword:(*Invoke\-WebRequest* *iwr * *wget * *curl * *Net.WebClient* *Start\-BitsTransfer*)
(EventID:"4104" AND ScriptBlockText.keyword:(*Invoke\-WebRequest* *iwr * *wget * *curl * *Net.WebClient* *Start\-BitsTransfer*))
```


### splunk
    
```
(CommandLine="*Invoke-WebRequest*" OR CommandLine="*iwr *" OR CommandLine="*wget *" OR CommandLine="*curl *" OR CommandLine="*Net.WebClient*" OR CommandLine="*Start-BitsTransfer*")
(source="WinEventLog:Microsoft-Windows-PowerShell/Operational" EventCode="4104" (ScriptBlockText="*Invoke-WebRequest*" OR ScriptBlockText="*iwr *" OR ScriptBlockText="*wget *" OR ScriptBlockText="*curl *" OR ScriptBlockText="*Net.WebClient*" OR ScriptBlockText="*Start-BitsTransfer*"))
```


### logpoint
    
```
CommandLine IN ["*Invoke-WebRequest*", "*iwr *", "*wget *", "*curl *", "*Net.WebClient*", "*Start-BitsTransfer*"]
(event_id="4104" ScriptBlockText IN ["*Invoke-WebRequest*", "*iwr *", "*wget *", "*curl *", "*Net.WebClient*", "*Start-BitsTransfer*"])
```


### grep
    
```
grep -P '^(?:.*.*Invoke-WebRequest.*|.*.*iwr .*|.*.*wget .*|.*.*curl .*|.*.*Net\.WebClient.*|.*.*Start-BitsTransfer.*)'
grep -P '^(?:.*(?=.*4104)(?=.*(?:.*.*Invoke-WebRequest.*|.*.*iwr .*|.*.*wget .*|.*.*curl .*|.*.*Net\.WebClient.*|.*.*Start-BitsTransfer.*)))'
```



