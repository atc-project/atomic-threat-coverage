| Title                    | Suspicious PowerShell Keywords       |
|:-------------------------|:------------------|
| **Description**          | Detects keywords that could indicate the use of some PowerShell exploitation framework |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1059.001: PowerShell](https://attack.mitre.org/techniques/T1059/001)</li><li>[T1086: PowerShell](https://attack.mitre.org/techniques/T1086)</li></ul>  |
| **Data Needed**          |  There is no documented Data Needed for this Detection Rule yet  |
| **Trigger**              | <ul><li>[T1059.001: PowerShell](../Triggers/T1059.001.md)</li></ul>  |
| **Severity Level**       | high |
| **False Positives**      | <ul><li>Penetration tests</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://posts.specterops.io/entering-a-covenant-net-command-and-control-e11038bcf462](https://posts.specterops.io/entering-a-covenant-net-command-and-control-e11038bcf462)</li><li>[https://github.com/PowerShellMafia/PowerSploit/blob/master/CodeExecution/Invoke-ReflectivePEInjection.ps1](https://github.com/PowerShellMafia/PowerSploit/blob/master/CodeExecution/Invoke-ReflectivePEInjection.ps1)</li><li>[https://github.com/hlldz/Invoke-Phant0m/blob/master/Invoke-Phant0m.ps1](https://github.com/hlldz/Invoke-Phant0m/blob/master/Invoke-Phant0m.ps1)</li></ul>  |
| **Author**               | Florian Roth, Perez Diego (@darkquassar) |


## Detection Rules

### Sigma rule

```
title: Suspicious PowerShell Keywords
id: 1f49f2ab-26bc-48b3-96cc-dcffbc93eadf
status: experimental
description: Detects keywords that could indicate the use of some PowerShell exploitation framework
date: 2019/02/11
author: Florian Roth, Perez Diego (@darkquassar)
references:
    - https://posts.specterops.io/entering-a-covenant-net-command-and-control-e11038bcf462
    - https://github.com/PowerShellMafia/PowerSploit/blob/master/CodeExecution/Invoke-ReflectivePEInjection.ps1
    - https://github.com/hlldz/Invoke-Phant0m/blob/master/Invoke-Phant0m.ps1
tags:
    - attack.execution
    - attack.t1059.001
    - attack.t1086  #an old one
logsource:
    product: windows
    service: powershell
    definition: 'It is recommended to use the new "Script Block Logging" of PowerShell v5 https://adsecurity.org/?p=2277. Monitor for EventID 4104'
detection:
    keywords:
        Message:
            - "System.Reflection.Assembly.Load"
            - "[System.Reflection.Assembly]::Load"
            - "[Reflection.Assembly]::Load"
            - "System.Reflection.AssemblyName"
            - "Reflection.Emit.AssemblyBuilderAccess"
            - "Runtime.InteropServices.DllImportAttribute"
            - "SuspendThread"
    condition: keywords
falsepositives:
    - Penetration tests
level: high

```





### powershell
    
```
Get-WinEvent -LogName Microsoft-Windows-PowerShell/Operational | where {(($_.message -match "System.Reflection.Assembly.Load" -or $_.message -match "[System.Reflection.Assembly]::Load" -or $_.message -match "[Reflection.Assembly]::Load" -or $_.message -match "System.Reflection.AssemblyName" -or $_.message -match "Reflection.Emit.AssemblyBuilderAccess" -or $_.message -match "Runtime.InteropServices.DllImportAttribute" -or $_.message -match "SuspendThread")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
Message:("System.Reflection.Assembly.Load" OR "\[System.Reflection.Assembly\]\:\:Load" OR "\[Reflection.Assembly\]\:\:Load" OR "System.Reflection.AssemblyName" OR "Reflection.Emit.AssemblyBuilderAccess" OR "Runtime.InteropServices.DllImportAttribute" OR "SuspendThread")
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/1f49f2ab-26bc-48b3-96cc-dcffbc93eadf <<EOF
{
  "metadata": {
    "title": "Suspicious PowerShell Keywords",
    "description": "Detects keywords that could indicate the use of some PowerShell exploitation framework",
    "tags": [
      "attack.execution",
      "attack.t1059.001",
      "attack.t1086"
    ],
    "query": "Message:(\"System.Reflection.Assembly.Load\" OR \"\\[System.Reflection.Assembly\\]\\:\\:Load\" OR \"\\[Reflection.Assembly\\]\\:\\:Load\" OR \"System.Reflection.AssemblyName\" OR \"Reflection.Emit.AssemblyBuilderAccess\" OR \"Runtime.InteropServices.DllImportAttribute\" OR \"SuspendThread\")"
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
                    "query": "Message:(\"System.Reflection.Assembly.Load\" OR \"\\[System.Reflection.Assembly\\]\\:\\:Load\" OR \"\\[Reflection.Assembly\\]\\:\\:Load\" OR \"System.Reflection.AssemblyName\" OR \"Reflection.Emit.AssemblyBuilderAccess\" OR \"Runtime.InteropServices.DllImportAttribute\" OR \"SuspendThread\")",
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
        "subject": "Sigma Rule 'Suspicious PowerShell Keywords'",
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
Message:("System.Reflection.Assembly.Load" "\[System.Reflection.Assembly\]\:\:Load" "\[Reflection.Assembly\]\:\:Load" "System.Reflection.AssemblyName" "Reflection.Emit.AssemblyBuilderAccess" "Runtime.InteropServices.DllImportAttribute" "SuspendThread")
```


### splunk
    
```
(source="WinEventLog:Microsoft-Windows-PowerShell/Operational" (Message="System.Reflection.Assembly.Load" OR Message="[System.Reflection.Assembly]::Load" OR Message="[Reflection.Assembly]::Load" OR Message="System.Reflection.AssemblyName" OR Message="Reflection.Emit.AssemblyBuilderAccess" OR Message="Runtime.InteropServices.DllImportAttribute" OR Message="SuspendThread"))
```


### logpoint
    
```
Message IN ["System.Reflection.Assembly.Load", "[System.Reflection.Assembly]::Load", "[Reflection.Assembly]::Load", "System.Reflection.AssemblyName", "Reflection.Emit.AssemblyBuilderAccess", "Runtime.InteropServices.DllImportAttribute", "SuspendThread"]
```


### grep
    
```
grep -P '^(?:.*System\.Reflection\.Assembly\.Load|.*\[System\.Reflection\.Assembly\]::Load|.*\[Reflection\.Assembly\]::Load|.*System\.Reflection\.AssemblyName|.*Reflection\.Emit\.AssemblyBuilderAccess|.*Runtime\.InteropServices\.DllImportAttribute|.*SuspendThread)'
```



