| Title                    | Suspicious PowerShell Invocations - Specific       |
|:-------------------------|:------------------|
| **Description**          | Detects suspicious PowerShell invocation command parameters |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1086: PowerShell](https://attack.mitre.org/techniques/T1086)</li></ul>  |
| **Data Needed**          |  There is no documented Data Needed for this Detection Rule yet  |
| **Trigger**              |  There is no documented Trigger for this Detection Rule yet  |
| **Severity Level**       | high |
| **False Positives**      | <ul><li>Penetration tests</li></ul>  |
| **Development Status**   | experimental |
| **References**           |  There are no documented References for this Detection Rule yet  |
| **Author**               | Florian Roth (rule) |
| Other Tags           | <ul><li>attack.t1059.001</li></ul> | 

## Detection Rules

### Sigma rule

```
title: Suspicious PowerShell Invocations - Specific
id: fce5f582-cc00-41e1-941a-c6fabf0fdb8c
status: experimental
description: Detects suspicious PowerShell invocation command parameters
tags:
    - attack.execution
    - attack.t1086
    - attack.t1059.001
author: Florian Roth (rule)
date: 2017/03/05
logsource:
    product: windows
    service: powershell
detection:
    keywords:
        Message:
            - '* -nop -w hidden -c * [Convert]::FromBase64String*'
            - '* -w hidden -noni -nop -c "iex(New-Object*'
            - '* -w hidden -ep bypass -Enc*'
            - '*powershell.exe reg add HKCU\software\microsoft\windows\currentversion\run*'
            - '*bypass -noprofile -windowstyle hidden (new-object system.net.webclient).download*'
            - '*iex(New-Object Net.WebClient).Download*'
    condition: keywords
falsepositives:
    - Penetration tests
level: high

```





### powershell
    
```
Get-WinEvent -LogName Microsoft-Windows-PowerShell/Operational | where {(($_.message -match "Message.*.* -nop -w hidden -c .* [Convert]::FromBase64String.*" -or $_.message -match "Message.*.* -w hidden -noni -nop -c \"iex(New-Object.*" -or $_.message -match "Message.*.* -w hidden -ep bypass -Enc.*" -or $_.message -match "Message.*.*powershell.exe reg add HKCU\\software\\microsoft\\windows\\currentversion\\run.*" -or $_.message -match "Message.*.*bypass -noprofile -windowstyle hidden (new-object system.net.webclient).download.*" -or $_.message -match "Message.*.*iex(New-Object Net.WebClient).Download.*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
Message.keyword:(*\ \-nop\ \-w\ hidden\ \-c\ *\ \[Convert\]\:\:FromBase64String* OR *\ \-w\ hidden\ \-noni\ \-nop\ \-c\ \"iex\(New\-Object* OR *\ \-w\ hidden\ \-ep\ bypass\ \-Enc* OR *powershell.exe\ reg\ add\ HKCU\\software\\microsoft\\windows\\currentversion\\run* OR *bypass\ \-noprofile\ \-windowstyle\ hidden\ \(new\-object\ system.net.webclient\).download* OR *iex\(New\-Object\ Net.WebClient\).Download*)
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/fce5f582-cc00-41e1-941a-c6fabf0fdb8c <<EOF
{
  "metadata": {
    "title": "Suspicious PowerShell Invocations - Specific",
    "description": "Detects suspicious PowerShell invocation command parameters",
    "tags": [
      "attack.execution",
      "attack.t1086",
      "attack.t1059.001"
    ],
    "query": "Message.keyword:(*\\ \\-nop\\ \\-w\\ hidden\\ \\-c\\ *\\ \\[Convert\\]\\:\\:FromBase64String* OR *\\ \\-w\\ hidden\\ \\-noni\\ \\-nop\\ \\-c\\ \\\"iex\\(New\\-Object* OR *\\ \\-w\\ hidden\\ \\-ep\\ bypass\\ \\-Enc* OR *powershell.exe\\ reg\\ add\\ HKCU\\\\software\\\\microsoft\\\\windows\\\\currentversion\\\\run* OR *bypass\\ \\-noprofile\\ \\-windowstyle\\ hidden\\ \\(new\\-object\\ system.net.webclient\\).download* OR *iex\\(New\\-Object\\ Net.WebClient\\).Download*)"
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
                    "query": "Message.keyword:(*\\ \\-nop\\ \\-w\\ hidden\\ \\-c\\ *\\ \\[Convert\\]\\:\\:FromBase64String* OR *\\ \\-w\\ hidden\\ \\-noni\\ \\-nop\\ \\-c\\ \\\"iex\\(New\\-Object* OR *\\ \\-w\\ hidden\\ \\-ep\\ bypass\\ \\-Enc* OR *powershell.exe\\ reg\\ add\\ HKCU\\\\software\\\\microsoft\\\\windows\\\\currentversion\\\\run* OR *bypass\\ \\-noprofile\\ \\-windowstyle\\ hidden\\ \\(new\\-object\\ system.net.webclient\\).download* OR *iex\\(New\\-Object\\ Net.WebClient\\).Download*)",
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
        "subject": "Sigma Rule 'Suspicious PowerShell Invocations - Specific'",
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
Message.keyword:(* \-nop \-w hidden \-c * \[Convert\]\:\:FromBase64String* * \-w hidden \-noni \-nop \-c \"iex\(New\-Object* * \-w hidden \-ep bypass \-Enc* *powershell.exe reg add HKCU\\software\\microsoft\\windows\\currentversion\\run* *bypass \-noprofile \-windowstyle hidden \(new\-object system.net.webclient\).download* *iex\(New\-Object Net.WebClient\).Download*)
```


### splunk
    
```
(source="WinEventLog:Microsoft-Windows-PowerShell/Operational" (Message="* -nop -w hidden -c * [Convert]::FromBase64String*" OR Message="* -w hidden -noni -nop -c \"iex(New-Object*" OR Message="* -w hidden -ep bypass -Enc*" OR Message="*powershell.exe reg add HKCU\\software\\microsoft\\windows\\currentversion\\run*" OR Message="*bypass -noprofile -windowstyle hidden (new-object system.net.webclient).download*" OR Message="*iex(New-Object Net.WebClient).Download*"))
```


### logpoint
    
```
Message IN ["* -nop -w hidden -c * [Convert]::FromBase64String*", "* -w hidden -noni -nop -c \"iex(New-Object*", "* -w hidden -ep bypass -Enc*", "*powershell.exe reg add HKCU\\software\\microsoft\\windows\\currentversion\\run*", "*bypass -noprofile -windowstyle hidden (new-object system.net.webclient).download*", "*iex(New-Object Net.WebClient).Download*"]
```


### grep
    
```
grep -P '^(?:.*.* -nop -w hidden -c .* \[Convert\]::FromBase64String.*|.*.* -w hidden -noni -nop -c "iex\(New-Object.*|.*.* -w hidden -ep bypass -Enc.*|.*.*powershell\.exe reg add HKCU\software\microsoft\windows\currentversion\run.*|.*.*bypass -noprofile -windowstyle hidden \(new-object system\.net\.webclient\)\.download.*|.*.*iex\(New-Object Net\.WebClient\)\.Download.*)'
```



