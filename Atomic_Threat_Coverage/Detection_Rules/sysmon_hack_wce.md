| Title                    | Windows Credential Editor       |
|:-------------------------|:------------------|
| **Description**          | Detects the use of Windows Credential Editor (WCE) |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0006: Credential Access](https://attack.mitre.org/tactics/TA0006)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1003: OS Credential Dumping](https://attack.mitre.org/techniques/T1003)</li><li>[T1003.001: LSASS Memory](https://attack.mitre.org/techniques/T1003/001)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1003: OS Credential Dumping](../Triggers/T1003.md)</li><li>[T1003.001: LSASS Memory](../Triggers/T1003.001.md)</li></ul>  |
| **Severity Level**       | critical |
| **False Positives**      | <ul><li>Another service that uses a single -s command line switch</li></ul>  |
| **Development Status**   |  Development Status wasn't defined for this Detection Rule yet  |
| **References**           | <ul><li>[https://www.ampliasecurity.com/research/windows-credentials-editor/](https://www.ampliasecurity.com/research/windows-credentials-editor/)</li></ul>  |
| **Author**               | Florian Roth |
| Other Tags           | <ul><li>attack.s0005</li></ul> | 

## Detection Rules

### Sigma rule

```
title: Windows Credential Editor
id: 7aa7009a-28b9-4344-8c1f-159489a390df
description: Detects the use of Windows Credential Editor (WCE)
author: Florian Roth
references:
    - https://www.ampliasecurity.com/research/windows-credentials-editor/
date: 2019/12/31
modified: 2020/08/26
tags:
    - attack.credential_access
    - attack.t1003 # an old one
    - attack.t1003.001
    - attack.s0005
logsource:
    category: process_creation
    product: windows
detection:
    selection1:
        Imphash: 
          - a53a02b997935fd8eedcb5f7abab9b9f
          - e96a73c7bf33a464c510ede582318bf2
    selection2:
        CommandLine|endswith: '.exe -S'
        ParentImage|endswith: '\services.exe'
    condition: 1 of them
falsepositives:
    - 'Another service that uses a single -s command line switch'
level: critical
```





### powershell
    
```
Get-WinEvent | where {(($_.message -match "a53a02b997935fd8eedcb5f7abab9b9f" -or $_.message -match "e96a73c7bf33a464c510ede582318bf2") -or ($_.message -match "CommandLine.*.*.exe -S" -and $_.message -match "ParentImage.*.*\\services.exe")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.event_data.Imphash:("a53a02b997935fd8eedcb5f7abab9b9f" OR "A53A02B997935FD8EEDCB5F7ABAB9B9F" OR "e96a73c7bf33a464c510ede582318bf2" OR "E96A73C7BF33A464C510EDE582318BF2") OR (winlog.event_data.CommandLine.keyword:*.exe\ \-S AND winlog.event_data.ParentImage.keyword:*\\services.exe))
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/7aa7009a-28b9-4344-8c1f-159489a390df <<EOF
{
  "metadata": {
    "title": "Windows Credential Editor",
    "description": "Detects the use of Windows Credential Editor (WCE)",
    "tags": [
      "attack.credential_access",
      "attack.t1003",
      "attack.t1003.001",
      "attack.s0005"
    ],
    "query": "(winlog.event_data.Imphash:(\"a53a02b997935fd8eedcb5f7abab9b9f\" OR \"A53A02B997935FD8EEDCB5F7ABAB9B9F\" OR \"e96a73c7bf33a464c510ede582318bf2\" OR \"E96A73C7BF33A464C510EDE582318BF2\") OR (winlog.event_data.CommandLine.keyword:*.exe\\ \\-S AND winlog.event_data.ParentImage.keyword:*\\\\services.exe))"
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
                    "query": "(winlog.event_data.Imphash:(\"a53a02b997935fd8eedcb5f7abab9b9f\" OR \"A53A02B997935FD8EEDCB5F7ABAB9B9F\" OR \"e96a73c7bf33a464c510ede582318bf2\" OR \"E96A73C7BF33A464C510EDE582318BF2\") OR (winlog.event_data.CommandLine.keyword:*.exe\\ \\-S AND winlog.event_data.ParentImage.keyword:*\\\\services.exe))",
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
        "subject": "Sigma Rule 'Windows Credential Editor'",
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
(Imphash:("a53a02b997935fd8eedcb5f7abab9b9f" "A53A02B997935FD8EEDCB5F7ABAB9B9F" "e96a73c7bf33a464c510ede582318bf2" "E96A73C7BF33A464C510EDE582318BF2") OR (CommandLine.keyword:*.exe \-S AND ParentImage.keyword:*\\services.exe))
```


### splunk
    
```
((Imphash="a53a02b997935fd8eedcb5f7abab9b9f" OR Imphash="e96a73c7bf33a464c510ede582318bf2") OR (CommandLine="*.exe -S" ParentImage="*\\services.exe"))
```


### logpoint
    
```
(Imphash IN ["a53a02b997935fd8eedcb5f7abab9b9f", "e96a73c7bf33a464c510ede582318bf2"] OR (CommandLine="*.exe -S" ParentImage="*\\services.exe"))
```


### grep
    
```
grep -P '^(?:.*(?:.*(?:.*a53a02b997935fd8eedcb5f7abab9b9f|.*e96a73c7bf33a464c510ede582318bf2)|.*(?:.*(?=.*.*\.exe -S)(?=.*.*\services\.exe))))'
```



