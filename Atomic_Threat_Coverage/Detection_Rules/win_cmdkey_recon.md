| Title                    | Cmdkey Cached Credentials Recon       |
|:-------------------------|:------------------|
| **Description**          | Detects usage of cmdkey to look for cached credentials |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0006: Credential Access](https://attack.mitre.org/tactics/TA0006)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1003: OS Credential Dumping](https://attack.mitre.org/techniques/T1003)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1003: OS Credential Dumping](../Triggers/T1003.md)</li></ul>  |
| **Severity Level**       | low |
| **False Positives**      | <ul><li>Legitimate administrative tasks.</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://www.peew.pw/blog/2017/11/26/exploring-cmdkey-an-edge-case-for-privilege-escalation](https://www.peew.pw/blog/2017/11/26/exploring-cmdkey-an-edge-case-for-privilege-escalation)</li><li>[https://technet.microsoft.com/en-us/library/cc754243(v=ws.11).aspx](https://technet.microsoft.com/en-us/library/cc754243(v=ws.11).aspx)</li></ul>  |
| **Author**               | jmallette |


## Detection Rules

### Sigma rule

```
title: Cmdkey Cached Credentials Recon
id: 07f8bdc2-c9b3-472a-9817-5a670b872f53
status: experimental
description: Detects usage of cmdkey to look for cached credentials
references:
    - https://www.peew.pw/blog/2017/11/26/exploring-cmdkey-an-edge-case-for-privilege-escalation
    - https://technet.microsoft.com/en-us/library/cc754243(v=ws.11).aspx
author: jmallette
date: 2019/01/16
tags:
    - attack.credential_access
    - attack.t1003
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image: '*\cmdkey.exe'
        CommandLine: '* /list *'
    condition: selection
fields:
    - CommandLine
    - ParentCommandLine
    - User
falsepositives:
    - Legitimate administrative tasks.
level: low

```





### powershell
    
```
Get-WinEvent | where {($_.message -match "Image.*.*\\cmdkey.exe" -and $_.message -match "CommandLine.*.* /list .*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.event_data.Image.keyword:*\\cmdkey.exe AND winlog.event_data.CommandLine.keyword:*\ \/list\ *)
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/07f8bdc2-c9b3-472a-9817-5a670b872f53 <<EOF
{
  "metadata": {
    "title": "Cmdkey Cached Credentials Recon",
    "description": "Detects usage of cmdkey to look for cached credentials",
    "tags": [
      "attack.credential_access",
      "attack.t1003"
    ],
    "query": "(winlog.event_data.Image.keyword:*\\\\cmdkey.exe AND winlog.event_data.CommandLine.keyword:*\\ \\/list\\ *)"
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
                    "query": "(winlog.event_data.Image.keyword:*\\\\cmdkey.exe AND winlog.event_data.CommandLine.keyword:*\\ \\/list\\ *)",
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
      "email": {
        "to": "root@localhost",
        "subject": "Sigma Rule 'Cmdkey Cached Credentials Recon'",
        "body": "Hits:\n{{#ctx.payload.hits.hits}}Hit on {{_source.@timestamp}}:\n      CommandLine = {{_source.CommandLine}}\nParentCommandLine = {{_source.ParentCommandLine}}\n             User = {{_source.User}}================================================================================\n{{/ctx.payload.hits.hits}}",
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
(Image.keyword:*\\cmdkey.exe AND CommandLine.keyword:* \/list *)
```


### splunk
    
```
(Image="*\\cmdkey.exe" CommandLine="* /list *") | table CommandLine,ParentCommandLine,User
```


### logpoint
    
```
(Image="*\\cmdkey.exe" CommandLine="* /list *")
```


### grep
    
```
grep -P '^(?:.*(?=.*.*\cmdkey\.exe)(?=.*.* /list .*))'
```



