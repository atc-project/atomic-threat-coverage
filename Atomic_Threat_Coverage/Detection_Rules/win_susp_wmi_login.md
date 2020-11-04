| Title                    | Login with WMI       |
|:-------------------------|:------------------|
| **Description**          | Detection of logins performed with WMI |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1047: Windows Management Instrumentation](https://attack.mitre.org/techniques/T1047)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0004_4624_windows_account_logon](../Data_Needed/DN_0004_4624_windows_account_logon.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1047: Windows Management Instrumentation](../Triggers/T1047.md)</li></ul>  |
| **Severity Level**       | low |
| **False Positives**      | <ul><li>Monitoring tools</li><li>Legitimate system administration</li></ul>  |
| **Development Status**   | stable |
| **References**           |  There are no documented References for this Detection Rule yet  |
| **Author**               | Thomas Patzke |


## Detection Rules

### Sigma rule

```
title: Login with WMI
id: 5af54681-df95-4c26-854f-2565e13cfab0
status: stable
description: Detection of logins performed with WMI
author: Thomas Patzke
date: 2019/12/04
tags:
    - attack.execution
    - attack.t1047
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4624
        ProcessName: "*\\WmiPrvSE.exe"
    condition: selection
falsepositives:
    - Monitoring tools
    - Legitimate system administration
level: low

```





### powershell
    
```
Get-WinEvent -LogName Security | where {($_.ID -eq "4624" -and $_.message -match "ProcessName.*.*\\WmiPrvSE.exe") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.channel:"Security" AND winlog.event_id:"4624" AND winlog.event_data.ProcessName.keyword:*\\WmiPrvSE.exe)
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/5af54681-df95-4c26-854f-2565e13cfab0 <<EOF
{
  "metadata": {
    "title": "Login with WMI",
    "description": "Detection of logins performed with WMI",
    "tags": [
      "attack.execution",
      "attack.t1047"
    ],
    "query": "(winlog.channel:\"Security\" AND winlog.event_id:\"4624\" AND winlog.event_data.ProcessName.keyword:*\\\\WmiPrvSE.exe)"
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
                    "query": "(winlog.channel:\"Security\" AND winlog.event_id:\"4624\" AND winlog.event_data.ProcessName.keyword:*\\\\WmiPrvSE.exe)",
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
        "subject": "Sigma Rule 'Login with WMI'",
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
(EventID:"4624" AND ProcessName.keyword:*\\WmiPrvSE.exe)
```


### splunk
    
```
(source="WinEventLog:Security" EventCode="4624" ProcessName="*\\WmiPrvSE.exe")
```


### logpoint
    
```
(event_source="Microsoft-Windows-Security-Auditing" event_id="4624" ProcessName="*\\WmiPrvSE.exe")
```


### grep
    
```
grep -P '^(?:.*(?=.*4624)(?=.*.*\WmiPrvSE\.exe))'
```



