| Title                    | Rubeus Hack Tool       |
|:-------------------------|:------------------|
| **Description**          | Detects command line parameters used by Rubeus hack tool |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0006: Credential Access](https://attack.mitre.org/tactics/TA0006)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1003: OS Credential Dumping](https://attack.mitre.org/techniques/T1003)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1003: OS Credential Dumping](../Triggers/T1003.md)</li></ul>  |
| **Severity Level**       | critical |
| **False Positives**      | <ul><li>unlikely</li></ul>  |
| **Development Status**   |  Development Status wasn't defined for this Detection Rule yet  |
| **References**           | <ul><li>[https://www.harmj0y.net/blog/redteaming/from-kekeo-to-rubeus/](https://www.harmj0y.net/blog/redteaming/from-kekeo-to-rubeus/)</li></ul>  |
| **Author**               | Florian Roth |
| Other Tags           | <ul><li>attack.s0005</li></ul> | 

## Detection Rules

### Sigma rule

```
title: Rubeus Hack Tool
id: 7ec2c172-dceb-4c10-92c9-87c1881b7e18
description: Detects command line parameters used by Rubeus hack tool
author: Florian Roth
references:
    - https://www.harmj0y.net/blog/redteaming/from-kekeo-to-rubeus/
date: 2018/12/19
tags:
    - attack.credential_access
    - attack.t1003
    - attack.s0005
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine:
            - '* asreproast *'
            - '* dump /service:krbtgt *'
            - '* kerberoast *'
            - '* createnetonly /program:*'
            - '* ptt /ticket:*'
            - '* /impersonateuser:*'
            - '* renew /ticket:*'
            - '* asktgt /user:*'
            - '* harvest /interval:*'
    condition: selection
falsepositives:
    - unlikely
level: critical

```





### powershell
    
```
Get-WinEvent | where {($_.message -match "CommandLine.*.* asreproast .*" -or $_.message -match "CommandLine.*.* dump /service:krbtgt .*" -or $_.message -match "CommandLine.*.* kerberoast .*" -or $_.message -match "CommandLine.*.* createnetonly /program:.*" -or $_.message -match "CommandLine.*.* ptt /ticket:.*" -or $_.message -match "CommandLine.*.* /impersonateuser:.*" -or $_.message -match "CommandLine.*.* renew /ticket:.*" -or $_.message -match "CommandLine.*.* asktgt /user:.*" -or $_.message -match "CommandLine.*.* harvest /interval:.*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
winlog.event_data.CommandLine.keyword:(*\ asreproast\ * OR *\ dump\ \/service\:krbtgt\ * OR *\ kerberoast\ * OR *\ createnetonly\ \/program\:* OR *\ ptt\ \/ticket\:* OR *\ \/impersonateuser\:* OR *\ renew\ \/ticket\:* OR *\ asktgt\ \/user\:* OR *\ harvest\ \/interval\:*)
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/7ec2c172-dceb-4c10-92c9-87c1881b7e18 <<EOF
{
  "metadata": {
    "title": "Rubeus Hack Tool",
    "description": "Detects command line parameters used by Rubeus hack tool",
    "tags": [
      "attack.credential_access",
      "attack.t1003",
      "attack.s0005"
    ],
    "query": "winlog.event_data.CommandLine.keyword:(*\\ asreproast\\ * OR *\\ dump\\ \\/service\\:krbtgt\\ * OR *\\ kerberoast\\ * OR *\\ createnetonly\\ \\/program\\:* OR *\\ ptt\\ \\/ticket\\:* OR *\\ \\/impersonateuser\\:* OR *\\ renew\\ \\/ticket\\:* OR *\\ asktgt\\ \\/user\\:* OR *\\ harvest\\ \\/interval\\:*)"
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
                    "query": "winlog.event_data.CommandLine.keyword:(*\\ asreproast\\ * OR *\\ dump\\ \\/service\\:krbtgt\\ * OR *\\ kerberoast\\ * OR *\\ createnetonly\\ \\/program\\:* OR *\\ ptt\\ \\/ticket\\:* OR *\\ \\/impersonateuser\\:* OR *\\ renew\\ \\/ticket\\:* OR *\\ asktgt\\ \\/user\\:* OR *\\ harvest\\ \\/interval\\:*)",
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
        "subject": "Sigma Rule 'Rubeus Hack Tool'",
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
CommandLine.keyword:(* asreproast * * dump \/service\:krbtgt * * kerberoast * * createnetonly \/program\:* * ptt \/ticket\:* * \/impersonateuser\:* * renew \/ticket\:* * asktgt \/user\:* * harvest \/interval\:*)
```


### splunk
    
```
(CommandLine="* asreproast *" OR CommandLine="* dump /service:krbtgt *" OR CommandLine="* kerberoast *" OR CommandLine="* createnetonly /program:*" OR CommandLine="* ptt /ticket:*" OR CommandLine="* /impersonateuser:*" OR CommandLine="* renew /ticket:*" OR CommandLine="* asktgt /user:*" OR CommandLine="* harvest /interval:*")
```


### logpoint
    
```
CommandLine IN ["* asreproast *", "* dump /service:krbtgt *", "* kerberoast *", "* createnetonly /program:*", "* ptt /ticket:*", "* /impersonateuser:*", "* renew /ticket:*", "* asktgt /user:*", "* harvest /interval:*"]
```


### grep
    
```
grep -P '^(?:.*.* asreproast .*|.*.* dump /service:krbtgt .*|.*.* kerberoast .*|.*.* createnetonly /program:.*|.*.* ptt /ticket:.*|.*.* /impersonateuser:.*|.*.* renew /ticket:.*|.*.* asktgt /user:.*|.*.* harvest /interval:.*)'
```



