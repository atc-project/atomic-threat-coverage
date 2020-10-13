| Title                    | Relevant Anti-Virus Event       |
|:-------------------------|:------------------|
| **Description**          | This detection method points out highly relevant Antivirus events |
| **ATT&amp;CK Tactic**    |   This Detection Rule wasn't mapped to ATT&amp;CK Tactic yet  |
| **ATT&amp;CK Technique** |  This Detection Rule wasn't mapped to ATT&amp;CK Technique yet  |
| **Data Needed**          |  There is no documented Data Needed for this Detection Rule yet  |
| **Trigger**              |  There is no documented Trigger for this Detection Rule yet  |
| **Severity Level**       | high |
| **False Positives**      | <ul><li>Some software piracy tools (key generators, cracks) are classified as hack tools</li></ul>  |
| **Development Status**   |  Development Status wasn't defined for this Detection Rule yet  |
| **References**           |  There are no documented References for this Detection Rule yet  |
| **Author**               | Florian Roth |


## Detection Rules

### Sigma rule

```
title: Relevant Anti-Virus Event
id: 78bc5783-81d9-4d73-ac97-59f6db4f72a8
description: This detection method points out highly relevant Antivirus events
author: Florian Roth
date: 2017/02/19
logsource:
    product: windows
    service: application
detection:
    keywords:
        Message:
            - "*HTool*"
            - "*Hacktool*"
            - "*ASP/Backdoor*"
            - "*JSP/Backdoor*"
            - "*PHP/Backdoor*"
            - "*Backdoor.ASP*"
            - "*Backdoor.JSP*"
            - "*Backdoor.PHP*"
            - "*Webshell*"
            - "*Portscan*"
            - "*Mimikatz*"
            - "*WinCred*"
            - "*PlugX*"
            - "*Korplug*"
            - "*Pwdump*"
            - "*Chopper*"
            - "*WmiExec*"
            - "*Xscan*"
            - "*Clearlog*"
            - "*ASPXSpy*"
    filters:
        Message:
            - "*Keygen*"
            - "*Crack*"
    condition: keywords and not 1 of filters
falsepositives:
    - Some software piracy tools (key generators, cracks) are classified as hack tools
level: high

```





### powershell
    
```
Get-WinEvent -LogName Application | where {(($_.message -match ".*HTool.*" -or $_.message -match ".*Hacktool.*" -or $_.message -match ".*ASP/Backdoor.*" -or $_.message -match ".*JSP/Backdoor.*" -or $_.message -match ".*PHP/Backdoor.*" -or $_.message -match ".*Backdoor.ASP.*" -or $_.message -match ".*Backdoor.JSP.*" -or $_.message -match ".*Backdoor.PHP.*" -or $_.message -match ".*Webshell.*" -or $_.message -match ".*Portscan.*" -or $_.message -match ".*Mimikatz.*" -or $_.message -match ".*WinCred.*" -or $_.message -match ".*PlugX.*" -or $_.message -match ".*Korplug.*" -or $_.message -match ".*Pwdump.*" -or $_.message -match ".*Chopper.*" -or $_.message -match ".*WmiExec.*" -or $_.message -match ".*Xscan.*" -or $_.message -match ".*Clearlog.*" -or $_.message -match ".*ASPXSpy.*") -and  -not (($_.message -match ".*Keygen.*" -or $_.message -match ".*Crack.*"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.channel:"Application" AND Message.keyword:(*HTool* OR *Hacktool* OR *ASP\/Backdoor* OR *JSP\/Backdoor* OR *PHP\/Backdoor* OR *Backdoor.ASP* OR *Backdoor.JSP* OR *Backdoor.PHP* OR *Webshell* OR *Portscan* OR *Mimikatz* OR *WinCred* OR *PlugX* OR *Korplug* OR *Pwdump* OR *Chopper* OR *WmiExec* OR *Xscan* OR *Clearlog* OR *ASPXSpy*) AND (NOT (Message.keyword:(*Keygen* OR *Crack*))))
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/78bc5783-81d9-4d73-ac97-59f6db4f72a8 <<EOF
{
  "metadata": {
    "title": "Relevant Anti-Virus Event",
    "description": "This detection method points out highly relevant Antivirus events",
    "tags": "",
    "query": "(winlog.channel:\"Application\" AND Message.keyword:(*HTool* OR *Hacktool* OR *ASP\\/Backdoor* OR *JSP\\/Backdoor* OR *PHP\\/Backdoor* OR *Backdoor.ASP* OR *Backdoor.JSP* OR *Backdoor.PHP* OR *Webshell* OR *Portscan* OR *Mimikatz* OR *WinCred* OR *PlugX* OR *Korplug* OR *Pwdump* OR *Chopper* OR *WmiExec* OR *Xscan* OR *Clearlog* OR *ASPXSpy*) AND (NOT (Message.keyword:(*Keygen* OR *Crack*))))"
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
                    "query": "(winlog.channel:\"Application\" AND Message.keyword:(*HTool* OR *Hacktool* OR *ASP\\/Backdoor* OR *JSP\\/Backdoor* OR *PHP\\/Backdoor* OR *Backdoor.ASP* OR *Backdoor.JSP* OR *Backdoor.PHP* OR *Webshell* OR *Portscan* OR *Mimikatz* OR *WinCred* OR *PlugX* OR *Korplug* OR *Pwdump* OR *Chopper* OR *WmiExec* OR *Xscan* OR *Clearlog* OR *ASPXSpy*) AND (NOT (Message.keyword:(*Keygen* OR *Crack*))))",
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
        "subject": "Sigma Rule 'Relevant Anti-Virus Event'",
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
(Message.keyword:(*HTool* *Hacktool* *ASP\/Backdoor* *JSP\/Backdoor* *PHP\/Backdoor* *Backdoor.ASP* *Backdoor.JSP* *Backdoor.PHP* *Webshell* *Portscan* *Mimikatz* *WinCred* *PlugX* *Korplug* *Pwdump* *Chopper* *WmiExec* *Xscan* *Clearlog* *ASPXSpy*) AND (NOT (Message.keyword:(*Keygen* *Crack*))))
```


### splunk
    
```
(source="WinEventLog:Application" (Message="*HTool*" OR Message="*Hacktool*" OR Message="*ASP/Backdoor*" OR Message="*JSP/Backdoor*" OR Message="*PHP/Backdoor*" OR Message="*Backdoor.ASP*" OR Message="*Backdoor.JSP*" OR Message="*Backdoor.PHP*" OR Message="*Webshell*" OR Message="*Portscan*" OR Message="*Mimikatz*" OR Message="*WinCred*" OR Message="*PlugX*" OR Message="*Korplug*" OR Message="*Pwdump*" OR Message="*Chopper*" OR Message="*WmiExec*" OR Message="*Xscan*" OR Message="*Clearlog*" OR Message="*ASPXSpy*") NOT ((Message="*Keygen*" OR Message="*Crack*")))
```


### logpoint
    
```
(Message IN ["*HTool*", "*Hacktool*", "*ASP/Backdoor*", "*JSP/Backdoor*", "*PHP/Backdoor*", "*Backdoor.ASP*", "*Backdoor.JSP*", "*Backdoor.PHP*", "*Webshell*", "*Portscan*", "*Mimikatz*", "*WinCred*", "*PlugX*", "*Korplug*", "*Pwdump*", "*Chopper*", "*WmiExec*", "*Xscan*", "*Clearlog*", "*ASPXSpy*"]  -(Message IN ["*Keygen*", "*Crack*"]))
```


### grep
    
```
grep -P '^(?:.*(?=.*(?:.*.*HTool.*|.*.*Hacktool.*|.*.*ASP/Backdoor.*|.*.*JSP/Backdoor.*|.*.*PHP/Backdoor.*|.*.*Backdoor\.ASP.*|.*.*Backdoor\.JSP.*|.*.*Backdoor\.PHP.*|.*.*Webshell.*|.*.*Portscan.*|.*.*Mimikatz.*|.*.*WinCred.*|.*.*PlugX.*|.*.*Korplug.*|.*.*Pwdump.*|.*.*Chopper.*|.*.*WmiExec.*|.*.*Xscan.*|.*.*Clearlog.*|.*.*ASPXSpy.*))(?=.*(?!.*(?:.*(?=.*(?:.*.*Keygen.*|.*.*Crack.*))))))'
```



