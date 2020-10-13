| Title                    | Avusing Azure Browser SSO       |
|:-------------------------|:------------------|
| **Description**          | Detects abusing  Azure Browser SSO by requesting  OAuth 2.0 refresh tokens for an Azure-AD-authenticated Windows user (i.e. the machine is joined to Azure AD and a user logs in with their Azure AD account) wanting to perform SSO authentication in the browser. An attacker can use this to authenticate to Azure AD in a browser as that user. |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li><li>[TA0004: Privilege Escalation](https://attack.mitre.org/tactics/TA0004)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1073: DLL Side-Loading](https://attack.mitre.org/techniques/T1073)</li><li>[T1574.002: DLL Side-Loading](https://attack.mitre.org/techniques/T1574/002)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0011_7_windows_sysmon_image_loaded](../Data_Needed/DN_0011_7_windows_sysmon_image_loaded.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1574.002: DLL Side-Loading](../Triggers/T1574.002.md)</li></ul>  |
| **Severity Level**       | high |
| **False Positives**      | <ul><li>unknown</li></ul>  |
| **Development Status**   | experimental |
| **References**           |  There are no documented References for this Detection Rule yet  |
| **Author**               | Den Iuzvyk |


## Detection Rules

### Sigma rule

```
title: Avusing Azure Browser SSO
id: 50f852e6-af22-4c78-9ede-42ef36aa3453
description: Detects abusing  Azure Browser SSO by requesting  OAuth 2.0 refresh tokens for an Azure-AD-authenticated Windows user (i.e. the machine is joined to Azure AD and a user logs in with their Azure AD account) wanting to perform SSO authentication in the browser. An attacker can use this to authenticate to Azure AD in a browser as that user.
author: Den Iuzvyk
reference:
   - https://posts.specterops.io/requesting-azure-ad-request-tokens-on-azure-ad-joined-machines-for-browser-sso-2b0409caad30
date: 2020/07/15
modified: 2020/08/26
logsource:
   category: sysmon
   product: windows
status: experimental
tags:
   - attack.defense_evasion
   - attack.privilege_escalation
   - attack.t1073          # an old one
   - attack.t1574.002
detection:
   condition: selection_dll and not filter_legit
   selection_dll:
      EventID: 7
      ImageLoaded|endswith: MicrosoftAccountTokenProvider.dll
   filter_legit:
      Image|endswith:
         - BackgroundTaskHost.exe
         - devenv.exe
         - iexplore.exe
         - MicrosoftEdge.exe
falsepositives:
   - unknown
level: high

```





### powershell
    
```
Get-WinEvent | where {(($_.ID -eq "7" -and $_.message -match "ImageLoaded.*.*MicrosoftAccountTokenProvider.dll") -and  -not (($_.message -match "Image.*.*BackgroundTaskHost.exe" -or $_.message -match "Image.*.*devenv.exe" -or $_.message -match "Image.*.*iexplore.exe" -or $_.message -match "Image.*.*MicrosoftEdge.exe"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
((winlog.event_id:"7" AND winlog.event_data.ImageLoaded.keyword:*MicrosoftAccountTokenProvider.dll) AND (NOT (winlog.event_data.Image.keyword:(*BackgroundTaskHost.exe OR *devenv.exe OR *iexplore.exe OR *MicrosoftEdge.exe))))
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/50f852e6-af22-4c78-9ede-42ef36aa3453 <<EOF
{
  "metadata": {
    "title": "Avusing Azure Browser SSO",
    "description": "Detects abusing  Azure Browser SSO by requesting  OAuth 2.0 refresh tokens for an Azure-AD-authenticated Windows user (i.e. the machine is joined to Azure AD and a user logs in with their Azure AD account) wanting to perform SSO authentication in the browser. An attacker can use this to authenticate to Azure AD in a browser as that user.",
    "tags": [
      "attack.defense_evasion",
      "attack.privilege_escalation",
      "attack.t1073",
      "attack.t1574.002"
    ],
    "query": "((winlog.event_id:\"7\" AND winlog.event_data.ImageLoaded.keyword:*MicrosoftAccountTokenProvider.dll) AND (NOT (winlog.event_data.Image.keyword:(*BackgroundTaskHost.exe OR *devenv.exe OR *iexplore.exe OR *MicrosoftEdge.exe))))"
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
                    "query": "((winlog.event_id:\"7\" AND winlog.event_data.ImageLoaded.keyword:*MicrosoftAccountTokenProvider.dll) AND (NOT (winlog.event_data.Image.keyword:(*BackgroundTaskHost.exe OR *devenv.exe OR *iexplore.exe OR *MicrosoftEdge.exe))))",
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
        "subject": "Sigma Rule 'Avusing Azure Browser SSO'",
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
((EventID:"7" AND ImageLoaded.keyword:*MicrosoftAccountTokenProvider.dll) AND (NOT (Image.keyword:(*BackgroundTaskHost.exe *devenv.exe *iexplore.exe *MicrosoftEdge.exe))))
```


### splunk
    
```
((EventCode="7" ImageLoaded="*MicrosoftAccountTokenProvider.dll") NOT ((Image="*BackgroundTaskHost.exe" OR Image="*devenv.exe" OR Image="*iexplore.exe" OR Image="*MicrosoftEdge.exe")))
```


### logpoint
    
```
((event_id="7" ImageLoaded="*MicrosoftAccountTokenProvider.dll")  -(Image IN ["*BackgroundTaskHost.exe", "*devenv.exe", "*iexplore.exe", "*MicrosoftEdge.exe"]))
```


### grep
    
```
grep -P '^(?:.*(?=.*(?:.*(?=.*7)(?=.*.*MicrosoftAccountTokenProvider\.dll)))(?=.*(?!.*(?:.*(?=.*(?:.*.*BackgroundTaskHost\.exe|.*.*devenv\.exe|.*.*iexplore\.exe|.*.*MicrosoftEdge\.exe))))))'
```



