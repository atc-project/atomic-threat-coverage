| Title                    | Avusing Azure Browser SSO       |
|:-------------------------|:------------------|
| **Description**          | Detects abusing  Azure Browser SSO by requesting  OAuth 2.0 refresh tokens for an Azure-AD-authenticated Windows user (i.e. the machine is joined to Azure AD and a user logs in with their Azure AD account) wanting to perform SSO authentication in the browser. An attacker can use this to authenticate to Azure AD in a browser as that user. |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li><li>[TA0004: Privilege Escalation](https://attack.mitre.org/tactics/TA0004)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1073: DLL Side-Loading](https://attack.mitre.org/techniques/T1073)</li><li>[T1574.002: DLL Side-Loading](https://attack.mitre.org/techniques/T1574.002)</li></ul>  |
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
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/50f852e6-af22-4c78-9ede-42ef36aa3453 <<EOF\n{\n  "metadata": {\n    "title": "Avusing Azure Browser SSO",\n    "description": "Detects abusing  Azure Browser SSO by requesting  OAuth 2.0 refresh tokens for an Azure-AD-authenticated Windows user (i.e. the machine is joined to Azure AD and a user logs in with their Azure AD account) wanting to perform SSO authentication in the browser. An attacker can use this to authenticate to Azure AD in a browser as that user.",\n    "tags": [\n      "attack.defense_evasion",\n      "attack.privilege_escalation",\n      "attack.t1073",\n      "attack.t1574.002"\n    ],\n    "query": "((winlog.event_id:\\"7\\" AND winlog.event_data.ImageLoaded.keyword:*MicrosoftAccountTokenProvider.dll) AND (NOT (winlog.event_data.Image.keyword:(*BackgroundTaskHost.exe OR *devenv.exe OR *iexplore.exe OR *MicrosoftEdge.exe))))"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "((winlog.event_id:\\"7\\" AND winlog.event_data.ImageLoaded.keyword:*MicrosoftAccountTokenProvider.dll) AND (NOT (winlog.event_data.Image.keyword:(*BackgroundTaskHost.exe OR *devenv.exe OR *iexplore.exe OR *MicrosoftEdge.exe))))",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": [\n          "winlogbeat-*"\n        ]\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "throttle_period": "15m",\n      "email": {\n        "profile": "standard",\n        "from": "root@localhost",\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Avusing Azure Browser SSO\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
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
grep -P '^(?:.*(?=.*(?:.*(?=.*7)(?=.*.*MicrosoftAccountTokenProvider\\.dll)))(?=.*(?!.*(?:.*(?=.*(?:.*.*BackgroundTaskHost\\.exe|.*.*devenv\\.exe|.*.*iexplore\\.exe|.*.*MicrosoftEdge\\.exe))))))'
```



