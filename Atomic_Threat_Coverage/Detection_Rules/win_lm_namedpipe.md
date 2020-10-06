| Title                    | First Time Seen Remote Named Pipe       |
|:-------------------------|:------------------|
| **Description**          | This detection excludes known namped pipes accessible remotely and notify on newly observed ones, may help to detect lateral movement and remote exec using named pipes |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0008: Lateral Movement](https://attack.mitre.org/tactics/TA0008)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1077: Windows Admin Shares](https://attack.mitre.org/techniques/T1077)</li><li>[T1021.002: SMB/Windows Admin Shares](https://attack.mitre.org/techniques/T1021/002)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0032_5145_network_share_object_was_accessed_detailed](../Data_Needed/DN_0032_5145_network_share_object_was_accessed_detailed.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1021.002: SMB/Windows Admin Shares](../Triggers/T1021.002.md)</li></ul>  |
| **Severity Level**       | high |
| **False Positives**      | <ul><li>update the excluded named pipe to filter out any newly observed legit named pipe</li></ul>  |
| **Development Status**   |  Development Status wasn't defined for this Detection Rule yet  |
| **References**           | <ul><li>[https://twitter.com/menasec1/status/1104489274387451904](https://twitter.com/menasec1/status/1104489274387451904)</li></ul>  |
| **Author**               | Samir Bousseaden |


## Detection Rules

### Sigma rule

```
title: First Time Seen Remote Named Pipe
id: 52d8b0c6-53d6-439a-9e41-52ad442ad9ad
description: This detection excludes known namped pipes accessible remotely and notify on newly observed ones, may help to detect lateral movement and remote exec using named pipes
author: Samir Bousseaden
date: 2019/04/03
references:
    - https://twitter.com/menasec1/status/1104489274387451904
tags:
    - attack.lateral_movement
    - attack.t1077          # an old one
    - attack.t1021.002
logsource:
    product: windows
    service: security
    definition: 'The advanced audit policy setting "Object Access > Audit Detailed File Share" must be configured for Success/Failure'
detection:
    selection1:
        EventID: 5145
        ShareName: \\*\IPC$
    selection2:
        EventID: 5145
        ShareName: \\*\IPC$
        RelativeTargetName:
            - 'atsvc'
            - 'samr'
            - 'lsarpc'
            - 'winreg'
            - 'netlogon'
            - 'srvsvc'
            - 'protected_storage'
            - 'wkssvc'
            - 'browser'
            - 'netdfs'
            - 'svcctl'
            - 'spoolss'
            - 'ntsvcs'
            - 'LSM_API_service'
            - 'HydraLsPipe'
            - 'TermSrv_API_service'
            - 'MsFteWds'
    condition: selection1 and not selection2
falsepositives:
    - update the excluded named pipe to filter out any newly observed legit named pipe
level: high

```





### powershell
    
```
Get-WinEvent -LogName Security | where {(($_.ID -eq "5145" -and $_.message -match "ShareName.*\\\\.*\\\\IPC$") -and  -not ($_.ID -eq "5145" -and $_.message -match "ShareName.*\\\\.*\\\\IPC$" -and ($_.message -match "atsvc" -or $_.message -match "samr" -or $_.message -match "lsarpc" -or $_.message -match "winreg" -or $_.message -match "netlogon" -or $_.message -match "srvsvc" -or $_.message -match "protected_storage" -or $_.message -match "wkssvc" -or $_.message -match "browser" -or $_.message -match "netdfs" -or $_.message -match "svcctl" -or $_.message -match "spoolss" -or $_.message -match "ntsvcs" -or $_.message -match "LSM_API_service" -or $_.message -match "HydraLsPipe" -or $_.message -match "TermSrv_API_service" -or $_.message -match "MsFteWds"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.channel:"Security" AND (winlog.event_id:"5145" AND winlog.event_data.ShareName.keyword:\\\\*\\\\IPC$) AND (NOT (winlog.event_id:"5145" AND winlog.event_data.ShareName.keyword:\\\\*\\\\IPC$ AND RelativeTargetName:("atsvc" OR "samr" OR "lsarpc" OR "winreg" OR "netlogon" OR "srvsvc" OR "protected_storage" OR "wkssvc" OR "browser" OR "netdfs" OR "svcctl" OR "spoolss" OR "ntsvcs" OR "LSM_API_service" OR "HydraLsPipe" OR "TermSrv_API_service" OR "MsFteWds"))))
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/52d8b0c6-53d6-439a-9e41-52ad442ad9ad <<EOF\n{\n  "metadata": {\n    "title": "First Time Seen Remote Named Pipe",\n    "description": "This detection excludes known namped pipes accessible remotely and notify on newly observed ones, may help to detect lateral movement and remote exec using named pipes",\n    "tags": [\n      "attack.lateral_movement",\n      "attack.t1077",\n      "attack.t1021.002"\n    ],\n    "query": "(winlog.channel:\\"Security\\" AND (winlog.event_id:\\"5145\\" AND winlog.event_data.ShareName.keyword:\\\\\\\\*\\\\\\\\IPC$) AND (NOT (winlog.event_id:\\"5145\\" AND winlog.event_data.ShareName.keyword:\\\\\\\\*\\\\\\\\IPC$ AND RelativeTargetName:(\\"atsvc\\" OR \\"samr\\" OR \\"lsarpc\\" OR \\"winreg\\" OR \\"netlogon\\" OR \\"srvsvc\\" OR \\"protected_storage\\" OR \\"wkssvc\\" OR \\"browser\\" OR \\"netdfs\\" OR \\"svcctl\\" OR \\"spoolss\\" OR \\"ntsvcs\\" OR \\"LSM_API_service\\" OR \\"HydraLsPipe\\" OR \\"TermSrv_API_service\\" OR \\"MsFteWds\\"))))"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "(winlog.channel:\\"Security\\" AND (winlog.event_id:\\"5145\\" AND winlog.event_data.ShareName.keyword:\\\\\\\\*\\\\\\\\IPC$) AND (NOT (winlog.event_id:\\"5145\\" AND winlog.event_data.ShareName.keyword:\\\\\\\\*\\\\\\\\IPC$ AND RelativeTargetName:(\\"atsvc\\" OR \\"samr\\" OR \\"lsarpc\\" OR \\"winreg\\" OR \\"netlogon\\" OR \\"srvsvc\\" OR \\"protected_storage\\" OR \\"wkssvc\\" OR \\"browser\\" OR \\"netdfs\\" OR \\"svcctl\\" OR \\"spoolss\\" OR \\"ntsvcs\\" OR \\"LSM_API_service\\" OR \\"HydraLsPipe\\" OR \\"TermSrv_API_service\\" OR \\"MsFteWds\\"))))",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": [\n          "winlogbeat-*"\n        ]\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "throttle_period": "15m",\n      "email": {\n        "profile": "standard",\n        "from": "root@localhost",\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'First Time Seen Remote Named Pipe\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
((EventID:"5145" AND ShareName.keyword:\\\\*\\\\IPC$) AND (NOT (EventID:"5145" AND ShareName.keyword:\\\\*\\\\IPC$ AND RelativeTargetName:("atsvc" "samr" "lsarpc" "winreg" "netlogon" "srvsvc" "protected_storage" "wkssvc" "browser" "netdfs" "svcctl" "spoolss" "ntsvcs" "LSM_API_service" "HydraLsPipe" "TermSrv_API_service" "MsFteWds"))))
```


### splunk
    
```
(source="WinEventLog:Security" (EventCode="5145" ShareName="\\\\*\\\\IPC$") NOT (EventCode="5145" ShareName="\\\\*\\\\IPC$" (RelativeTargetName="atsvc" OR RelativeTargetName="samr" OR RelativeTargetName="lsarpc" OR RelativeTargetName="winreg" OR RelativeTargetName="netlogon" OR RelativeTargetName="srvsvc" OR RelativeTargetName="protected_storage" OR RelativeTargetName="wkssvc" OR RelativeTargetName="browser" OR RelativeTargetName="netdfs" OR RelativeTargetName="svcctl" OR RelativeTargetName="spoolss" OR RelativeTargetName="ntsvcs" OR RelativeTargetName="LSM_API_service" OR RelativeTargetName="HydraLsPipe" OR RelativeTargetName="TermSrv_API_service" OR RelativeTargetName="MsFteWds")))
```


### logpoint
    
```
(event_source="Microsoft-Windows-Security-Auditing" (event_id="5145" ShareName="\\\\*\\\\IPC$")  -(event_id="5145" ShareName="\\\\*\\\\IPC$" RelativeTargetName IN ["atsvc", "samr", "lsarpc", "winreg", "netlogon", "srvsvc", "protected_storage", "wkssvc", "browser", "netdfs", "svcctl", "spoolss", "ntsvcs", "LSM_API_service", "HydraLsPipe", "TermSrv_API_service", "MsFteWds"]))
```


### grep
    
```
grep -P '^(?:.*(?=.*(?:.*(?=.*5145)(?=.*\\\\.*\\IPC\\$)))(?=.*(?!.*(?:.*(?=.*5145)(?=.*\\\\.*\\IPC\\$)(?=.*(?:.*atsvc|.*samr|.*lsarpc|.*winreg|.*netlogon|.*srvsvc|.*protected_storage|.*wkssvc|.*browser|.*netdfs|.*svcctl|.*spoolss|.*ntsvcs|.*LSM_API_service|.*HydraLsPipe|.*TermSrv_API_service|.*MsFteWds))))))'
```



