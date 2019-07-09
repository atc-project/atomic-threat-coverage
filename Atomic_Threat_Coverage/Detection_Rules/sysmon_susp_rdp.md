| Title                | Suspicious Outbound RDP Connections                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects Non-Standard Tools Connecting to TCP port 3389 indicating possible lateral movement                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0008: Lateral Movement](https://attack.mitre.org/tactics/TA0008)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1210: Exploitation of Remote Services](https://attack.mitre.org/techniques/T1210)</li></ul>  |
| Data Needed          | <ul><li>[DN_0007_3_windows_sysmon_network_connection](../Data_Needed/DN_0007_3_windows_sysmon_network_connection.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1210: Exploitation of Remote Services](../Triggers/T1210.md)</li></ul>  |
| Severity Level       | high |
| False Positives      | <ul><li>Other Remote Desktop RDP tools</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2019-0708](https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2019-0708)</li></ul>  |
| Author               | Markus Neis - Swisscom |
| Other Tags           | <ul><li>car.2013-07-002</li><li>car.2013-07-002</li></ul> | 

## Detection Rules

### Sigma rule

```
title: Suspicious Outbound RDP Connections 
status: experimental
description: Detects Non-Standard Tools Connecting to TCP port 3389 indicating possible lateral movement
references:
    - https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2019-0708
author: Markus Neis - Swisscom 
date: 2019/05/15
tags:
    - attack.lateral_movement
    - attack.t1210
    - car.2013-07-002
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        EventID: 3
        DestinationPort: 3389 
    filter:
        Image:
            - '*\mstsc.exe'
            - '*\RTSApp.exe'
            - '*\RTS2App.exe'
            - '*\RDCMan.exe'
            - '*\ws_TunnelService.exe'
            - '*\RSSensor.exe'
            - '*\RemoteDesktopManagerFree.exe'
            - '*\RemoteDesktopManager.exe'
            - '*\RemoteDesktopManager64.exe'
            - '*\mRemoteNG.exe'
            - '*\mRemote.exe'
            - '*\Terminals.exe'
            - '*\spiceworks-finder.exe'
            - '*\FSDiscovery.exe'
            - '*\FSAssessment.exe'
            - '*\MobaRTE.exe'
            - '*\chrome.exe'
    condition: selection and not filter 
falsepositives:
    - Other Remote Desktop RDP tools
level: high

```





### es-qs
    
```
((EventID:"3" AND DestinationPort:"3389") AND (NOT (Image.keyword:(*\\\\mstsc.exe *\\\\RTSApp.exe *\\\\RTS2App.exe *\\\\RDCMan.exe *\\\\ws_TunnelService.exe *\\\\RSSensor.exe *\\\\RemoteDesktopManagerFree.exe *\\\\RemoteDesktopManager.exe *\\\\RemoteDesktopManager64.exe *\\\\mRemoteNG.exe *\\\\mRemote.exe *\\\\Terminals.exe *\\\\spiceworks\\-finder.exe *\\\\FSDiscovery.exe *\\\\FSAssessment.exe *\\\\MobaRTE.exe *\\\\chrome.exe))))
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/Suspicious-Outbound-RDP-Connections <<EOF\n{\n  "metadata": {\n    "title": "Suspicious Outbound RDP Connections",\n    "description": "Detects Non-Standard Tools Connecting to TCP port 3389 indicating possible lateral movement",\n    "tags": [\n      "attack.lateral_movement",\n      "attack.t1210",\n      "car.2013-07-002"\n    ],\n    "query": "((EventID:\\"3\\" AND DestinationPort:\\"3389\\") AND (NOT (Image.keyword:(*\\\\\\\\mstsc.exe *\\\\\\\\RTSApp.exe *\\\\\\\\RTS2App.exe *\\\\\\\\RDCMan.exe *\\\\\\\\ws_TunnelService.exe *\\\\\\\\RSSensor.exe *\\\\\\\\RemoteDesktopManagerFree.exe *\\\\\\\\RemoteDesktopManager.exe *\\\\\\\\RemoteDesktopManager64.exe *\\\\\\\\mRemoteNG.exe *\\\\\\\\mRemote.exe *\\\\\\\\Terminals.exe *\\\\\\\\spiceworks\\\\-finder.exe *\\\\\\\\FSDiscovery.exe *\\\\\\\\FSAssessment.exe *\\\\\\\\MobaRTE.exe *\\\\\\\\chrome.exe))))"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "((EventID:\\"3\\" AND DestinationPort:\\"3389\\") AND (NOT (Image.keyword:(*\\\\\\\\mstsc.exe *\\\\\\\\RTSApp.exe *\\\\\\\\RTS2App.exe *\\\\\\\\RDCMan.exe *\\\\\\\\ws_TunnelService.exe *\\\\\\\\RSSensor.exe *\\\\\\\\RemoteDesktopManagerFree.exe *\\\\\\\\RemoteDesktopManager.exe *\\\\\\\\RemoteDesktopManager64.exe *\\\\\\\\mRemoteNG.exe *\\\\\\\\mRemote.exe *\\\\\\\\Terminals.exe *\\\\\\\\spiceworks\\\\-finder.exe *\\\\\\\\FSDiscovery.exe *\\\\\\\\FSAssessment.exe *\\\\\\\\MobaRTE.exe *\\\\\\\\chrome.exe))))",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Suspicious Outbound RDP Connections\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
((EventID:"3" AND DestinationPort:"3389") AND NOT (Image:("*\\\\mstsc.exe" "*\\\\RTSApp.exe" "*\\\\RTS2App.exe" "*\\\\RDCMan.exe" "*\\\\ws_TunnelService.exe" "*\\\\RSSensor.exe" "*\\\\RemoteDesktopManagerFree.exe" "*\\\\RemoteDesktopManager.exe" "*\\\\RemoteDesktopManager64.exe" "*\\\\mRemoteNG.exe" "*\\\\mRemote.exe" "*\\\\Terminals.exe" "*\\\\spiceworks\\-finder.exe" "*\\\\FSDiscovery.exe" "*\\\\FSAssessment.exe" "*\\\\MobaRTE.exe" "*\\\\chrome.exe")))
```


### splunk
    
```
((EventID="3" DestinationPort="3389") NOT ((Image="*\\\\mstsc.exe" OR Image="*\\\\RTSApp.exe" OR Image="*\\\\RTS2App.exe" OR Image="*\\\\RDCMan.exe" OR Image="*\\\\ws_TunnelService.exe" OR Image="*\\\\RSSensor.exe" OR Image="*\\\\RemoteDesktopManagerFree.exe" OR Image="*\\\\RemoteDesktopManager.exe" OR Image="*\\\\RemoteDesktopManager64.exe" OR Image="*\\\\mRemoteNG.exe" OR Image="*\\\\mRemote.exe" OR Image="*\\\\Terminals.exe" OR Image="*\\\\spiceworks-finder.exe" OR Image="*\\\\FSDiscovery.exe" OR Image="*\\\\FSAssessment.exe" OR Image="*\\\\MobaRTE.exe" OR Image="*\\\\chrome.exe")))
```


### logpoint
    
```
((EventID="3" DestinationPort="3389")  -(Image IN ["*\\\\mstsc.exe", "*\\\\RTSApp.exe", "*\\\\RTS2App.exe", "*\\\\RDCMan.exe", "*\\\\ws_TunnelService.exe", "*\\\\RSSensor.exe", "*\\\\RemoteDesktopManagerFree.exe", "*\\\\RemoteDesktopManager.exe", "*\\\\RemoteDesktopManager64.exe", "*\\\\mRemoteNG.exe", "*\\\\mRemote.exe", "*\\\\Terminals.exe", "*\\\\spiceworks-finder.exe", "*\\\\FSDiscovery.exe", "*\\\\FSAssessment.exe", "*\\\\MobaRTE.exe", "*\\\\chrome.exe"]))
```


### grep
    
```
grep -P '^(?:.*(?=.*(?:.*(?=.*3)(?=.*3389)))(?=.*(?!.*(?:.*(?=.*(?:.*.*\\mstsc\\.exe|.*.*\\RTSApp\\.exe|.*.*\\RTS2App\\.exe|.*.*\\RDCMan\\.exe|.*.*\\ws_TunnelService\\.exe|.*.*\\RSSensor\\.exe|.*.*\\RemoteDesktopManagerFree\\.exe|.*.*\\RemoteDesktopManager\\.exe|.*.*\\RemoteDesktopManager64\\.exe|.*.*\\mRemoteNG\\.exe|.*.*\\mRemote\\.exe|.*.*\\Terminals\\.exe|.*.*\\spiceworks-finder\\.exe|.*.*\\FSDiscovery\\.exe|.*.*\\FSAssessment\\.exe|.*.*\\MobaRTE\\.exe|.*.*\\chrome\\.exe))))))'
```



