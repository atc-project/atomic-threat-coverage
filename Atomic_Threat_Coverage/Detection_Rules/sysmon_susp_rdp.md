| Title                    | Suspicious Outbound RDP Connections       |
|:-------------------------|:------------------|
| **Description**          | Detects Non-Standard Tools Connecting to TCP port 3389 indicating possible lateral movement |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0008: Lateral Movement](https://attack.mitre.org/tactics/TA0008)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1210: Exploitation of Remote Services](https://attack.mitre.org/techniques/T1210)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0007_3_windows_sysmon_network_connection](../Data_Needed/DN_0007_3_windows_sysmon_network_connection.md)</li></ul>  |
| **Trigger**              |  There is no documented Trigger for this Detection Rule yet  |
| **Severity Level**       | high |
| **False Positives**      | <ul><li>Other Remote Desktop RDP tools</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2019-0708](https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2019-0708)</li></ul>  |
| **Author**               | Markus Neis - Swisscom |
| Other Tags           | <ul><li>car.2013-07-002</li></ul> | 

## Detection Rules

### Sigma rule

```
title: Suspicious Outbound RDP Connections
id: ed74fe75-7594-4b4b-ae38-e38e3fd2eb23
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
        Initiated: 'true'
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
            - '*\thor.exe'
            - '*\thor64.exe'
    condition: selection and not filter 
falsepositives:
    - Other Remote Desktop RDP tools
level: high

```





### powershell
    
```
Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "3" -and $_.message -match "DestinationPort.*3389" -and $_.message -match "Initiated.*true") -and  -not (($_.message -match "Image.*.*\\mstsc.exe" -or $_.message -match "Image.*.*\\RTSApp.exe" -or $_.message -match "Image.*.*\\RTS2App.exe" -or $_.message -match "Image.*.*\\RDCMan.exe" -or $_.message -match "Image.*.*\\ws_TunnelService.exe" -or $_.message -match "Image.*.*\\RSSensor.exe" -or $_.message -match "Image.*.*\\RemoteDesktopManagerFree.exe" -or $_.message -match "Image.*.*\\RemoteDesktopManager.exe" -or $_.message -match "Image.*.*\\RemoteDesktopManager64.exe" -or $_.message -match "Image.*.*\\mRemoteNG.exe" -or $_.message -match "Image.*.*\\mRemote.exe" -or $_.message -match "Image.*.*\\Terminals.exe" -or $_.message -match "Image.*.*\\spiceworks-finder.exe" -or $_.message -match "Image.*.*\\FSDiscovery.exe" -or $_.message -match "Image.*.*\\FSAssessment.exe" -or $_.message -match "Image.*.*\\MobaRTE.exe" -or $_.message -match "Image.*.*\\chrome.exe" -or $_.message -match "Image.*.*\\thor.exe" -or $_.message -match "Image.*.*\\thor64.exe"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.channel:"Microsoft\-Windows\-Sysmon\/Operational" AND (winlog.event_id:"3" AND winlog.event_data.DestinationPort:"3389" AND Initiated:"true") AND (NOT (winlog.event_data.Image.keyword:(*\\mstsc.exe OR *\\RTSApp.exe OR *\\RTS2App.exe OR *\\RDCMan.exe OR *\\ws_TunnelService.exe OR *\\RSSensor.exe OR *\\RemoteDesktopManagerFree.exe OR *\\RemoteDesktopManager.exe OR *\\RemoteDesktopManager64.exe OR *\\mRemoteNG.exe OR *\\mRemote.exe OR *\\Terminals.exe OR *\\spiceworks\-finder.exe OR *\\FSDiscovery.exe OR *\\FSAssessment.exe OR *\\MobaRTE.exe OR *\\chrome.exe OR *\\thor.exe OR *\\thor64.exe))))
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/ed74fe75-7594-4b4b-ae38-e38e3fd2eb23 <<EOF
{
  "metadata": {
    "title": "Suspicious Outbound RDP Connections",
    "description": "Detects Non-Standard Tools Connecting to TCP port 3389 indicating possible lateral movement",
    "tags": [
      "attack.lateral_movement",
      "attack.t1210",
      "car.2013-07-002"
    ],
    "query": "(winlog.channel:\"Microsoft\\-Windows\\-Sysmon\\/Operational\" AND (winlog.event_id:\"3\" AND winlog.event_data.DestinationPort:\"3389\" AND Initiated:\"true\") AND (NOT (winlog.event_data.Image.keyword:(*\\\\mstsc.exe OR *\\\\RTSApp.exe OR *\\\\RTS2App.exe OR *\\\\RDCMan.exe OR *\\\\ws_TunnelService.exe OR *\\\\RSSensor.exe OR *\\\\RemoteDesktopManagerFree.exe OR *\\\\RemoteDesktopManager.exe OR *\\\\RemoteDesktopManager64.exe OR *\\\\mRemoteNG.exe OR *\\\\mRemote.exe OR *\\\\Terminals.exe OR *\\\\spiceworks\\-finder.exe OR *\\\\FSDiscovery.exe OR *\\\\FSAssessment.exe OR *\\\\MobaRTE.exe OR *\\\\chrome.exe OR *\\\\thor.exe OR *\\\\thor64.exe))))"
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
                    "query": "(winlog.channel:\"Microsoft\\-Windows\\-Sysmon\\/Operational\" AND (winlog.event_id:\"3\" AND winlog.event_data.DestinationPort:\"3389\" AND Initiated:\"true\") AND (NOT (winlog.event_data.Image.keyword:(*\\\\mstsc.exe OR *\\\\RTSApp.exe OR *\\\\RTS2App.exe OR *\\\\RDCMan.exe OR *\\\\ws_TunnelService.exe OR *\\\\RSSensor.exe OR *\\\\RemoteDesktopManagerFree.exe OR *\\\\RemoteDesktopManager.exe OR *\\\\RemoteDesktopManager64.exe OR *\\\\mRemoteNG.exe OR *\\\\mRemote.exe OR *\\\\Terminals.exe OR *\\\\spiceworks\\-finder.exe OR *\\\\FSDiscovery.exe OR *\\\\FSAssessment.exe OR *\\\\MobaRTE.exe OR *\\\\chrome.exe OR *\\\\thor.exe OR *\\\\thor64.exe))))",
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
        "subject": "Sigma Rule 'Suspicious Outbound RDP Connections'",
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
((EventID:"3" AND DestinationPort:"3389" AND Initiated:"true") AND (NOT (Image.keyword:(*\\mstsc.exe *\\RTSApp.exe *\\RTS2App.exe *\\RDCMan.exe *\\ws_TunnelService.exe *\\RSSensor.exe *\\RemoteDesktopManagerFree.exe *\\RemoteDesktopManager.exe *\\RemoteDesktopManager64.exe *\\mRemoteNG.exe *\\mRemote.exe *\\Terminals.exe *\\spiceworks\-finder.exe *\\FSDiscovery.exe *\\FSAssessment.exe *\\MobaRTE.exe *\\chrome.exe *\\thor.exe *\\thor64.exe))))
```


### splunk
    
```
(source="WinEventLog:Microsoft-Windows-Sysmon/Operational" (EventCode="3" DestinationPort="3389" Initiated="true") NOT ((Image="*\\mstsc.exe" OR Image="*\\RTSApp.exe" OR Image="*\\RTS2App.exe" OR Image="*\\RDCMan.exe" OR Image="*\\ws_TunnelService.exe" OR Image="*\\RSSensor.exe" OR Image="*\\RemoteDesktopManagerFree.exe" OR Image="*\\RemoteDesktopManager.exe" OR Image="*\\RemoteDesktopManager64.exe" OR Image="*\\mRemoteNG.exe" OR Image="*\\mRemote.exe" OR Image="*\\Terminals.exe" OR Image="*\\spiceworks-finder.exe" OR Image="*\\FSDiscovery.exe" OR Image="*\\FSAssessment.exe" OR Image="*\\MobaRTE.exe" OR Image="*\\chrome.exe" OR Image="*\\thor.exe" OR Image="*\\thor64.exe")))
```


### logpoint
    
```
((event_id="3" DestinationPort="3389" Initiated="true")  -(Image IN ["*\\mstsc.exe", "*\\RTSApp.exe", "*\\RTS2App.exe", "*\\RDCMan.exe", "*\\ws_TunnelService.exe", "*\\RSSensor.exe", "*\\RemoteDesktopManagerFree.exe", "*\\RemoteDesktopManager.exe", "*\\RemoteDesktopManager64.exe", "*\\mRemoteNG.exe", "*\\mRemote.exe", "*\\Terminals.exe", "*\\spiceworks-finder.exe", "*\\FSDiscovery.exe", "*\\FSAssessment.exe", "*\\MobaRTE.exe", "*\\chrome.exe", "*\\thor.exe", "*\\thor64.exe"]))
```


### grep
    
```
grep -P '^(?:.*(?=.*(?:.*(?=.*3)(?=.*3389)(?=.*true)))(?=.*(?!.*(?:.*(?=.*(?:.*.*\mstsc\.exe|.*.*\RTSApp\.exe|.*.*\RTS2App\.exe|.*.*\RDCMan\.exe|.*.*\ws_TunnelService\.exe|.*.*\RSSensor\.exe|.*.*\RemoteDesktopManagerFree\.exe|.*.*\RemoteDesktopManager\.exe|.*.*\RemoteDesktopManager64\.exe|.*.*\mRemoteNG\.exe|.*.*\mRemote\.exe|.*.*\Terminals\.exe|.*.*\spiceworks-finder\.exe|.*.*\FSDiscovery\.exe|.*.*\FSAssessment\.exe|.*.*\MobaRTE\.exe|.*.*\chrome\.exe|.*.*\thor\.exe|.*.*\thor64\.exe))))))'
```



