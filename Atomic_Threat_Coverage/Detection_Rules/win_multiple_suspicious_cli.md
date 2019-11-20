| Title                | Quick Execution of a Series of Suspicious Commands                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects multiple suspicious process in a limited timeframe                                                                                                                                           |
| ATT&amp;CK Tactic    |   This Detection Rule wasn't mapped to ATT&amp;CK Tactic yet  |
| ATT&amp;CK Technique |  This Detection Rule wasn't mapped to ATT&amp;CK Technique yet  |
| Data Needed          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              |  There is no documented Trigger for this Detection Rule yet  |
| Severity Level       | low |
| False Positives      | <ul><li>False positives depend on scripts and administrative tools used in the monitored environment</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[https://car.mitre.org/wiki/CAR-2013-04-002](https://car.mitre.org/wiki/CAR-2013-04-002)</li></ul>  |
| Author               | juju4 |
| Other Tags           | <ul><li>car.2013-04-002</li><li>car.2013-04-002</li></ul> | 

## Detection Rules

### Sigma rule

```
title: Quick Execution of a Series of Suspicious Commands
id: 61ab5496-748e-4818-a92f-de78e20fe7f1
description: Detects multiple suspicious process in a limited timeframe
status: experimental
references:
    - https://car.mitre.org/wiki/CAR-2013-04-002
author: juju4
modified: 2012/12/11
tags:
    - car.2013-04-002
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine:
            - arp.exe
            - at.exe
            - attrib.exe
            - cscript.exe
            - dsquery.exe
            - hostname.exe
            - ipconfig.exe
            - mimikatz.exe
            - nbtstat.exe
            - net.exe
            - netsh.exe
            - nslookup.exe
            - ping.exe
            - quser.exe
            - qwinsta.exe
            - reg.exe
            - runas.exe
            - sc.exe
            - schtasks.exe
            - ssh.exe
            - systeminfo.exe
            - taskkill.exe
            - telnet.exe
            - tracert.exe
            - wscript.exe
            - xcopy.exe
            - pscp.exe
            - copy.exe
            - robocopy.exe
            - certutil.exe
            - vssadmin.exe
            - powershell.exe
            - wevtutil.exe
            - psexec.exe
            - bcedit.exe
            - wbadmin.exe
            - icacls.exe
            - diskpart.exe
    timeframe: 5m
    condition: selection | count() by MachineName > 5
falsepositives:
    - False positives depend on scripts and administrative tools used in the monitored environment
level: low

```





### splunk
    
```
(CommandLine="arp.exe" OR CommandLine="at.exe" OR CommandLine="attrib.exe" OR CommandLine="cscript.exe" OR CommandLine="dsquery.exe" OR CommandLine="hostname.exe" OR CommandLine="ipconfig.exe" OR CommandLine="mimikatz.exe" OR CommandLine="nbtstat.exe" OR CommandLine="net.exe" OR CommandLine="netsh.exe" OR CommandLine="nslookup.exe" OR CommandLine="ping.exe" OR CommandLine="quser.exe" OR CommandLine="qwinsta.exe" OR CommandLine="reg.exe" OR CommandLine="runas.exe" OR CommandLine="sc.exe" OR CommandLine="schtasks.exe" OR CommandLine="ssh.exe" OR CommandLine="systeminfo.exe" OR CommandLine="taskkill.exe" OR CommandLine="telnet.exe" OR CommandLine="tracert.exe" OR CommandLine="wscript.exe" OR CommandLine="xcopy.exe" OR CommandLine="pscp.exe" OR CommandLine="copy.exe" OR CommandLine="robocopy.exe" OR CommandLine="certutil.exe" OR CommandLine="vssadmin.exe" OR CommandLine="powershell.exe" OR CommandLine="wevtutil.exe" OR CommandLine="psexec.exe" OR CommandLine="bcedit.exe" OR CommandLine="wbadmin.exe" OR CommandLine="icacls.exe" OR CommandLine="diskpart.exe") | eventstats count as val by MachineName| search val > 5
```






### Saved Search for Splunk

```
Generated with Sigma2SplunkAlert
[Quick Execution of a Series of Suspicious Commands]
action.email = 1
action.email.subject.alert = Splunk Alert: $name$
action.email.to = test@test.de
action.email.message.alert = Splunk Alert $name$ triggered \
List of interesting fields:   \
title: Quick Execution of a Series of Suspicious Commands status: experimental \
description: Detects multiple suspicious process in a limited timeframe \
references: ['https://car.mitre.org/wiki/CAR-2013-04-002'] \
tags: ['car.2013-04-002'] \
author: juju4 \
date:  \
falsepositives: ['False positives depend on scripts and administrative tools used in the monitored environment'] \
level: low
action.email.useNSSubject = 1
alert.severity = 1
alert.suppress = 0
alert.track = 1
alert.expires = 24h
counttype = number of events
cron_schedule = */10 * * * *
allow_skew = 50%
schedule_window = auto
description = Detects multiple suspicious process in a limited timeframe
dispatch.earliest_time = -10m
dispatch.latest_time = now
enableSched = 1
quantity = 0
relation = greater than
request.ui_dispatch_app = sigma_hunting_app
request.ui_dispatch_view = search
search = (CommandLine="arp.exe" OR CommandLine="at.exe" OR CommandLine="attrib.exe" OR CommandLine="cscript.exe" OR CommandLine="dsquery.exe" OR CommandLine="hostname.exe" OR CommandLine="ipconfig.exe" OR CommandLine="mimikatz.exe" OR CommandLine="nbtstat.exe" OR CommandLine="net.exe" OR CommandLine="netsh.exe" OR CommandLine="nslookup.exe" OR CommandLine="ping.exe" OR CommandLine="quser.exe" OR CommandLine="qwinsta.exe" OR CommandLine="reg.exe" OR CommandLine="runas.exe" OR CommandLine="sc.exe" OR CommandLine="schtasks.exe" OR CommandLine="ssh.exe" OR CommandLine="systeminfo.exe" OR CommandLine="taskkill.exe" OR CommandLine="telnet.exe" OR CommandLine="tracert.exe" OR CommandLine="wscript.exe" OR CommandLine="xcopy.exe" OR CommandLine="pscp.exe" OR CommandLine="copy.exe" OR CommandLine="robocopy.exe" OR CommandLine="certutil.exe" OR CommandLine="vssadmin.exe" OR CommandLine="powershell.exe" OR CommandLine="wevtutil.exe" OR CommandLine="psexec.exe" OR CommandLine="bcedit.exe" OR CommandLine="wbadmin.exe" OR CommandLine="icacls.exe" OR CommandLine="diskpart.exe") | eventstats count as val by MachineName| search val > 5 | stats values(*) AS * by _time | search NOT [| inputlookup Quick_Execution_of_a_Series_of_Suspicious_Commands_whitelist.csv] | collect index=threat-hunting marker="sigma_tag=car.2013-04-002,level=low"
```
