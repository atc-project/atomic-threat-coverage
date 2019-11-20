| Title                | Reconnaissance Activity with Net Command                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects a set of commands often used in recon stages by different attack groups                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0007: Discovery](https://attack.mitre.org/tactics/TA0007)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1087: Account Discovery](https://attack.mitre.org/techniques/T1087)</li><li>[T1082: System Information Discovery](https://attack.mitre.org/techniques/T1082)</li></ul>  |
| Data Needed          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1087: Account Discovery](../Triggers/T1087.md)</li><li>[T1082: System Information Discovery](../Triggers/T1082.md)</li></ul>  |
| Severity Level       | medium |
| False Positives      | <ul><li>False positives depend on scripts and administrative tools used in the monitored environment</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[https://twitter.com/haroonmeer/status/939099379834658817](https://twitter.com/haroonmeer/status/939099379834658817)</li><li>[https://twitter.com/c_APT_ure/status/939475433711722497](https://twitter.com/c_APT_ure/status/939475433711722497)</li><li>[https://www.fireeye.com/blog/threat-research/2016/05/targeted_attacksaga.html](https://www.fireeye.com/blog/threat-research/2016/05/targeted_attacksaga.html)</li></ul>  |
| Author               | Florian Roth, Markus Neis |
| Other Tags           | <ul><li>car.2016-03-001</li><li>car.2016-03-001</li></ul> | 

## Detection Rules

### Sigma rule

```
title: Reconnaissance Activity with Net Command
id: 2887e914-ce96-435f-8105-593937e90757
status: experimental
description: Detects a set of commands often used in recon stages by different attack groups
references:
    - https://twitter.com/haroonmeer/status/939099379834658817
    - https://twitter.com/c_APT_ure/status/939475433711722497
    - https://www.fireeye.com/blog/threat-research/2016/05/targeted_attacksaga.html
author: Florian Roth, Markus Neis
date: 2018/08/22
modified: 2018/12/11
tags:
    - attack.discovery
    - attack.t1087
    - attack.t1082
    - car.2016-03-001
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine:
            - tasklist
            - net time
            - systeminfo
            - whoami
            - nbtstat
            - net start
            - '*\net1 start'
            - qprocess
            - nslookup
            - hostname.exe
            - '*\net1 user /domain'
            - '*\net1 group /domain'
            - '*\net1 group "domain admins" /domain'
            - '*\net1 group "Exchange Trusted Subsystem" /domain'
            - '*\net1 accounts /domain'
            - '*\net1 user net localgroup administrators'
            - netstat -an
    timeframe: 15s
    condition: selection | count() by CommandLine > 4
falsepositives:
    - False positives depend on scripts and administrative tools used in the monitored environment
level: medium

```





### splunk
    
```
(CommandLine="tasklist" OR CommandLine="net time" OR CommandLine="systeminfo" OR CommandLine="whoami" OR CommandLine="nbtstat" OR CommandLine="net start" OR CommandLine="*\\\\net1 start" OR CommandLine="qprocess" OR CommandLine="nslookup" OR CommandLine="hostname.exe" OR CommandLine="*\\\\net1 user /domain" OR CommandLine="*\\\\net1 group /domain" OR CommandLine="*\\\\net1 group \\"domain admins\\" /domain" OR CommandLine="*\\\\net1 group \\"Exchange Trusted Subsystem\\" /domain" OR CommandLine="*\\\\net1 accounts /domain" OR CommandLine="*\\\\net1 user net localgroup administrators" OR CommandLine="netstat -an") | eventstats count as val by CommandLine| search val > 4
```






### Saved Search for Splunk

```
Generated with Sigma2SplunkAlert
[Reconnaissance Activity with Net Command]
action.email = 1
action.email.subject.alert = Splunk Alert: $name$
action.email.to = test@test.de
action.email.message.alert = Splunk Alert $name$ triggered \
List of interesting fields:   \
title: Reconnaissance Activity with Net Command status: experimental \
description: Detects a set of commands often used in recon stages by different attack groups \
references: ['https://twitter.com/haroonmeer/status/939099379834658817', 'https://twitter.com/c_APT_ure/status/939475433711722497', 'https://www.fireeye.com/blog/threat-research/2016/05/targeted_attacksaga.html'] \
tags: ['attack.discovery', 'attack.t1087', 'attack.t1082', 'car.2016-03-001'] \
author: Florian Roth, Markus Neis \
date:  \
falsepositives: ['False positives depend on scripts and administrative tools used in the monitored environment'] \
level: medium
action.email.useNSSubject = 1
alert.severity = 1
alert.suppress = 0
alert.track = 1
alert.expires = 24h
counttype = number of events
cron_schedule = */10 * * * *
allow_skew = 50%
schedule_window = auto
description = Detects a set of commands often used in recon stages by different attack groups
dispatch.earliest_time = -10m
dispatch.latest_time = now
enableSched = 1
quantity = 0
relation = greater than
request.ui_dispatch_app = sigma_hunting_app
request.ui_dispatch_view = search
search = (CommandLine="tasklist" OR CommandLine="net time" OR CommandLine="systeminfo" OR CommandLine="whoami" OR CommandLine="nbtstat" OR CommandLine="net start" OR CommandLine="*\\net1 start" OR CommandLine="qprocess" OR CommandLine="nslookup" OR CommandLine="hostname.exe" OR CommandLine="*\\net1 user /domain" OR CommandLine="*\\net1 group /domain" OR CommandLine="*\\net1 group \"domain admins\" /domain" OR CommandLine="*\\net1 group \"Exchange Trusted Subsystem\" /domain" OR CommandLine="*\\net1 accounts /domain" OR CommandLine="*\\net1 user net localgroup administrators" OR CommandLine="netstat -an") | eventstats count as val by CommandLine| search val > 4 | stats values(*) AS * by _time | search NOT [| inputlookup Reconnaissance_Activity_with_Net_Command_whitelist.csv] | collect index=threat-hunting marker="sigma_tag=attack.discovery,sigma_tag=attack.t1087,sigma_tag=attack.t1082,sigma_tag=car.2016-03-001,level=medium"
```
