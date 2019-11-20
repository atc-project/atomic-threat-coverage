| Title                | Possible Applocker Bypass                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects execution of executables that can be used to bypass Applocker whitelisting                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1118: InstallUtil](https://attack.mitre.org/techniques/T1118)</li><li>[T1121: Regsvcs/Regasm](https://attack.mitre.org/techniques/T1121)</li><li>[T1127: Trusted Developer Utilities](https://attack.mitre.org/techniques/T1127)</li><li>[T1170: Mshta](https://attack.mitre.org/techniques/T1170)</li></ul>  |
| Data Needed          |  There is no documented Data Needed for this Detection Rule yet  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1118: InstallUtil](../Triggers/T1118.md)</li><li>[T1121: Regsvcs/Regasm](../Triggers/T1121.md)</li><li>[T1127: Trusted Developer Utilities](../Triggers/T1127.md)</li><li>[T1170: Mshta](../Triggers/T1170.md)</li></ul>  |
| Severity Level       | low |
| False Positives      | <ul><li>False positives depend on scripts and administrative tools used in the monitored environment</li><li>Using installutil to add features for .NET applications (primarly would occur in developer environments)</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[https://github.com/subTee/ApplicationWhitelistBypassTechniques/blob/master/TheList.txt](https://github.com/subTee/ApplicationWhitelistBypassTechniques/blob/master/TheList.txt)</li><li>[https://room362.com/post/2014/2014-01-16-application-whitelist-bypass-using-ieexec-dot-exe/](https://room362.com/post/2014/2014-01-16-application-whitelist-bypass-using-ieexec-dot-exe/)</li></ul>  |
| Author               | juju4 |


## Detection Rules

### Sigma rule

```
title: Possible Applocker Bypass
id: 82a19e3a-2bfe-4a91-8c0d-5d4c98fbb719
description: Detects execution of executables that can be used to bypass Applocker whitelisting
status: experimental
references:
    - https://github.com/subTee/ApplicationWhitelistBypassTechniques/blob/master/TheList.txt
    - https://room362.com/post/2014/2014-01-16-application-whitelist-bypass-using-ieexec-dot-exe/
author: juju4
tags:
    - attack.defense_evasion
    - attack.t1118
    - attack.t1121
    - attack.t1127
    - attack.t1170
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains:
            - '\msdt.exe'
            - '\installutil.exe'
            - '\regsvcs.exe'
            - '\regasm.exe'
            # - '\regsvr32.exe'  # too many FPs, very noisy
            - '\msbuild.exe'
            - '\ieexec.exe'
            #- '\mshta.exe'
            #- '\csc.exe'
    condition: selection
falsepositives:
    - False positives depend on scripts and administrative tools used in the monitored environment
    - Using installutil to add features for .NET applications (primarly would occur in developer environments)
level: low

```





### splunk
    
```
(CommandLine="*\\\\msdt.exe*" OR CommandLine="*\\\\installutil.exe*" OR CommandLine="*\\\\regsvcs.exe*" OR CommandLine="*\\\\regasm.exe*" OR CommandLine="*\\\\msbuild.exe*" OR CommandLine="*\\\\ieexec.exe*")
```






### Saved Search for Splunk

```
Generated with Sigma2SplunkAlert
[Possible Applocker Bypass]
action.email = 1
action.email.subject.alert = Splunk Alert: $name$
action.email.to = test@test.de
action.email.message.alert = Splunk Alert $name$ triggered \
List of interesting fields:   \
title: Possible Applocker Bypass status: experimental \
description: Detects execution of executables that can be used to bypass Applocker whitelisting \
references: ['https://github.com/subTee/ApplicationWhitelistBypassTechniques/blob/master/TheList.txt', 'https://room362.com/post/2014/2014-01-16-application-whitelist-bypass-using-ieexec-dot-exe/'] \
tags: ['attack.defense_evasion', 'attack.t1118', 'attack.t1121', 'attack.t1127', 'attack.t1170'] \
author: juju4 \
date:  \
falsepositives: ['False positives depend on scripts and administrative tools used in the monitored environment', 'Using installutil to add features for .NET applications (primarly would occur in developer environments)'] \
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
description = Detects execution of executables that can be used to bypass Applocker whitelisting
dispatch.earliest_time = -10m
dispatch.latest_time = now
enableSched = 1
quantity = 0
relation = greater than
request.ui_dispatch_app = sigma_hunting_app
request.ui_dispatch_view = search
search = (CommandLine="*\\msdt.exe*" OR CommandLine="*\\installutil.exe*" OR CommandLine="*\\regsvcs.exe*" OR CommandLine="*\\regasm.exe*" OR CommandLine="*\\msbuild.exe*" OR CommandLine="*\\ieexec.exe*") | stats values(*) AS * by _time | search NOT [| inputlookup Possible_Applocker_Bypass_whitelist.csv] | collect index=threat-hunting marker="sigma_tag=attack.defense_evasion,sigma_tag=attack.t1118,sigma_tag=attack.t1121,sigma_tag=attack.t1127,sigma_tag=attack.t1170,level=low"
```
