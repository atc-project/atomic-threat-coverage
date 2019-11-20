| Title                | Webshell Detection With Command Line Keywords                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects certain command line parameters often used during reconnaissance activity via web shells                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0004: Privilege Escalation](https://attack.mitre.org/tactics/TA0004)</li><li>[TA0003: Persistence](https://attack.mitre.org/tactics/TA0003)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1100: Web Shell](https://attack.mitre.org/techniques/T1100)</li></ul>  |
| Data Needed          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1100: Web Shell](../Triggers/T1100.md)</li></ul>  |
| Severity Level       | high |
| False Positives      | <ul><li>unknown</li></ul>  |
| Development Status   |  Development Status wasn't defined for this Detection Rule yet  |
| References           |  There are no documented References for this Detection Rule yet  |
| Author               | Florian Roth |


## Detection Rules

### Sigma rule

```
title: Webshell Detection With Command Line Keywords
id: bed2a484-9348-4143-8a8a-b801c979301c
description: Detects certain command line parameters often used during reconnaissance activity via web shells
author: Florian Roth
reference:
    - https://www.fireeye.com/blog/threat-research/2013/08/breaking-down-the-china-chopper-web-shell-part-ii.html
date: 2017/01/01
modified: 2019/10/26
tags:
    - attack.privilege_escalation
    - attack.persistence
    - attack.t1100
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage:
            - '*\apache*'
            - '*\tomcat*'
            - '*\w3wp.exe'
            - '*\php-cgi.exe'
            - '*\nginx.exe'
            - '*\httpd.exe'
        CommandLine:
            - '*whoami*'
            - '*net user *'
            - '*ping -n *'
            - '*systeminfo'
            - '*&cd&echo*'
            - '*cd /d*'  # https://www.computerhope.com/cdhlp.htm
    condition: selection
fields:
    - CommandLine
    - ParentCommandLine
falsepositives:
    - unknown
level: high

```





### splunk
    
```
((ParentImage="*\\\\apache*" OR ParentImage="*\\\\tomcat*" OR ParentImage="*\\\\w3wp.exe" OR ParentImage="*\\\\php-cgi.exe" OR ParentImage="*\\\\nginx.exe" OR ParentImage="*\\\\httpd.exe") (CommandLine="*whoami*" OR CommandLine="*net user *" OR CommandLine="*ping -n *" OR CommandLine="*systeminfo" OR CommandLine="*&cd&echo*" OR CommandLine="*cd /d*")) | table CommandLine,ParentCommandLine
```






### Saved Search for Splunk

```
Generated with Sigma2SplunkAlert
[Webshell Detection With Command Line Keywords]
action.email = 1
action.email.subject.alert = Splunk Alert: $name$
action.email.to = test@test.de
action.email.message.alert = Splunk Alert $name$ triggered \
List of interesting fields:  \
CommandLine: $result.CommandLine$ \
ParentCommandLine: $result.ParentCommandLine$  \
title: Webshell Detection With Command Line Keywords status:  \
description: Detects certain command line parameters often used during reconnaissance activity via web shells \
references:  \
tags: ['attack.privilege_escalation', 'attack.persistence', 'attack.t1100'] \
author: Florian Roth \
date:  \
falsepositives: ['unknown'] \
level: high
action.email.useNSSubject = 1
alert.severity = 1
alert.suppress = 0
alert.track = 1
alert.expires = 24h
counttype = number of events
cron_schedule = */10 * * * *
allow_skew = 50%
schedule_window = auto
description = Detects certain command line parameters often used during reconnaissance activity via web shells
dispatch.earliest_time = -10m
dispatch.latest_time = now
enableSched = 1
quantity = 0
relation = greater than
request.ui_dispatch_app = sigma_hunting_app
request.ui_dispatch_view = search
search = ((ParentImage="*\\apache*" OR ParentImage="*\\tomcat*" OR ParentImage="*\\w3wp.exe" OR ParentImage="*\\php-cgi.exe" OR ParentImage="*\\nginx.exe" OR ParentImage="*\\httpd.exe") (CommandLine="*whoami*" OR CommandLine="*net user *" OR CommandLine="*ping -n *" OR CommandLine="*systeminfo" OR CommandLine="*&cd&echo*" OR CommandLine="*cd /d*")) | table CommandLine,ParentCommandLine,host | search NOT [| inputlookup Webshell_Detection_With_Command_Line_Keywords_whitelist.csv] | collect index=threat-hunting marker="sigma_tag=attack.privilege_escalation,sigma_tag=attack.persistence,sigma_tag=attack.t1100,level=high"
```
