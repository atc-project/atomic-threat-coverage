| Title              | DN_0073_4756_member_was_added_to_a_security_enabled_universal_group       |
|:-------------------|:------------------|
| **Author**         | @atc_project        |
| **Description**    | Member was added to a security-enabled universal group |
| **Logging Policy** | <ul><li>[LP0101_windows_audit_security_group_management](../Logging_Policies/LP0101_windows_audit_security_group_management.md)</li></ul> |
| **References**     | <ul><li>[https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventID=4756](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventID=4756)</li></ul> |
| **Platform**       | Windows    |
| **Type**           | Windows Log        |
| **Channel**        | Security     |
| **Provider**       | Microsoft-Windows-Security-Auditing    |
| **Fields**         | <ul><li>EventID</li><li>ComputerName</li><li>Computer</li><li>Hostname</li><li>MemberName</li><li>MemberSid</li><li>TargetUserName</li><li>TargetDomainName</li><li>TargetSid</li><li>SubjectUserSid</li><li>SubjectUserName</li><li>SubjectDomainName</li><li>SubjectLogonId</li><li>PrivilegeList</li></ul> |


## Log Samples

### Raw Log

```
- <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  - <System>
      <Provider Name="Microsoft-Windows-Security-Auditing" Guid="{54849625-5478-4994-A5BA-3E3B0328C30D}" /> 
      <EventID>4756</EventID> 
      <Version>0</Version> 
      <Level>0</Level> 
      <Task>13826</Task> 
      <Opcode>0</Opcode> 
      <Keywords>0x8020000000000000</Keywords> 
      <TimeCreated SystemTime="2019-03-20T17:08:41.465560800Z" /> 
      <EventRecordID>4405437</EventRecordID> 
      <Correlation /> 
      <Execution ProcessID="704" ThreadID="2584" /> 
      <Channel>Security</Channel> 
      <Computer>atc-win-2k16.atc.local</Computer> 
      <Security /> 
    </System>
  - <EventData>
      <Data Name="MemberName">CN=demouser,CN=Users,DC=atc,DC=local</Data> 
      <Data Name="MemberSid">S-1-5-21-2245550993-2690282630-2861202560-18603</Data> 
      <Data Name="TargetUserName">Enterprise Admins</Data> 
      <Data Name="TargetDomainName">ATC</Data> 
      <Data Name="TargetSid">S-1-5-21-2245550993-2622282683-2531201460-519</Data> 
      <Data Name="SubjectUserSid">S-1-5-21-2245550993-2622282683-2531201460-500</Data> 
      <Data Name="SubjectUserName">test_user</Data> 
      <Data Name="SubjectDomainName">ATC</Data> 
      <Data Name="SubjectLogonId">0x109a6c</Data> 
      <Data Name="PrivilegeList">-</Data> 
    </EventData>
  </Event>

```




