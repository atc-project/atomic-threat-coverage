| Title              | DN_0069_4732_member_was_added_to_security_enabled_local_group       |
|:-------------------|:------------------|
| **Author**         | @atc_project        |
| **Description**    | This event generates every time a new member was added to a  security-enabled (security) local group. This event generates  on domain controllers, member servers, and workstations |
| **Logging Policy** | <ul><li>[LP_0101_windows_audit_security_group_management](../Logging_Policies/LP_0101_windows_audit_security_group_management.md)</li></ul> |
| **References**     | <ul><li>[https://github.com/MicrosoftDocs/windows-itpro-docs/blob/master/windows/security/threat-protection/auditing/event-4732.md](https://github.com/MicrosoftDocs/windows-itpro-docs/blob/master/windows/security/threat-protection/auditing/event-4732.md)</li></ul> |
| **Platform**       | Windows    |
| **Type**           | Windows Log        |
| **Channel**        | Security     |
| **Provider**       | Microsoft-Windows-Security-Auditing    |
| **Fields**         | <ul><li>EventID</li><li>Computer</li><li>Hostname</li><li>MemberName</li><li>MemberSid</li><li>TargetUserName</li><li>TargetDomainName</li><li>TargetSid</li><li>SubjectUserSid</li><li>SubjectUserName</li><li>SubjectDomainName</li><li>SubjectLogonId</li><li>PrivilegeList</li></ul> |


## Log Samples

### Raw Log

```
- <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  - <System>
    <Provider Name="Microsoft-Windows-Security-Auditing" Guid="{54849625-5478-4994-A5BA-3E3B0328C30D}" /> 
    <EventID>4732</EventID> 
    <Version>0</Version> 
    <Level>0</Level> 
    <Task>13826</Task> 
    <Opcode>0</Opcode> 
    <Keywords>0x8020000000000000</Keywords> 
    <TimeCreated SystemTime="2015-08-19T03:02:38.563110400Z" /> 
    <EventRecordID>174856</EventRecordID> 
    <Correlation /> 
    <Execution ProcessID="512" ThreadID="1092" /> 
    <Channel>Security</Channel> 
    <Computer>DC01.contoso.local</Computer> 
    <Security /> 
  </System>
  - <EventData>
    <Data Name="MemberName">CN=eadmin,CN=Users,DC=contoso,DC=local</Data> 
    <Data Name="MemberSid">S-1-5-21-3457937927-2839227994-823803824-500</Data> 
    <Data Name="TargetUserName">AccountOperators</Data> 
    <Data Name="TargetDomainName">CONTOSO</Data> 
    <Data Name="TargetSid">S-1-5-21-3457937927-2839227994-823803824-6605</Data> 
    <Data Name="SubjectUserSid">S-1-5-21-3457937927-2839227994-823803824-1104</Data> 
    <Data Name="SubjectUserName">dadmin</Data> 
    <Data Name="SubjectDomainName">CONTOSO</Data> 
    <Data Name="SubjectLogonId">0x3031e</Data> 
    <Data Name="PrivilegeList">-</Data> 
  </EventData>
</Event>

```




