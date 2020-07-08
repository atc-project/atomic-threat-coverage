| Title              | DN0078_4771_kerberos_pre_authentication_failed       |
|:-------------------|:------------------|
| **Author**         | @atc_project        |
| **Description**    | This event generates every time the Key Distribution Center fails  to issue a Kerberos Ticket Granting Ticket (TGT). This can occur  when a domain controller doesn’t have a certificate installed for  smart card authentication (for example, with a "Domain Controller"  or "Domain Controller Authentication" template), the user’s password  has expired, or the wrong password was provided. This event  generates only on domain controllers |
| **Logging Policy** | <ul><li>[LP0038_windows_audit_kerberos_authentication_service](../Logging_Policies/LP0038_windows_audit_kerberos_authentication_service.md)</li></ul> |
| **References**     | <ul><li>[https://github.com/MicrosoftDocs/windows-itpro-docs/blob/master/windows/security/threat-protection/auditing/event-4771.md](https://github.com/MicrosoftDocs/windows-itpro-docs/blob/master/windows/security/threat-protection/auditing/event-4771.md)</li></ul> |
| **Platform**       | Windows    |
| **Type**           | Windows Log        |
| **Channel**        | Security     |
| **Provider**       | Microsoft-Windows-Security-Auditing    |
| **Fields**         | <ul><li>EventID</li><li>Computer</li><li>Hostname</li><li>TargetUserName</li><li>TargetSid</li><li>ServiceName</li><li>TicketOptions</li><li>Status</li><li>PreAuthType</li><li>IpAddress</li><li>IpPort</li><li>CertIssuerName</li><li>CertSerialNumber</li><li>CertThumbprint</li></ul> |


## Log Samples

### Raw Log

```
- <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  - <System>
    <Provider Name="Microsoft-Windows-Security-Auditing" Guid="{54849625-5478-4994-A5BA-3E3B0328C30D}" /> 
    <EventID>4771</EventID> 
    <Version>0</Version> 
    <Level>0</Level> 
    <Task>14339</Task> 
    <Opcode>0</Opcode> 
    <Keywords>0x8010000000000000</Keywords> 
    <TimeCreated SystemTime="2015-08-07T18:10:21.495462300Z" /> 
    <EventRecordID>166708</EventRecordID> 
    <Correlation /> 
    <Execution ProcessID="520" ThreadID="1084" /> 
    <Channel>Security</Channel> 
    <Computer>DC01.contoso.local</Computer> 
    <Security /> 
  </System>
  - <EventData>
    <Data Name="TargetUserName">dadmin</Data> 
    <Data Name="TargetSid">S-1-5-21-3457937927-2839227994-823803824-1104</Data> 
    <Data Name="ServiceName">krbtgt/CONTOSO.LOCAL</Data> 
    <Data Name="TicketOptions">0x40810010</Data> 
    <Data Name="Status">0x10</Data> 
    <Data Name="PreAuthType">15</Data> 
    <Data Name="IpAddress">::ffff:10.0.0.12</Data> 
    <Data Name="IpPort">49254</Data> 
    <Data Name="CertIssuerName" /> 
    <Data Name="CertSerialNumber" /> 
    <Data Name="CertThumbprint" /> 
  </EventData>
</Event>

```




