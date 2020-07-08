| Title              | DN0076_4768_kerberos_authentication_ticket_was_requested       |
|:-------------------|:------------------|
| **Author**         | @atc_project        |
| **Description**    | This event generates every time Key Distribution Center issues a  Kerberos Ticket Granting Ticket (TGT). This event generates only  on domain controllers. If TGT issue fails then you will see  Failure event with Result Code field not equal to "0x0" |
| **Logging Policy** | <ul><li>[LP0038_windows_audit_kerberos_authentication_service](../Logging_Policies/LP0038_windows_audit_kerberos_authentication_service.md)</li></ul> |
| **References**     | <ul><li>[https://github.com/MicrosoftDocs/windows-itpro-docs/blob/master/windows/security/threat-protection/auditing/event-4768.md](https://github.com/MicrosoftDocs/windows-itpro-docs/blob/master/windows/security/threat-protection/auditing/event-4768.md)</li></ul> |
| **Platform**       | Windows    |
| **Type**           | Windows Log        |
| **Channel**        | Security     |
| **Provider**       | Microsoft-Windows-Security-Auditing    |
| **Fields**         | <ul><li>EventID</li><li>Computer</li><li>Hostname</li><li>TargetUserName</li><li>TargetDomainName</li><li>TargetSid</li><li>ServiceName</li><li>ServiceSid</li><li>TicketOptions</li><li>Status</li><li>TicketEncryptionType</li><li>PreAuthType</li><li>IpAddress</li><li>IpPort</li><li>CertIssuerName</li><li>CertSerialNumber</li><li>CertThumbprint</li></ul> |


## Log Samples

### Raw Log

```
- <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  - <System>
    <Provider Name="Microsoft-Windows-Security-Auditing" Guid="{54849625-5478-4994-A5BA-3E3B0328C30D}" /> 
    <EventID>4768</EventID> 
    <Version>0</Version> 
    <Level>0</Level> 
    <Task>14339</Task> 
    <Opcode>0</Opcode> 
    <Keywords>0x8020000000000000</Keywords> 
    <TimeCreated SystemTime="2015-08-07T18:13:46.074535600Z" /> 
    <EventRecordID>166747</EventRecordID> 
    <Correlation /> 
    <Execution ProcessID="520" ThreadID="1496" /> 
    <Channel>Security</Channel> 
    <Computer>DC01.contoso.local</Computer> 
    <Security /> 
  </System>
  - <EventData>
    <Data Name="TargetUserName">dadmin</Data> 
    <Data Name="TargetDomainName">CONTOSO.LOCAL</Data> 
    <Data Name="TargetSid">S-1-5-21-3457937927-2839227994-823803824-1104</Data> 
    <Data Name="ServiceName">krbtgt</Data> 
    <Data Name="ServiceSid">S-1-5-21-3457937927-2839227994-823803824-502</Data> 
    <Data Name="TicketOptions">0x40810010</Data> 
    <Data Name="Status">0x0</Data> 
    <Data Name="TicketEncryptionType">0x12</Data> 
    <Data Name="PreAuthType">15</Data> 
    <Data Name="IpAddress">::ffff:10.0.0.12</Data> 
    <Data Name="IpPort">49273</Data> 
    <Data Name="CertIssuerName">contoso-DC01-CA-1</Data> 
    <Data Name="CertSerialNumber">1D0000000D292FBE3C6CDDAFA200020000000D</Data> 
    <Data Name="CertThumbprint">564DFAEE99C71D62ABC553E695BD8DBC46669413</Data> 
  </EventData>
</Event>

```




