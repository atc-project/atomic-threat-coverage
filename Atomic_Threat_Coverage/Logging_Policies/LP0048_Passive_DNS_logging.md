| Title            | LP0048_Passive_DNS_logging                                                                     |
|:-----------------|:--------------------------------------------------------------------------------|
| **Author**       | @atc_project                                                                      |
| **Description**  | Configuration to enable logging of all fields logging in Passive DNS                                                               |
| **Default**      | Not configured                                                                   |
| **Event Volume** | High                                                                    |
| **EventID**      | <ul><li>None</li></ul>         |
| **References**   | <ul><li>[None](None)</li></ul> |



## Configuration

#/etc/default/passivedns
#Manually set the values to log:

# FIELDS:
#  H: YMD-HMS Stamp S: Timestamp(s)  M: Timestamp(ms)  c: Client IP 
#  s: Server IP     C: Class         Q: Query          T: Type      
#  A: Answer        t: TTL           n: Count
  
LOGFIELDS=SMcsCQTAtn
  
#Manually set DNS RR Types to care about
  
# FLAGS:
#  4:A    6:AAAA  C:CNAME  D:DNAME  N:NAPTR  O:SOA
#  P:PTR  R:RP    S:SRV    T:TXT    M:MX     n:NS
#  x:NXD
  
DNSRRTYPES=46CDNOPRSTMnx


