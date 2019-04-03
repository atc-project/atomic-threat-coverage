| Title          | RA_0038_containment_block_ip_on_ngfw                                                                                                      |
|:---------------|:-----------------------------------------------------------------------------------------------------------------|
| Stage    | containment                                                            |
| Automation | None |
| Author    | @atc_project                                                          |
| Creation Date    | 31.01.2019                                            |
| References     | None                                  |
| Description    | Block ip on NGFW.                                                               |
| Linked Response Actions | None |
| Linked Analytics |<ul><li>MS_ngfw</li></ul> |


### Workflow

Block ip address on NGFW using native filtering functionality.
Warning: 
- If not all corporate hosts access internet through the NGFW, this Response Action cannot guarantee containment of threat.
- Be careful blocking IP address. Make sure it's not cloud provider or hoster. In this case you have to use blocking by URL something more specific.