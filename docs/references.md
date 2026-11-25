# References

## Specifications

- [RFC 8999: Version-Independent Properties of QUIC](https://www.rfc-editor.org/rfc/rfc8999)
- [RFC 9000: QUIC: A UDP-Based Multiplexed and Secure Transport](https://www.rfc-editor.org/rfc/rfc9000)
- [RFC 9001: Using TLS to Secure QUIC](https://www.rfc-editor.org/rfc/rfc9001)
- [RFC 9002: QUIC Loss Detection and Congestion Control](https://www.rfc-editor.org/rfc/rfc9002)
- [RFC 9114: HTTP/3](https://www.rfc-editor.org/rfc/rfc9114)
- [RFC 9221: An Unreliable Datagram Extension to QUIC](https://www.rfc-editor.org/rfc/rfc9221)
- [RFC 9287: Greasing the QUIC Bit](https://www.rfc-editor.org/rfc/rfc9287)
- [RFC 9298: Proxying UDP in HTTP](https://www.rfc-editor.org/rfc/rfc9298)
- [RFC 9312: Manageability of the QUIC Transport Protocol](https://www.rfc-editor.org/rfc/rfc9312)
- [RFC 9369: QUIC Version 2](https://www.rfc-editor.org/rfc/rfc9369)
- [IANA HTTP/3 parameters registry](https://www.iana.org/assignments/http3-parameters/http3-parameters.xhtml)
- [QUIC-LB: Generating Routable QUIC Connection IDs (draft)](https://datatracker.ietf.org/doc/draft-ietf-quic-load-balancers/)

## Threat reporting

- [Unit 42: QUIC and Covert: Novel HTTP/3-Powered RATs Target Southeast Asian Governments](https://unit42.paloaltonetworks.com/custom-rats-target-southeast-asia-governments/) (PerfectPioneer, KUKURAT)
- [Seqrite: Operation QUICSILVER](https://www.seqrite.com/blog/operation-quicsilver-china-nexus-actor-targets-myanmar-diplomats-via-vhd-delivered-go-backdoor/) (QUICAgent)
- [GBHackers: Salat Malware Abuses QUIC and WebSockets](https://gbhackers.com/salat-malware-abuses-quic/)
- [Active Countermeasures: A Network Threat Hunter's Guide to C2 over QUIC](https://www.activecountermeasures.com/a-network-threat-hunters-guide-to-c2-over-quic/)
- [Active Countermeasures: Malware of the Day: Merlin C2 Data Jitter](https://www.activecountermeasures.com/malware-of-the-day-merlin-c2-data-jitter/)
- [Salesforce Engineering: gQUIC analyzer and CYU fingerprinting](https://engineering.salesforce.com/?p=2152)

## Research

- Steganography in the QUIC Communication Protocol, *Journal of Universal Computer Science*, 2026
- [QUIC-Exfil: Exploiting QUIC's Server Preferred Address Feature to Perform Data Exfiltration Attacks (arXiv 2505.05292)](https://arxiv.org/abs/2505.05292)
- Sudhan & Kulkarni, latency spin-bit covert channel, COMSNETS 2024
- QuicCourier and QuicCC-SMD (2025), traffic-shaping covert channels over QUIC
- TS-Morph (2025), generative timing for covert channels
- [GIAC GCIA paper: identifying QUIC traffic with common open-source IDS/IPS tools](https://www.giac.org/paper/gcia/9662/quic-dead-common-ids-ips-tools-identify-quic-traffic/118096)

## Tooling and vendor guidance

- [Zeek QUIC analyzer](https://docs.zeek.org/en/master/scripts/base/protocols/quic/main.zeek.html)
- [Suricata QUIC keywords](https://docs.suricata.io/en/latest/rules/quic-keywords.html)
- [FoxIO JA4+](https://github.com/FoxIO-LLC/ja4) and [APNIC: JA4+ network fingerprinting](https://blog.apnic.net/2023/11/22/ja4-network-fingerprinting/)
- [quic-go](https://github.com/quic-go/quic-go), the Go QUIC library used by most in-the-wild QUIC C2
- [Merlin](https://github.com/Ne0nd0g/merlin), the open-source C2 framework with HTTP/3 support used in the lab guide
- [Cloudflare Gateway: HTTP/3 inspection](https://developers.cloudflare.com/cloudflare-one/policies/gateway/http-policies/http3/)
- [Fortinet: Blocking QUIC](https://docs.fortinet.com/document/fortisase/latest/administration-guide/219936/blocking-quic)
- [Cisco: Disable QUIC Protocol to Ensure Compatibility](https://www.cisco.com/c/en/us/support/docs/security/umbrella/224709-disable-quic-protocol-to-ensure.pdf)
- [ESET: Disable QUIC protocol in web browsers](https://support.eset.com/en/kb6757-disable-quic-protocol-in-google-chrome-browser)
