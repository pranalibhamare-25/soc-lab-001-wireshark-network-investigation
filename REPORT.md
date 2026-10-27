# SOC Investigation Report — SOC-LAB-001

**Date:** 27 October 2026  
**Scenario:** Simulated outbound network alert  
**Evidence:** Real Wireshark capture from a personal Windows laptop

## Alert summary
An outbound TCP connection was observed from `192.168.0.187` to `57.144.177.32` on TCP port `443`.

## TCP analysis
Frames `236`, `238`, and `240` showed SYN, SYN-ACK, and ACK, confirming completion of the TCP three-way handshake.

## TLS analysis
Frame `244` contained a TLS Client Hello whose SNI extension indicated `web.whatsapp.com`. Subsequent packets showed encrypted application data; frames `351–354` showed orderly TCP closure.

## Security assessment
No malicious activity was confirmed from the packet evidence alone. The SNI does not establish user intent, application identity, or authorization.

## Recommended action
Review endpoint process and network logs, browser history, relevant SIEM/EDR alerts, and company policy to determine whether the connection was legitimate.

## Conclusion
The evidence supports successful TCP and TLS communication. Further contextual evidence is needed before concluding whether the activity is authorized or suspicious.
