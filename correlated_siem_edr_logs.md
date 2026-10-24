[2026-10-24T08:14:22Z] [SEG-MAIL-01] INFO  Inbound message received: QueueID=449A82F from=[no-reply@secure-hr-update-portal.com] to=[j.smith@corp-finsec.com] subject="URGENT: Required Annual Payroll Policy Acknowledgment"
[2026-10-24T08:14:23Z] [SEG-MAIL-01] WARN  SPF verification softfail for IP 198.51.100.45 (Domain corp-finsec.com)
[2026-10-24T08:14:23Z] [SEG-MAIL-01] WARN  DKIM signature verification failed for domain corp-finsec.com
[2026-10-24T08:14:24Z] [SEG-MAIL-01] INFO  DMARC policy result: FAIL (Action Taken: DELIVER - Policy=none)
[2026-10-24T08:18:05Z] [PROXY-GW-02] INFO  TCP_MISS/200 GET http://login.corp-finsec.com.auth-update-portal.net/login.php User=j.smith ClientIP=10.0.4.112 DomainAge=2days
[2026-10-24T08:21:40Z] [EDR-AGENT-12] INFO  File written to disk: C:\Users\jsmith\Downloads\Payroll_Policy_2026.pdf.exe Hash=e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
[2026-10-24T08:22:01Z] [EDR-AGENT-12] WARN  Process spawned: C:\Windows\Explorer.exe -> C:\Users\jsmith\Downloads\Payroll_Policy_2026.pdf.exe (PID: 4920)
[2026-10-24T08:22:05Z] [EDR-AGENT-12] ALERT Registry Key Modified: HKCU\Software\Microsoft\Windows\CurrentVersion\Run\WinSysUpdate -> C:\Users\jsmith\AppData\Local\Temp\svchost_update.exe
[2026-10-24T08:22:10Z] [EDR-AGENT-12] CRIT  Outbound connection detected: C:\Users\jsmith\AppData\Local\Temp\svchost_update.exe -> 185.220.101.5:443 (Protocol: TCP/TLS)
[2026-10-24T08:25:00Z] [SOC-SIEM-01] CRIT  Alert triggered [Rule ID: 8092]: "Unsigned binary persistence created + External C2 IP connection" Host=WS-JSMITH
[2026-10-24T08:35:10Z] [SOC-ANALYST] ACTION Host Isolated from Network: WS-JSMITH (10.0.4.112)