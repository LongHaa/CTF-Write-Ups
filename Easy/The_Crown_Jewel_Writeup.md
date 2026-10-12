# The Crown Jewel — TryHackMe Writeup

| Field | Details |
|---|---|
| **Room** | The Crown Jewel |
| **Difficulty** | Easy |
| **Topics** | Network Forensics |
| **Tools** | Wireshark, Splunk |

## Summary

This room focuses on investigating a network intrusion involving command-and-control (C2) communication, ARP spoofing, and DNS tunneling for data exfiltration. Using Splunk and Wireshark, I analyzed security logs and network packets to identify suspicious activity, determine the compromised machine, and investigate how the attacker extracted sensitive information from the network.

## Scenario

You are on a shift, looking at a new alert from Imperium Labs, a company that has been under MSSP monitoring since before you joined the team. Although the company's primary focus is unclear, it has a global presence and valuable secrets to protect, particularly on its heavily secured GitLab and Jira servers, which contain proprietary source code and project data.

## Investigation

### 1. From which internal IP did the suspicious connection originate?

I started by reviewing the network logs in **Splunk**. I focused on the IDS alert timestamp, **November 30, 2025, at 09:30:12**, and inspected the source IP associated with the flagged outbound reverse-shell connection. The logs identified `10.10.10.100` as the internal source.

**Answer:** `10.10.10.100`

### 2. What outbound connection was detected as a C2 channel?

In Splunk, I examined the destination address and port associated with the suspicious connection. The logs showed outbound traffic to `1.1.1.1` on port `8080`.

**Answer:** `1.1.1.1:8080`

### 3. Which MAC address is impersonating the gateway `10.10.10.1`?

In Wireshark, I initially examined traffic involving the suspicious internal host using this display filter:

```wireshark
ip.addr == 10.10.10.100
```

I observed TCP connection activity and then investigated the ARP traffic separately. ARP is not IP traffic, so the IP address filter needs to be cleared to inspect ARP packets. The ARP activity indicated that MAC address `00:0c:29:11:22:33` was claiming the gateway IP `10.10.10.1`. This suggested gateway impersonation through ARP spoofing.

Useful display filter:

```wireshark
arp
```

**Answer:** `00:0c:29:11:22:33`

### 4. What is the non-standard User-Agent hitting the Jira instance?

*I used a walkthrough to help with this question.*

The walkthrough demonstrated how to search for the destination IP `1.1.1.1` or the keyword `jira` in Splunk, then inspect the **User-Agent** field. The unusual User-Agent value was `CVE-202X-EXPLOIT`.

**Answer:** `CVE-202X-EXPLOIT`

### 5. How many ARP spoofing attacks were observed in the PCAP?

In Wireshark, I opened **Statistics → Protocol Hierarchy** to see a breakdown of the protocols in the packet capture. It showed **90 ARP packets**.

**Answer submitted:** `90`

> **Note:** Protocol Hierarchy counts all ARP packets, not just malicious ones. Confirming which packets are part of spoofing activity requires inspecting the ARP requests/replies and suspicious IP-to-MAC mappings.

### 6. What's the payload containing the plaintext credentials found in the POST request?

I used this Wireshark display filter to locate HTTP POST requests:

```wireshark
http.request.method == "POST"
```

After locating the request, I inspected the packet details and saw credentials transmitted in plaintext. I also consulted a walkthrough to understand how to retrieve the exact payload format by using **Follow → TCP Stream**.

**Answer:**

```text
username=dev_user&password=SecrectPassword!
```

This demonstrates why sensitive credentials should not be transmitted over unencrypted HTTP.

### 7. What domain, owned by the attacker, was used for data exfiltration?

After investigating the ARP spoofing activity, I noticed unusual DNS queries containing long or irregular subdomains. This pattern reminded me of **DNS tunneling**, a technique I had studied while preparing for Security+.

The suspicious queries used subdomains under `exfil-domain.xyz`. In DNS-based exfiltration, an attacker can encode information within subdomain labels so that DNS lookups transmit that information to an attacker-controlled domain.

Useful display filter:

```wireshark
dns.qry.name contains "exfil-domain.xyz"
```

**Answer:** `exfil-domain.xyz`

### 8. After examining the logs, which protocol was used for data exfiltration?

The attacker used **DNS** to exfiltrate data. By embedding data in subdomain queries, the attacker could make exfiltration traffic resemble ordinary DNS lookups and potentially bypass network controls that allow DNS requests.

**Answer:** `DNS`

## Lessons Learned

- Improved my ability to analyze network traffic using Wireshark display filters, Protocol Hierarchy statistics, and **Follow TCP Stream**.
- Practiced investigating security alerts and identifying suspicious IP addresses using Splunk.
- Learned how to recognize indicators of ARP spoofing and DNS tunneling in network traffic.
- Gained a better understanding of how attackers can use DNS queries to exfiltrate data.
- Learned how plaintext credentials can be exposed through unencrypted HTTP requests.
- Improved my ability to correlate network activity with security alerts during an incident investigation.

---

*This writeup is for educational purposes and documents activity within an authorized TryHackMe lab environment.*
