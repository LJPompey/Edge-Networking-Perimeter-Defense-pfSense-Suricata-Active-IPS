# Edge Networking & Perimeter Defense: pfSense & Suricata Active IPS

## Project Overview
In modern enterprise environments, endpoint security alone is not enough—threats must be inspected and dropped at the network perimeter before they ever reach internal assets. For this phase of my **Project X** enterprise homelab, I architected and deployed a dedicated **pfSense CE (FreeBSD)** edge firewall to segment my internal Active Directory network from external traffic, then hardened it with **Suricata** running in active Intrusion Prevention System (IPS) mode.

### Objectives
* Provision a dual-homed virtual firewall separating external WAN traffic from the internal `10.0.0.0/24` enterprise subnet.
* Configure routing, DNS, and virtualization-specific NIC tuning to eliminate false-positive telemetry.
* Deploy Suricata with ETOpen Emerging Threats rulesets in active blocking (IPS) mode.
* Author and validate a custom Suricata detection rule to prove inline traffic inspection and automated host blocking.

---

## Lab Architecture & Network Topology

| System / Component | Role | Interface / Network | IP Address |
| :--- | :--- | :--- | :--- |
| **project-x-pfsense** | Edge Firewall & Suricata IPS | WAN (`em0` - VirtualBox NAT) | `10.0.2.15/24` (DHCP) |
| **project-x-pfsense** | Internal Default Gateway | LAN (`em1` - `project-x-network`) | `10.0.0.6/24` (Static) |
| **project-x-dc** | Windows Server 2025 DC / DNS | LAN (`project-x-network`) | `10.0.0.5/24` (Static) |
| **Windows Client** | Internal Test Endpoint | LAN (`project-x-network`) | `10.0.0.x/24` (Gateway: `10.0.0.6`) |

---

## Implementation Walkthrough

### Phase 1: Firewall Provisioning & Interface Segmentation
1. Provisioned a 64-bit FreeBSD VM (`project-x-pfsense`) in VirtualBox with 2 GB RAM (to accommodate Suricata's in-memory rule engine) and mounted the pfSense 2.9.0-RELEASE ISO.
2. Configured two distinct virtual network adapters:
   * **Adapter 1 (WAN):** Attached to **NAT** to provide isolated upstream internet access.
   * **Adapter 2 (LAN):** Attached to the existing **`project-x-network` NAT Network** to bridge into the enterprise lab.
3. Assigned `em0` as WAN and `em1` as LAN via the FreeBSD console, locking the LAN interface to static IP **`10.0.0.6/24`** with no upstream gateway and DHCP server disabled (preserving Active Directory DHCP/DNS authority).

*[Insert Screenshot: pfSense Console Menu showing WAN `10.0.2.15/24` and LAN `10.0.0.6/24`]*

### Phase 2: Initial Hardening & VirtualBox Tuning
1. Completed the pfSense WebConfigurator setup wizard at `https://10.0.0.6`, aligning the firewall domain with `corp.project-x-dc.com` and rotating the default administrative credentials.
2. **Private WAN Routing Fix:** Because the VirtualBox NAT WAN receives a private RFC1918 IP (`10.0.2.15`), I unchecked **Block RFC1918 Private Networks** and **Block bogon networks** on the WAN interface to prevent the firewall from dropping legitimate return traffic.
3. **Eliminating Virtualized Checksum False Positives:** Under **System > Advanced > Networking**, I disabled **Hardware Checksum Offloading**, **TCP Segmentation Offloading (TSO)**, and **Large Receive Offloading (LRO)**, followed by a clean reboot.

*[Insert Screenshot: pfSense Dashboard showing active WAN/LAN interfaces]*

### Phase 3: Suricata Active IPS Deployment
1. Installed the **Suricata** package via **System > Package Manager**.
2. Enabled and downloaded the **ETOpen Emerging Threats** rulesets under **Services > Suricata > Global Settings** and **Updates**.
3. Configured Suricata to monitor the **WAN** interface and enabled **Block Offenders** to transition the engine from passive alerting (IDS) to active inline blocking (IPS).
4. Enabled high-priority threat categories (`emerging-scan.rules`, `emerging-dos.rules`, `emerging-malware.rules`, and `emerging-attack_response.rules`) and started the service.

### Phase 4: Detection Engineering & Active Block Validation
To prove that traffic from internal endpoints was routing through pfSense and actively inspected by Suricata:
1. Updated the Windows endpoint's Default Gateway to **`10.0.0.6`** and verified routing path via `tracert`.
2. Authored a custom Suricata rule under **WAN Rules > Custom Rules** to detect and block outbound ICMP traffic to Google DNS (`8.8.8.8`):
   ```text
   alert icmp any any -> 8.8.8.8 any (msg:"TEST ICMP PING TO GOOGLE DNS"; sid:1000001; rev:1;)
