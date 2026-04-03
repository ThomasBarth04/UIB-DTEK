# 1. TCP handshake & HTTP

## 1.1 Which packets make up the TCP handshake with `https://www.skyss.no`?

Answer: The TCP handshake packets for `https://www.skyss.no` are packets `55`, `58`, and `59`.

Reasoning: I first used `dns.qry.name == "www.skyss.no"` and found the A records for `vefy02appi9z4c.dxp.optimizely.com` (`172.64.153.191` and `104.18.34.65`). I then filtered with `tcp.flags.syn == 1 && tcp.flags.ack == 0 && ip.dst == 104.18.34.65`, identified packet `55` as the initial SYN, and used **Conversation Filter -> TCP** to locate the full three-way handshake:

1. `55, 2.689668624, 129.177.103.39, vefy02appi9z4c.dxp.optimizely.com, TCP, 76, 34796 → https(443) [SYN] Seq=0 Win=64240 Len=0 MSS=1460 SACK_PERM TSval=3080001861 TSecr=0 WS=128`
2. `58, 2.697442731, vefy02appi9z4c.dxp.optimizely.com, 129.177.103.39, TCP, 76, https(443) → 34796 [SYN, ACK] Seq=0 Ack=1 Win=65535 Len=0 MSS=1250 SACK_PERM TSval=1983991312 TSecr=3080001861 WS=8192`
3. `59, 2.697503561, 129.177.103.39, vefy02appi9z4c.dxp.optimizely.com, TCP, 68, 34796 → https(443) [ACK] Seq=1 Ack=1 Win=64256 Len=0 TSval=3080001869 TSecr=1983991312`

## 1.2 Which packets make up the TCP handshake with `http://www.iloveramennoodles.com`?

Answer: The TCP handshake packets for `http://www.iloveramennoodles.com` are packets `487`, `499`, and `500`.

Reasoning: I repeated the same method. DNS lookup showed `www.iloveramennoodles.com` with A record `69.163.178.49`. Using `tcp.flags.syn == 1 && tcp.flags.ack == 0 && ip.dst == 69.163.178.49` and then **Conversation Filter -> TCP**, the handshake is:

1. `487, 6.355055784, 129.177.103.39, www.iloveramennoodles.com, TCP, 76, 36178 → http(80) [SYN] Seq=0 Win=64240 Len=0 MSS=1460 SACK_PERM TSval=2582003020 TSecr=0 WS=128`
2. `499, 6.553217553, www.iloveramennoodles.com, 129.177.103.39, TCP, 68, http(80) → 36178 [SYN, ACK] Seq=0 Ack=1 Win=42340 Len=0 MSS=1250 SACK_PERM WS=1024`
3. `500, 6.553281391, 129.177.103.39, www.iloveramennoodles.com, TCP, 56, 36178 → http(80) [ACK] Seq=1 Ack=1 Win=64256 Len=0`

## 1.3 Another website is accessed as a result of the HTTP connection to `http://www.iloveramennoodles.com`. Which one?

Answer: The additional website is `fonts.googleapis.com`.

Reasoning: With display filter `http`, I found a `GET` request for a stylesheet in packet `508`. Looking at the DNS activity right after packet `508`, the lookup is for `fonts.googleapis.com`.

## 1.4 The packet trace contains less information about the connection to `https://www.skyss.no`, compared with `http://www.iloveramennoodles.com`. What is the reason for this?

Answer: The difference is that one connection uses `HTTP` and the other uses `HTTPS`.

Reasoning: In Wireshark, `HTTP` traffic is readable directly, so we can see actual requests and responses such as `GET`, response codes, content types, and referrers. For `https://www.skyss.no`, after the TCP handshake the next application-layer protocol is `TLS`. We can still read some metadata (for example server names), but the HTTP requests and responses are encrypted inside TLS and therefore not readable.

# 2. Wireless connection - DHCP & ARP

The laptop first sends a DHCP broadcast from `0.0.0.0` to `255.255.255.255` to request network configuration (packet `45`). The hotspot then completes the DHCP exchange and confirms the lease in packet `47` (DHCP ACK), assigning IP `10.233.13.195` and identifying DHCP server `10.233.13.84`. After obtaining IP configuration, the laptop performs ARP operations on the local link: it announces its new address (packet `53`) and requests the MAC address for `10.233.13.84` (packet `54`). Once ARP resolution is complete, the laptop can send Ethernet frames to the correct next-hop MAC and communicate normally through the hotspot.

## 2.1 Identify the initial broadcast message packet when the device connected

The "initial" broadcast message is packet `45`, where the source is `0.0.0.0` and the destination is `255.255.255.255`.


## 2.2 What IP address was assigned to the device?

The assigned IP address is `10.233.13.195` (shown with hostname `uib-fzcg424.local`).


## 2.3 What is the DHCP server's IP address?

The DHCP server IP address is `10.233.13.84`.


## 2.4 What is the MAC address of the device?

The device MAC address is `f0:20:ff:5b:27:32`.


## 2.5 Identify two packets during the ARP flow (IP request and IP announcement)

1. IP announcement: packet `53` with message `ARP Announcement for 10.233.13.195`.
2. IP request: packet `54` with message `Who has 10.233.13.84? Tell 10.233.13.195`.


## 2.6 Explain the role of the DHCP server and the ARP table when a device connects to a wi-fi hotspot

The DHCP server provides the Layer 3 configuration the device needs to join the network, while ARP resolves local IPv4 addresses to MAC addresses so frames can be delivered on the LAN.

# 3. File downloads and packet loss

## 3.1 Compare MAC addresses in packet 1 of `q3_TCPserv.pcap` and packet 1 of `q3_TCPclient.pcap`

The MAC addresses are **not identical**.

MAC addresses are valid only on the local Layer 2 link. When the same IP datagram traverses routers, each router removes the incoming Ethernet header and adds a new Ethernet header for the next hop. Therefore, the server-side capture shows MAC addresses from the server's local link, while the client-side capture shows MAC addresses from the client's local link.

## 3.2 Identify one packet the client did not receive correctly on the first transmission attempt. How was it identified?

One lost/missing segment is the TCP segment starting at sequence number `14256809`.

I identified this by filtering on `tcp.analysis.duplicate_ack` and finding a duplicate-ACK cluster where the ACK number stays at `14256809`. In the client capture, packets `1205` to `1213` are duplicate ACKs for `14256809`, and SACK information shows that later segments were received out of order. In the server capture, packet `1170` is marked as **TCP Fast Retransmission** with `Seq=14256809` and `Len=3714`, confirming that this segment had to be retransmitted.

## 3.3 Suggest a possible cause of the packet loss event


## 3.4 How did the server respond to the packet loss event?

The server responded with **TCP fast retransmission**.

In `q3_TCPserv.pcap`, after the duplicate ACK burst (packets `1166` to `1169`), the server quickly retransmits missing data, including:
- packet `1170` (`Seq=14256809`)
- packet `1171` (`Seq=14260523`)
- packet `1173` (`Seq=14261761`)
- packet `1175` (`Seq=14264237`)

Additional retransmissions follow, showing that TCP recovery was active until the missing data was recovered.

## 3.5 Was the file eventually correctly received? Explain your answer.

Yes, the file was eventually received correctly.

- In `q3_TCPclient.pcapng`, the final cumulative ACK reaches `25000002` in packet `2083`, indicating that all expected bytes in the transfer were acknowledged.
- The TCP connection then closes normally with FIN/ACK exchange:
  - packet `2081`: server `FIN` (after last data)
  - packet `2084`: client `FIN, ACK`
  - packet `2085`: final `ACK` from server

## 3.6 From the two UDP captures, discuss file integrity and estimate lost packets

The UDP file was **not** received intact.

- Total packets in capture:
  - Server capture: `12210`
  - Client capture: `10382`

Estimated packets never received by the client:
- `12210 - 10382 = 1828` lost data packets

Since UDP has no retransmission mechanism, these missing transfer packets are not automatically recovered, so the downloaded file becomes incomplete/corrupted.

## 3.7 Estimate the size of the file the client received (original size: 25 MB)

Using the received fraction of transfer packets:

\[
\frac{10382}{12210} \approx 0.8505
\]

Estimated received file size:

\[
25\ \text{MB} \times 0.8505 \approx 21.3\ \text{MB}
\]

So the client received approximately **21.3 MB** of the original 25 MB file.

## 3.8 If packets were lost, can the UDP checksum help reconstruct the file?

No. The UDP checksum can only detect data corruption within a received UDP datagram; it cannot recover missing packets or request retransmission.

So when packets are lost, checksum validation may tell us that received packets are valid/invalid, but it cannot reconstruct the missing parts of the file by itself.
