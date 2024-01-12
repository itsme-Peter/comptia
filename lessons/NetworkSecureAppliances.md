# Secure Network Appliances

### Objectives
- Implement firewalls and proxy servers.
- Implement network security monitoring.
- Summarize the use of SIEM.

# Firewalls
## Packet Filtering Firewalls
All firewalls can still perform this basic function.\
### Access Control List(ACL)
A packet filtering firewall is configured by specifying a group of rules, called an <u>Access control list (ACL)</u>. Each rule defines a specific type of data packet and the action to take when a packet matches the rule. A packet filtering firewall can inspect the headers of IP packets. This means that rules can be based on the information found in those headers:
- IP filtering - accepting or denying traffic on the basis of its source and/or destination IP address. Some firewalls might also be able to filter by MAC addresses.
- Protocol ID/type (TCP, UDP, ICMP, routing protocols, and so on).
- Port filtering/security—accepting or denying a packet on the basis of source and destination port numbers (TCP or UDP application type).

If the action is configured to accept or permit, the firewall allows the packet to pass. A drop or deny action silently discards the packet. A reject action also blocks the packet, but responds to the sender with an ICMP message, such as port unreachable. 

Another distinction that can be made is whether the firewall can control only inbound traffic or both inbound and outbound traffic.\
This is also often referred to as ingress and egress traffic or filtering. Controlling outbound traffic is useful because it can block applications that have not been authorized to run on the network and defeat malware, such as backdoors. Ingress and egress traffic is filtered using separate ACLs. 

### Stateless Operation
A basic packet filtering firewall is stateless. This means that it does not preserve information about network sessions. Each packet is analyzed independently, with no record of previously processed packets.\
This type of filtering requires the least processing effort, but it can be vulnerable to attacks that are spread over a sequence of packets.\
A stateless firewall can also introduce problems in traffic flow, especially when some sort of load balancing is being used or when clients or servers need to use dynamically assigned ports. 

### Stateful Inspection Firewalls
A stateful inspection firewall addresses problems by tracking information about the session established between two hosts, or blocking malicious attempts to start a bogus session. The vast majority of firewalls now incorporate some level of stateful inspection capability.Session data is stored in a <u>state table.</u>

When a packet arrives, the firewall checks it to confirm whether it belongs to an existing connection. If it does not, it applies the ordinary packet filtering rules to determine whether to allow it. Once the connection has been allowed, the firewall usually allows traffic to pass unmonitored, in order to conserve processing effort.

Stateful inspection occurs at two layers
- Transport Layer(OSI Layer 4):- The firewall examines the TCP three-way handshake to distinguish new from established connections. A legitimate TCP connection should follow a SYN > SYN/ACK > ACK sequence to establish a session, which is then tracked using sequence numbers.\
Deviations from this, such as SYN without ACK or sequence number anomalies, can be dropped as malicious flooding or session hijacking attempts. The firewall can be configured to respond to such attacks by blocking source IP addresses and throttling sessions. It can also track UDP connections, though this is harder as UDP is a connectionless protocol. It is also likely to be able to detect IP header and ICMP anomalies.
- Application Layer(OSI Layer 7):- One key feature is to verify the application protocol matches the port; to verify that malware isn't sending raw TCP data over port 80 just because port 80 is open, for instance.\
A web application firewall could analyze the HTTP headers and the HTML code present in HTTP packets to try to identify code that matches a pattern in its threat database.\
Application-aware firewalls have many different names, including application layer gateway, stateful multilayer inspection, or deep packet inspection.\
Application aware devices have to be configured with separate filters for each type of traffic (HTTP and HTTPS, SMTP/POP/IMAP, FTP, and so on). Application aware firewalls are very powerful, but they are not invulnerable. Their complexity means that it is possible to craft DoS attacks against exploitable vulnerabilities in the firewall firmware. Also, the firewall cannot examine encrypted data packets, unless configured with an SSL/TLS inspector.

### IPTABLES
It  is a command line utility provided by many Linux distributions that allows administrators to edit the rules enforced by the Linux kernel firewall.\
It works with chains, which apply to the different types of traffic, such as the INPUT chain for traffic destined for the local host. Each chain has a default policy set to DROP or ACCEPT traffic that does not match a rule. Each rule, processed in order, determines whether traffic matching the criteria is allowed or dropped.
> iptables --list INPUT --line-numbers -n

It will show the contents of the INPUT chain with line numbers and no name resolution.
> iptables -I INPUT 2 -p tcp -s 10.1.0.0/24 --dport 22 -j ACCEPT

It will insert a new rule as line 2 to allow traffic to the SSH server TCP port (22) from the local subnet

### Firewall Implimentation
Some types of firewalls are better suited for placement at the network edge or zonal borders; others are designed to protect individual hosts.

#### Appliance Firewall
An <u>Appliance Firewall</u> is a stand-alone hardware firewall deployed to monitor traffic passing into and out of a network zone. A firewall appliance can be deployed in two ways
- Routed(Layer 3) - the firewall performs forwarding between subnets. Each interface on the firewall connects to a different subnet and represents a different security zone.
- Bridged (layer 2)—the firewall inspects traffic passing between two nodes, such as a router and a switch. This is also referred to as transparent mode.\
The firewall does not have an IP interface (except for configuration management). It bridges the Ethernet interfaces between the two nodes. Despite performing forwarding at layer 2, the firewall can still inspect and filter traffic on the basis of the full range of packet headers.\
The typical use case for a transparent firewall is to deploy it without having to reconfigure subnets and reassign IP addresses on other devices.
- A router firewall or firewall router appliance implements filtering functionality as part of the router firmware. The difference is that a router appliance is primarily designed for routing, with firewall as a secondary feature. SOHO Internet router/modems come with a firewall built-in, for example.

#### Application-Based Firewalls
Firewalls can also run as software on any type of computing host. There are several types of application-based firewalls:

- Host-based firewall (or personal firewall)—implemented as a software application running on a single host designed to protect that host only. As well as enforcing packet filtering ACLs, a personal firewall can be used to allow or deny software processes from accessing the network.
- Application firewall—software designed to run on a server to protect a particular application only (a web server firewall, for instance, or a firewall designed to protect an SQL Server database). This is a type of host-based firewall and would typically be deployed in addition to a network firewall.
- Network operating system (NOS) firewall—a software-based firewall running under a network server OS, such as Windows or Linux. The server would function as a gateway or proxy for a network segment. 

## Proxies and Gateways
A firewall that performs application layer filtering is likely to be implemented as a proxy.\
Where a network firewall only accepts or blocks traffic, a proxy server works on a store-and-forward model. The proxy deconstructs each packet, performs analysis, then rebuilds the packet and forwards it on, providing it conforms to the rules. 
>The amount of rebuilding depends on the proxy. Some proxies may only manipulate the IP and TCP headers. Application-aware proxies might add or remove HTTP headers. A deep packet inspection proxy might be able to remove content from an HTTP payload.

### Forward Proxy Servers
A forward proxy provides for protocol-specific outbound traffic.\
For example, you might deploy a web proxy that enables client computers on the LAN to connect to websites and secure websites on the Internet. This is a forward proxy that services TCP ports 80 and 443 for outbound traffic.

The main benefit of a proxy is that client computers connect to a specified point on the perimeter network for web access. The proxy can be positioned within a DMZ. This provides for a degree of traffic management and security. In addition, most web proxy servers provide caching engines, whereby frequently requested web pages are retained on the proxy, negating the need to re-fetch those pages for subsequent requests.

A proxy server must understand the application it is servicing. For example, a web proxy must be able to parse and modify HTTP and HTTPS commands (and potentially HTML and scripts too). Some proxy servers are application-specific; others are multipurpose. A multipurpose proxy is one configured with filters for multiple protocol types, such as HTTP, FTP, and SMTP.

Classified as:-
- A non-transparent proxy means that the client must be configured with the proxy server address and port number to use it. The port on which the proxy server accepts client connections is often configured as port 8080.
- A transparent (or forced or intercepting) proxy intercepts client traffic without the client having to be reconfigured. A transparent proxy must be implemented on a switch or router or other inline network appliance.

### Reverse Proxy Servers
A reverse proxy server provides for protocol-specific inbound traffic. For security purposes, you might not want external hosts to be able to connect directly to application servers, such as web, email, and VoIP servers. Instead, you can deploy a reverse proxy on the network edge and configure it to listen for client requests from a public network (the Internet).

The proxy applies filtering rules and if accepted, it creates the appropriate request for an application server within a DMZ. In addition, some reverse proxy servers can handle application-specific load balancing, traffic encryption, and caching, reducing the overhead on the application servers. 

### Network Addrees Translation(NAT)
Network address translation (NAT) was devised as a way of freeing up scarce IP addresses for hosts needing Internet access.\
A private network will typically use a private addressing scheme to allocate IP addresses to host. These addresses can be drawn from one of the pools of addresses defined in RFC 1918 (tools.ietf.org/html/rfc1918) as non-routable over the Internet:
- 10.0.0.0 to 10.255.255.255 (Class A private address range).
- 172.16.0.0 to 172.31.255.255 (Class B private address range).
- 192.168.0.0 to 192.168.255.255 (Class C private address range).

A NAT gateway is a service that translates between the private addressing scheme used by hosts on the LAN and the public addressing scheme used by router, firewall, or proxy server on the network edge. NAT provides security in the sense that it can manage ingress and egress traffic at well-defined points on the network edge, but it is important to realize that it does not perform a filtering function.

Types of NAT
- Static and dynamic source NAT—perform 1:1 mappings between private ("inside local") network address and public ("inside global") addresses. These mappings can be static or dynamically assigned.
- Overloaded NAT/Network Address Port Translation (NAPT)/Port Address Translation (PAT)—provides a means for multiple private IP addresses to be mapped onto a single public address. For example, say two hosts (10.0.0.101 and 10.0.0.103) initiate a web connection at the same time. The NAPT service creates two new port mappings for these requests (10.0.0.101:60101 and 10.0.0.103:60103). It then substitutes the private IPs for the public IP and forwards the requests to the public Internet. It performs a reverse mapping on any traffic returned using those ports, inserting the original IP address and port number, and forwards the packets to the internal hosts.
![image](../images/network%20Appliances/nat-overloading.png)
- Destination NAT/port forwarding—uses the router's public address to publish a web service, but forwards incoming requests to a different IP. Port forwarding means that the router takes requests from the Internet for a particular application (say, HTTP/port 80) and sends them to a designated host and port in the DMZ or LAN.

### Virtual Firewalls
Virtual firewalls are usually deployed within data centers and cloud services. A virtual firewall can be implemented in three different ways:
- Hypervisor-based—this means that filtering functionality is built into the hypervisor or cloud provisioning tool. You can use the cloud's web app or application programming interface (API) to write access control lists (ACLs) for traffic arriving or leaving a virtual host or virtual network.
- Virtual appliance—this refers to deploying a vendor firewall appliance instance using virtualization, in the same way you might deploy a Windows or Linux guest OS.
- Multiple context—this refers to multiple virtual firewall instances running on a hardware firewall appliance. Each context has a separate interface and can perform a distinct filtering role.

While they can be deployed like "regular" firewalls for zone-based routing and filtering, virtual firewalls' most significant role is to support the east-west security and zero-trust microsegmentation design paradigms. They are able to inspect traffic as it passes from host-to-host or between virtual networks, rather than requiring that traffic be routed up to a firewall appliance and back.

# Network Security Monitoring
## Network-Based Intrusion Detection Systems
An intrusion detection system (IDS) is a means of using software tools to provide real-time analysis of either network traffic or system and application logs.

A network-based IDS (NIDS) captures traffic via a packet sniffer, referred to as a sensor. It analyzes the packets to identify malicious traffic and displays alerts to a console or dashboard.

A NIDS, such as Snort (snort.org), Suricata (https://suricata.io/), or Zeek/Bro (zeek.org) performs passive detection. When traffic is matched to a detection signature, it raises an alert or generates a log entry, but does not block the source host. This type of passive sensor does not slow down traffic and is undetectable by the attacker. It does not have an IP address on the monitored network segment.

A NIDS is used to identify and log hosts and applications and to detect attack signatures, password guessing attempts, port scans, worms, backdoor applications, malformed packets or sessions, and policy violations (ports or IP addresses that are not permitted, for instance).\
You can use analysis of the logs to tune firewall rulesets, remove or block suspect hosts and processes from the network, or deploy additional security controls to mitigate any threats you identify.

### TAPS and Port Mirrors
A TAP will usually output two streams to monitor a full-duplex link (one channel for upstream and one for downstream). Alternatively, there are aggregation TAPs, which rebuild the streams into a single channel, but these can drop frames under very heavy load.\
There are three main options for connecting a sensor to the appropriate point in the network:
- SPAN (switched port analyzer)/mirror port—this means that the sensor is attached to a specially configured port on the switch that receives copies of frames addressed to nominated access ports (or all the other ports). This method is not completely reliable. Frames with errors will not be mirrored and frames may be dropped under heavy load.
- Passive test access point (TAP)—this is a box with ports for incoming and outgoing network cabling and an inductor or optical splitter that physically copies the signal from the cabling to a monitor port. There are types for copper and fiber optic cabling. Unlike a SPAN, no logic decisions are made so the monitor port receives every frame—corrupt or malformed or not—and the copying is unaffected by load.
- Active TAP—this is a powered device that performs signal regeneration (again, there are copper and fiber variants), which may be necessary in some circumstances. Gigabit signaling over copper wire is too complex for a passive tap to monitor and some types of fiber links may be adversely affected by optical splitting. Because it performs an active function, the TAP becomes a point of failure for the links in the event of power loss. When deploying an active TAP, it is important to use a model with internal batteries or connect it to a UPS.

## Network-Based Intrusion Prevention Systems
An intrusion prevention system (IPS) can provide an active response to any network threats that it matches.

One typical preventive measure is to end the TCP session, sending a TCP reset packet to the attacking host. Another option is for the IPS to apply a temporary filter on the firewall to block the attacker's IP address (shunning). Other advanced measures include throttling bandwidth to attacking hosts, applying complex firewall filters, and even modifying suspect packets to render them harmless. Finally, the appliance may be able to run a script or third-party program to perform some other action not supported by the IPS software itself.

Some IPS provide inline, wire-speed antivirus scanning. Their rulesets can be configured to provide user content filtering, such as blocking URLs, applying keyword-sensitive block lists or allow lists, or applying time-based access restrictions

IPS appliances are positioned like firewalls at the border between two network zones. As with proxy servers, the appliances are "inline" with the network, meaning that all traffic passes through them (also making them a single point-of-failure if there is no fault tolerance mechanism). This means that they need to be able to cope with high bandwidths and process each packet very quickly to avoid slowing down the network.

### Signature-Based Detection
Signature-based detection (or pattern-matching) means that the engine is loaded with a database of attack patterns or signatures. If traffic matches a pattern, then the engine generates an incident.

The signatures and rules (often called plug-ins or feeds) powering intrusion detection need to be updated regularly to provide protection against the latest threat types. Commercial software requires a paid-for subscription to obtain the updates. It is important to ensure that the software is configured to update only from valid repositories, ideally using a secure connection method, such as HTTPS.

### Behavior and  Anomaly-Based detection
Behavioral-based detection means that the engine is trained to recognize baseline "normal" traffic or events. Anything that deviates from this baseline (outside a defined level of tolerance) generates an incident. The idea is that the software will be able to identify zero day attacks, insider threats, and other malicious activity for which there is no signature.

This type of detection was provided by network behavior and anomaly detection (NBAD) products. An NBAD engine uses heuristics to generate a statistical model of what baseline normal traffic looks like. It may develop several profiles to model network use at different times of the day. This means that the system generates false positive and false negatives until it has had time to improve its statistical model of what is "normal." A false positive is where legitimate behavior generates an alert, while a false negative is where malicious activity is not alerted.

There are two general classes of behavior-based detection products that utilize machine learning:
- User and entity behavior analytics (UEBA)—these products scan indicators from multiple intrusion detection and log sources to identify anomalies. They are often integrated with security information and event management (SIEM) platforms.
- Network traffic analysis (NTA)—these products are closer to IDS and NBAD in that they apply analysis techniques only to network streams, rather than multiple network and log data sources.

### Next-Generation Firewalls and Content Filters
The original next-generation firewall (NGFW) was released as far back as 2010 by Palo Alto. This product combined application-aware filtering with user account-based filtering and the ability to act as an intrusion prevention system (IPS). \
Subsequent firewall generations have added capabilities such as cloud inspection and combined features of different security technologies.
- Unified threat management (UTM) refers to a security product that centralizes many types of security controls—firewall, anti-malware, network intrusion prevention, spam filtering, content filtering, data loss prevention, VPN, cloud access gateway—into a single appliance. This means that you can monitor and manage the controls from a single console. 
- Content/URL filter - is designed to apply a number of user-focused filtering rules, such as blocking uniform resource locators (URLs) that appear on content block lists or applying time-based restrictions to browsing. Content filters are now usually implemented as a class of product called a secure web gateway (SWG). As well as filtering, a SWG performs threat analysis and often integrates the functionality of data loss prevention (DLP) and cloud access security brokers (CASB) to protect against the full range of unauthorized egress threats, including malware command and control and data exfiltration.

### Host-Based Intrusion Detection Systems
A host-based IDS (HIDS) captures information from a single host, such as a server, router, or firewall.

The core ability is to capture and analyze log files, but more sophisticated systems can also monitor OS kernel files, monitor ports and network interfaces, and process data and logs generated by specific applications, such as HTTP or FTP.

HIDS software produces similar output to an anti-malware scanner. If the software detects a threat, it may just log the event or display an alert. The log should show you which process initiated the event and what resources on the host were affected. You can use the log to investigate whether the suspect process is authorized or should be removed from the host.

### Web Application Firewalls(WAF)
It is designed specifically to protect software running on web servers and their back-end databases from code injection and DoS attacks. 

WAFs use application-aware processing rules to filter traffic and perform application-specific intrusion detection. The WAF can be programmed with signatures of known attacks and use pattern matching to block requests containing suspect code. The output from a WAF will be written to a log, which you can inspect to determine what threats the web application might be subject to.

Some examples of WAF products include:
- ModSecurity (modsecurity.org) is an open source (sponsored by Trustwave) WAF for Apache, nginx, and IIS.
- NAXSI (github.com/nbs-system/naxsi) is an open source module for the nginx web server software.
- Imperva (imperva.com) is a commercial web security offering with a particular focus on data centers. Imperva markets WAF, DDoS, and database security through its SecureSphere appliance.

# Security Information and Event Management(SIEM)
Software designed to assist with managing security data inputs and provide reporting and alerting.  The core function of a SIEM tool is to aggregate traffic data and logs. In addition to logs from Windows and Linux-based hosts, this could include switches, routers, firewalls, IDS sensors, vulnerability scanners, malware scanners, data loss prevention (DLP) systems, and databases.

## Monitoring Services
Security assessments and incident response both require real-time monitoring of host and network status indicators plus audit information.

#### Packet Capture
Data captured from network sensors/sniffers plus netflow sources provides both summary statistics about bandwidth and protocol usage and the opportunity for detailed frame analysis.

#### Network Monitors
As distinct from network traffic monitoring, a network monitor collects data about network appliances, such as switches, access points, routers, firewalls, and servers. This is used to monitor load status for CPU/memory, state tables, disk capacity, fan speeds/temperature, network link utilization/error statistics, and so on. Another important function is a heartbeat message to indicate availability. This data might be collected using the Simple Network Management Protocol (SNMP) or a proprietary management system. As well as supporting availability, network monitoring might reveal unusual conditions that could point to some kind of attack.

#### Logs
Logs are one of the most valuable sources of security information. A system log can be used to diagnose availability issues. A security log can record both authorized and unauthorized uses of a resource or privilege. Logs function both as an audit trail of actions and (if monitored regularly) provide a warning of intrusion attempts. Log review is a critical part of security assurance. Only referring to the logs following a major incident is missing the opportunity to identify threats and vulnerabilities early and to respond proactively. 
- Collection - Three main types:-
    - Agent-based - with this approach, you must install an agent service on each host. As events occur on the host, logging data is filtered, aggregated, and normalized at the host, then sent to the SIEM server for analysis and storage.
    - Listener/collector—rather than installing an agent, hosts can be configured to push updates to the SIEM server using a protocol such as syslog or SNMP. A process runs on the management server to parse and normalize each log/monitoring source.
    - Sensor—as well as log data, the SIEM might collect packet captures and traffic flow data from sniffers. 
- Aggregation -refers to normalizing data from different sources so that it is consistent and searchable.  SIEM software features connectors or plug-ins to interpret (or parse) data from distinct types of systems and to account for differences between vendor implementations. Usually parsing will be carried out using regular expressions tailored to each log file format to identify attributes and content that can be mapped to standard fields in the SIEM's reporting and analysis tools. Another important function is to normalize date/time zone differences to a single timeline.

### Analysis and Report review
- User and entity behavior analytics
- Sentiment analysis
- Security orchestration,Automation and response


### File manipulation
> cat -n access.log access2.log

> cat -n access.log access2.log > access_cat.log

> tail -n 20 /var/log/messages

> head -n 20 /var/log/messages

> logger -n 10.1.0.242 `hostname` up

### GREP and REGEX operations
