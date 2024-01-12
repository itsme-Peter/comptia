# Host Security Solutions

### Objectives
- Implement secure firmware.
- Implement endpoint security.
- Explain embedded system security implications.

# Secure Firmware

## Hardware Root of Trust
A hardware Root of Trust (RoT) or trust anchor is a secure subsystem that is able to provide attestation. Attestation means that a statement made by the system can be trusted by the receiver.The hardware root of trust is used to scan the boot metrics and OS files to verify their signatures, then it signs the report.

The RoT is usually established by a type of cryptoprocessor called a trusted platform module (TPM). TPM is a specification for hardware-based storage of encryption keys, hashed passwords, and other user and platform identification information. The TPM is implemented either as part of the chipset or as an embedded function of the CPU

Each TPM is hard-coded with a unique, unchangeable asymmetric private key called the endorsement key. This endorsement key is used to create various other types of subkeys used in key storage, signature, and encryption operations.

The TPM also supports the concept of an owner, usually identified by a password (though this is not mandatory). Anyone with administrative control over the setup program can take ownership of the TPM, which destroys and then regenerates its subkeys. A TPM can be managed in Windows via the tpm.msc console or through group policy. On an enterprise network, provisioning keys to the TPM might be centrally managed via the Key Management Interoperability Protocol (KMIP).

## Boot Integrity
Most PCs implement the unified extensible firmware interface (UEFI). UEFI provides code that allows the host to boot to an OS. UEFI can enforce a number of boot integrity checks.

- Secure Boot\
Secure boot is designed to prevent a computer from being hijacked by a malicious OS. UEFI is configured with digital certificates from valid OS vendors. The system firmware checks the operating system boot loader and kernel using the stored certificate to ensure that it has been digitally signed by the OS vendor. This prevents a boot loader or kernel that has been changed by malware (or an OS installed without authorization) from being used.

- Measured Boot\
A trusted or measured boot process uses platform configuration registers (PCRs) in the TPM at each stage in the boot process to check whether hashes of key system state data (boot firmware, boot loader, OS kernel, and critical drivers) have changed. This does not usually prevent boot, but it will record the presence of unsigned kernel-level code.

- Boot Attestation\
Boot attestation is the capability to transmit a boot log report signed by the TPM via a trusted process to a remote server, such as a network access control server. The boot log can be analyzed for signs of compromise, such as the presence of unsigned drivers. The host can be prevented from accessing the network if it does not meet the required health policy or if no attestation report is received.

## Disk Encryption
Full disk encryption (FDE) means that the entire contents of the drive (or volume), including system files and folders, are encrypted. 

One of the drawbacks of FDE is that, because the OS performs the cryptographic operations, performance is reduced. This issue is mitigated by self-encrypting drives (SED), where the cryptographic operations are performed by the drive controller. The SED uses a symmetric data/media encryption key (DEK/MEK) for bulk encryption and stores the DEK securely by encrypting it with an asymmetric key pair called either the authentication key (AK) or key encryption key (KEK). Use of the AK is authenticated by the user password. This means that the user password can be changed without having to decrypt and re-encrypt the drive. Early types of SEDs used proprietary mechanisms, but many vendors now develop to the Opal Storage Specification (nvmexpress.org/wp-content/uploads/TCGandNVMe_Joint_White_Paper-TCG_Storage_Opal_and_NVMe_FINAL.pdf), developed by the Trusted Computing Group (TCG).

## USB and Flash Drive Security
Exploiting the firmware of external storage devices, such as USB flash drives (and potentially any other type of firmware), presents adversaries with an incredible toolkit. The firmware can be reprogrammed to make the device look like another device class, such as a keyboard. In this case it could then be used to inject a series of keystrokes upon an attachment or work as a keylogger. The device could also be programmed to act like a network device and corrupt name resolution, redirecting the user to malicious websites.

## Third Party Risk Management
Establishing a trusted supply chain for computer equipment essentially means denying malicious actors the time or resources to modify the assets being supplied
- Vendor—this means a supplier of commodity goods and services, possibly with some level of customization and direct support.
- Business partner—this implies a closer relationship where two companies share quite closely aligned goals and marketing opportunities.

## End of Life Systems
When a manufacturer discontinues sales of a product, it enters an end of life (EOL) phase in which support and availability of spares and updates become more limited. An end of service life (EOSL) system is one that is no longer supported by its developer or vendor. EOSL products no longer receive security updates and so represent a critical vulnerability if any remain in active use.

## Organizational Security Agreements
- Memorandum of understanding (MOU)—A preliminary or exploratory agreement to express an intent to work together.
- Business partnership agreement (BPA)—While there are many ways of establishing business partnerships, the most common model in IT is the partner agreements that large IT companies (such as Microsoft and Cisco) set up with resellers and solution providers.
- Nondisclosure agreement (NDA)—Legal basis for protecting information assets. NDAs are used between companies and employees, between companies and contractors, and between two companies
- Service level agreement (SLA)—A contractual agreement setting out the detailed terms under which a service is provided.
- Measurement systems analysis (MSA)—quality management processes, such as Six Sigma, make use of quantified analysis methods to determine the effectiveness of a system. 

# Endpoint Security
## Hardening
The process of putting an operating system or application in a secure configuration is called hardening.
- Unsued network interfaces should be removed
- Services not used should be removed
- Application service ports(unused) should be blocked
- Data backups + encryption

## Baseline Configuration and Registry Settings
Baseline deviation reporting means testing the actual configuration of hosts to ensure that their configuration settings match the baseline template. 

In Windows, configuration settings are stored in the registry. On a Windows domain network, each domain-joined computer will receive policy settings from one or more group policy objects (GPOs). These policy settings are applied to the registry each time a computer boots. Where hosts are centrally managed and running only authorized apps and services, there should be relatively little reason for security-relevant registry values to change. Rights to modify the registry should only be issued to user and service accounts on a least privilege basis. A host-based intrusion detection system can be configured to alert suspicious registry events

## Endpoint Protection
Another crucial step in hardening is to configure endpoint protection for automatic detection and prevention of malware threats.

- Antivirus(A-V)/Anti-Malware\
The first generation of antivirus (A-V) software is characterized by signature-based detection and prevention of known viruses. An "A-V" product will now perform generalized malware detection, meaning not just viruses and worms, but also Trojans, spyware, PUPs, cryptojackers, and so on. While A-V software remains important, signature-based detection is widely recognized as being insufficient for the prevention of data breaches.

- Host-Based Intrusion Detection/Prevention (HIDS/HIPS)\
Host-based intrusion detection systems (HIDS) provide threat detection via log and file system monitoring. HIDS come in many different forms with different capabilities, some of them preventative (HIPS). File system integrity monitoring uses signatures to detect whether a managed file image—such as an OS system file, driver, or application executable—has changed. Products may also monitor ports and network interfaces, and process data and logs generated by specific applications, such as HTTP or FTP.

- Endpoint Protection Platform (EPP)\
An endpoint protection platform (EPP) is a single agent performing multiple security tasks, including malware/intrusion detection and prevention, but also other security features, such as a host firewall, web content filtering/secure search and browsing, and file/message encryption.

- Data Loss Prevention(DLP)\
Many EPPs include a data loss prevention (DLP) agent. This is configured with policies to identify privileged files and strings that should be kept private or confidential, such as credit card numbers. The agent enforces the policy to prevent data from being copied or attached to a message without authorization

- Endpoint Protection Deployment\
    - Configure the management system to push the agent software and any updates to all desktops. This will require configuring permissions and firewall settings.
    - Assign hosts to appropriate groups for policy assignment. 
    - Test the different host group configuration settings to ensure that the expected range of threats is detected.
    - Use a monitoring dashboard to verify status across all network hosts.

## Next-Generation Endpoint Protection
Where EPP provides mostly signature-based detection and prevention, next-generation endpoint protection with automated response is focused on logging of endpoint observables and indicators combined with behavioral- and anomaly-based analysis.

### Endpoint Detection and Response(EDR)
An endpoint detection and response (EDR) product's aim is not to prevent initial execution, but to provide real-time and historical visibility into the compromise, contain the malware within a single host, and facilitate remediation of the host to its original state. 

### Next-Generation Firewall Integration
An analytics-driven next-gen antivirus product is likely to combine with the perimeter and zonal security offered by next-gen firewalls. For example, detecting a threat on an endpoint could automate a firewall policy to block the covert channel at the perimeter, isolate the endpoint, and mitigate risks of the malware using lateral movement between hosts.

## Antivirus Response
An on-access antivirus scanner or intrusion prevention system works by identifying when processes or scripts are executed and intercepting (or hooking) the call to scan the code first. If the code matches a signature of known malware or exhibits malware-like behavior that matches a heuristic profile, the scanner will prevent execution and attempt to take the configured action on the host file (clean, quarantine, erase, and so on). 

- Advanced Malware Tools\
Malware is often able to evade detection by automated scanners. Analysis of SIEM and intrusion detection logs might reveal suspicious network connections, or a user may observe unexplained activity or behavior on a host. When you identify symptoms such as these, but the AV scanner or EPP agent does not report an infection, you will need to analyze the host for malware using advanced tools.

There is a plethora of advanced analysis and detection utilities, but the starting point for most technicians is Sysinternals ( https://learn.microsoft.com/en-us/sysinternals/ ).

- Sandboxing\
Sandboxing is a technique that isolates an untrusted host or app in a segregated environment to conduct tests. Sandbox environments intentionally limit interfaces with the host environment. The analysis of files sent to a sandbox can include determining whether the file is malicious, how it might have affected certain systems if run outside of the sandbox, and what dependencies it might have with external files and hosts. Sandboxes offer more than traditional anti-malware solutions because you can apply a variety of different environments to the sandbox instead of just relying on how the malware might exist in your current configuration.

# Embedded System Security Implications
An embedded system is a complete computer system that is designed to perform a specific, dedicated function. These systems can be as contained as a microcontroller in an intravenous drip-rate meter or as large and complex as the network of control devices managing a water treatment plant. \
Embedded systems can be characterized as static environments.
- Cost,Power and Computing Constraints\
Embedded systems are usually constrained in terms of processor capability (cores and speed), system memory, and persistent storage. Cost is an important factor\
Many embedded devices are battery-powered, and may need to run for years without having to replace the cells. This means that processing must be kept to the minimum possible level.

- Crypto,Authentication and Implied Trust Constraints\
As embedded systems become more accessible via those networks, however, they need to use cryptoprocessors to ensure confidentiality, integrity, and availability. This is prompting the development of ciphers that do not require such large processing resources.\
On PC hardware, a root of trust is established at the hardware level by a TPM. Without this explicit trust anchor, a network has to use an implied trust model. Implied trust means that every device that has been added to the network is trusted, on the assumption that it was added and continues to be operated by a legitimate administrator. Until there is widespread adoption of embedded TPM, embedded networks have to rely on the perimeter security model.

- Network and Range Constraints\
Networks for embedded systems emphasize power-efficient transfer of small amounts of data with a high degree of reliability and low latency.\
Minimizing compute functions also has an impact on choices for network connectivity. 

## Logic Controllers for Embedded Systems
Embedded systems are normally based on firmware running on a programmable logic controller (PLC). These PLCs are built from different hardware and OS components than some desktop PCs. 
- System on Chip(Soc)\
System on chip (SoC) is a design where all these processors, controllers, and devices are provided on a single processor die (or chip). This type of packaging saves space and is usually power efficient, and so is very commonly used with embedded systems.\
Raspberry Pi (raspberrypi.org) and Arduino (arduino.cc) are examples of SoC boards
- Field Programmable Gate Array (FPGA)\
A field programmable gate array (FPGA) is a type of controller that solves this problem. The structure of the controller is not fully set at the time of manufacture. The end customer can configure the programming logic of the device to run a specific application.
- Real-Time Operating Systems\
Embedded systems typically cannot tolerate reboots or crashes and must have response times that are predictable to within microsecond tolerances. Consequently, these systems often use differently engineered platforms called real-time operating systems (RTOS). An RTOS should be designed to have as small an attack surface as possible. An RTOS is still susceptible to CVEs and exploits, however.

## Embedded Systems Communications Considerations
- Operational Technology(OT) Networks\
A cabled network for industrial applications is referred to as an operational technology (OT) network. These typically use either serial data protocols or industrial Ethernet. Industrial Ethernet is optimized for real-time, deterministic transfers. Such networks might use vendor-developed data link and networking protocols, as well as specialist application protocols

- Cellular Networks\
A cellular network enables long-distance communication over the same system that supports mobile and smartphones. This is also called baseband radio, after the baseband processor that performs the function of a cellular modem. There are several baseband radio technologies:
    - Narrowband-IoT(NB-IoT)—this refers to a low-power version of the Long Term Evolution (LTE) or 4G cellular standard. The signal occupies less bandwidth than regular cellular. This means that data rates are limited (20-100 kbps), but most sensors need to send small packets with low latency, rather than making large data transfers. Narrowband also has greater penetrating power, making it more suitable for use in inaccessible locations, such as tunnels or deep within buildings, where ordinary cellular connectivity would be impossible
    - LTE Machine Type Communication (LTE-M)—this is another low-power system, but supports higher bandwidth (up to about 1 Mbps)

- Z-Wave and Zigbee\
Z-Wave and Zigbee are wireless communications protocols used primarily for home automation. Both create a mesh network topology, using low-energy radio waves to communicate from one appliance to another.\
In Z-Wave, devices can be configured to work as repeaters to extend the network but there is a limit of four "hops" between a controller device and an endpoint. Z-Wave uses ~900 Mhz frequencies.\
Zigbee has similar uses to Z-Wave and is an open source competitor technology to it. The Zigbee Alliance operates certification programs for its various technologies and standards. Zigbee uses the 2.4 GHz frequency band. This higher frequency allows more data bandwidth at the expense of range compared to Z-Wave and the greater risk of interference from other 2.4 GHz radio communications. Zigbee supports more overall devices within a single network and there is no hop limit for communication between devices.\
Both Z-Wave and Zigbee have communications encryption. The main threats are from re-pairing attacks and from rogue devices. A re-pairing attack allows a threat actor to discover the network key by forcing a device off the network, causing it to try to re-connect (checkpoint.com/press/2020/the-dark-side-of-smart-lighting-check-point-research-shows-how-business-and-home-networks-can-be-hacked-from-a-lightbulb). If the user connects a rogue device to the network, the system depends on application-level security to prevent the device from compromising higher value targets, such as a smart hub, alarm, or door entry mechanism.

## Industrial Control Systems(ICSs)
Industrial processes also prioritize availability and integrity over confidentiality—reversing the CIA triad as the AIC triad.

### Workflows and automation systems
These systems control machinery used in critical infrastructure, like power suppliers, water suppliers, health services, telecommunications, and national security services. An ICS that manages process automation within a single site is usually referred to as a distributed control system (DCS).

Output and configuration of a PLC is performed by one or more human-machine interfaces (HMIs). An HMI might be a local control panel or software running on a computing host. PLCs are connected within a control loop, and the whole process automation system can be governed by a control server. Another important concept is the data historian, which is a database of all the information generated by the control loop.

### Supervisory Control and Data Acquisition(SCADA)
A supervisory control and data acquisition (SCADA) system takes the place of a control server in large-scale, multiple-site ICSs. SCADA typically run as software on ordinary computers, gathering data from and managing plant devices and equipment with embedded PLCs, referred to as field devices. SCADA typically use WAN communications, such as cellular or satellite, to link the SCADA server to field devices.

### Internet of Things(IOT)
is used to describe a global network of appliances and personal devices that have been equipped with sensors, software, and network connectivity. This compute functionality allows these objects to communicate and pass data between themselves and other traditional systems like computer servers. This is often referred to as Machine to Machine (M2M) communication. Each “thing” is identified with some form of unique serial number or code embedded within its own operating or control system and is able to inter-operate within the existing Internet infrastructure either directly or via an intermediary. An IoT network will generally use the following types of components:
- Hub/Control System
- Smart Devices
- Wearables
- Sensors

## Specialized Systems For Facility Automation
A specialized system refers to the use of embedded systems and/or IoT devices for a specific purpose or application.

### Building Automation System(BAS)
BAS for offices and data centers ("smart buildings") can include physical access control systems, but also heating, ventilation, and air conditioning (HVAC), fire control, power and lighting, and elevators and escalators. These subsystems are implemented by PLCs and various types of sensors that measure temperature, air pressure, humidity, room occupancy, and so on. Some typical vulnerabilities that affect these systems include:
- Process and Memory vulnerabilities
- Use of plaintext credentials or crypto keys within application code
- Code injection via the graphical web application interfaces used to configure and monitor systems

### Smart Meters
A smart meter provides continually updating reports of electricity, gas, or water usage to the supplier, reducing the need for manual inspections. Most meters use cellular data for communication back to the supplier, and an IoT protocol, such as ZigBee, for integration with smart appliances.  

### Surveillance Systems
A physical access control system (PACS) is a network of monitored locks, intruder alarms, and video surveillance. 

## Specialized Systems in IT
There are also specialized systems installed within office networks, such as printer and Voice over IP (VoIP) equipment. These systems must not be overlooked by security monitoring procedures.

### Multifunction Printers(MFPs)
Most modern print devices, scanners, and fax machines have hard drives and sophisticated firmware, allowing their use without attachment to a computer and over a network. 

Often these print/scan/fax functions are performed by single devices, referred to as multifunction printers (MFPs). 

Unless they have been securely deleted, images and documents are frequently recoverable from all of these machines. Some of the more feature-rich, networked printers and MFPs can also be used as a pivot point to attack the rest of the network. These machines also have their own firmware that must be kept patched 
and updated.

### Voice over IP(VoIP)
Types of embedded systems are used to implement both Voice over IP (VoIP) endpoints and media gateways. Endpoints can be individual handsets or conferencing units. A media gateway might use a separate firmware/OS to implement integration with telephone and cellular networks.

## Security for Embedded Systems
- Network Segmentation
- Wrappers
- Firmware Code Control and Inability to Patch
