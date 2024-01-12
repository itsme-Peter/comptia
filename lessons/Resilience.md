# CyberSecurity Resilience

### Objectives
- Resundancy Strategies
- Backup Strategies
- Resiliency Strategies

# Redndancy Strategies

## High Availability
One of the key properties of a resilient system is high availability. Availability is the percentage of time that the system is online, measured over the defined period, typically one year. The corollary of availability is downtime, or the amount of time for which the system is unavailable. The maximum tolerable downtime (MTD) metric expresses the availability requirement for a particular business function. 
- Scalability and elasticity 
- Fault Tolerance and Redundancy 

## Power Redundancy
- Dual Power Supplies
- Managed Poweer Distribution Units(PDUs)
- Battery Backups and Uninterruptible Power Supplies(UPSs)
- Generators

## Network Redundancy
- Network interface Card(NIC) Teamaing
- Switching and Routing
- Load Balancers

## Disk Redundancy
Disk redundancy ensures that a server can continue to operate if one, or possibly more, storage devices fail.

- Redundant Array of Indepedent Disks(RAID) - 
- Multipath

## Geographical Redundancy and Replication
Data replication is technology that maintains exact copies of data at more than one location. RAID mirroring and parity implements types of replication between local storage devices. Data replication can be applied in many other contexts:
- 
    - Storage Area Network(SAN)
    - Database
    - Virtual Machine(VM)

- Geographical Dispersal
- Asynchronous and Synchronous Relication
- On-Premise versus Cloud

# Backup Startegies

## Backups and Retention Policy
- Short Term
- Long Term

### Backup Types
- Full - all selected file/directories
- Incrimental - New files, as well as files modified since the last backup
- Diffrential - All new and modified files since the last full

## Snapshots and Images
A snapshot is a point-in-time copy of data maintained by the file system. A backup program can use the snapshot rather than the live data to perform the backup. In Windows, snapshots are provided for on NTFS volumes by the Volume Shadow Copy Service (VSS). They are also supported on Sun's ZFS file system, and under some distributions of Linux.

An image backup is made by duplicating an OS installation.Imaging allows the system to be redeployed quickly, without having to reinstall third-party software, patches, and configuration settings.

## Backup Storage Issues
- Offsite Storage 
- Online versus Offline Backups

## Backup Media Types
- Disk
- Network Attached Storage(NAT)
- Tape
- Storage Area Network(SAN) and Cloud

## Restoration Order
- power delivery systems
- switch and routing infrastructure and routing appliances
- Network security applicances(firewalls,IDS,proxies)
- Criticak network servers(DHCP,DNS,NTP)
- Backend and middleware(databases&business logic)
- Front-end applications
- Client workstations and client browser access

## Nonpersistence
An environment that is static in terms of processing function.\
Mechanisms for ensuring nonpersistence:
- Snapshot/revert to known state
- Rollback to known configuration
- Live boot media

- Master image - 
- Automated build from template

# Resiliency Strategies

## Configuration Management
Configuration management ensures that each component of ICT infrastructure is in a trusted state that has not diverged from its documented properties. Change control and change management reduce the risk that changes to these components could cause service disruption. 

## Asset management
Tracks org systems,components and objects of value in inventory.

- Asset Identification - using barcode or radio frequency ID(RFID) tags.
- Standard Naming Conventions - The naming strategy should allow administrators to identify the type and function of any particular resource or location at any point

- Internet Protocol(IP) Schema - IP address management (IPAM) software suites can be used to monitor IP usage. The division of the IP address space into subnets should be carefully planned and documented in an Internet Protocol (IP) schema. 

## Change Control and Change Management
- Change Control - process used to requet and approe changes in a planned and conrolled way. The need/reasons for change is captured in a request for change(RFC) document
- Change Management - 

## Site Resiliency 
It ensures that once the main site fails another can take over
- Hot site - ready to failover immediately and its loaded with live data
- Warm site - required to be loaded with latest data
- Cold site - takes longer and installation of requirement needs to be done

## Diversity and Defense in Depth
Layered security is typically seen as improving cybersecurity resiliency because it provides defense in depth.\

#### Technology and Control Diversity
Technology diversity refers to environments that are a mix of operating systems, applications, coding languages, virtualization solutions, and so on. Control diversity means that the layers of controls should combine different classes of technical and administrative controls with the range of control functions: prevent, detect, correct, and deter.

#### Vendor Diversity
Vendor diversity means that security controls are sourced from multiple suppliers. A single vendor solution is a tempting choice for many organizations, as it provides interoperability and can reduce training and support costs

####  Crypto Diversity 
- Cryptograhic algos(ChaCha over AES)
- Blockchain-based Identity and Access Management(IAM)

## Deception and Disruption Strategies
- Active defense - engagement with advesary. Can be done thru deployment of decoy assets.
- Honeypts,honeynets and honeyfiles
- Disruption Strategies
    - bogus DNS entries
    - web server with multiple fake directories
    - port triggering
    - DNS sinkhole to route traffic for analysis