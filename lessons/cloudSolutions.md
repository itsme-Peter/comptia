# Secure Cloud Solutions

### Objectives
- Secure Cloud and Virtualization Services
- Cloud Security Solutions
- Infrastructure an code Concepts

# Cloud and Virtualization Services
## Cloud Deployment Models
It classifies how the service is owned and provisioned.
- Public(multi-tenant) - a service offered over the Internet by cloud service providers (CSPs) to cloud consumers. With this model, businesses can offer subscriptions or pay-as-you-go financing, while at the same time providing lower-tier services free of charge.
- Hosted private -hosted by 3rd party for exclusive use by organisation
- Private - private to and completely owned by org
- Community - this is where several organizations share the costs of either a hosted private or fully private cloud.
- Hybrid - combination of some

## Cloud Service Models
cloud services are often differentiated on the level of complexity and pre-configuration provided. These models are referred to as something or anything as a service (XaaS). 
- Infrastructure as a Service(IaaS) -  is a means of provisioning IT resources such as servers, load balancers, and storage area network (SAN) components quickly. Rather than purchase these components and the Internet links they require, you rent them on an as-needed basis from the service provider's data center.
- Software as a Service(SaaS) - provisioning software applications. Rather than purchasing software licenses for a given number of seats, a business would access software hosted on a supplier's servers on a pay-as-you-go or lease arrangement (on-demand). Virtual infrastructure allows developers to provision on-demand applications much more quickly than previously. The applications can be developed and tested in the cloud without the need to test and deploy on client computers. 
- Platform as a Sevice(PaaS) - provides resources somewhere between SaaS and IaaS. A typical PaaS solution would provide servers and storage network infrastructure (as per IaaS) but also provide a multi-tier web application/database platform on top. This platform could be based on Oracle or MS SQL or PHP and MySQL.

## Security as a Service
The breadth of technologies requiring specialist security knowledge and configuration makes it likely that companies will need to depend on third-party support at some point. You can classify such support in three general "tiers":
- Consultaints - the experience and perspective of a third-party professional can be hugely useful in improving security awareness and capabilities in any type of organization (small to large). 

- Managed Security Services Provider(MSSP) - a means of fully outsourcing responsibility for information assurance to a third party. This type of solution is expensive but can be a good fit for a SMB that has experienced rapid growth and has no in-house security capability. Of course, this type of outsourcing places a huge amount of trust in the MSSP. Maintaining effective oversight of the MSSP requires a good degree of internal security awareness and expertise. 

- Security as a Service(SECaaS) - can mean lots of different things, but is typically distinguished from an MSSP as being a means of implementing a particular security control, such as virus scanning or SIEM-like functionality, in the cloud. 

## Virtualization Technologies and Hypervisor
Virtualization means that multiple operating systems can be installed and run simultaneously on a single computer. A virtual platform requires at least three components:
- Host hardware - the platform that will host the virtual environment. 
- Hypervisor/Virtual Machine Monitor(VMM) - manages the virtual machine environment and facilitates interaction with the computer hardware and network.
- Guest operating systems, Virtual Machines (VM), or instances—operating systems installed under the virtual environment.

In a guest OS (or host-based) system, the hypervisor application (known as a Type II hypervisor) is itself installed onto a host operating system. Examples of host-based hypervisors include VMware Workstation, Oracle Virtual Box, and Parallels Workstation. The hypervisor software must support the host OS.

A bare metal virtual platform means that the hypervisor (Type I hypervisor) is installed directly onto the computer and manages access to the host hardware without going through a host OS. Examples include VMware ESXi Server, Microsoft's Hyper-V, and Citrix's XEN Server. The hardware needs only support the base system requirements for the hypervisor plus resources for the type and number of guest OSes that will be installed.

## Virtual Desktop Infrastructure(VDI), Environment, Thin clients
Virtual desktop infrastructure (VDI) refers to using a VM as a means of provisioning corporate desktops. Computers are replaced by low spec low power thin client computers. \
When the thin client starts, it boots a minimal OS, allowing the user to log on to a VM stored on the company server infrastructure using some sort of remote protocol.

All application processing and data storage in the virtual desktop environment (VDE) or workspace is performed by the server. The thin client computer must only be powerful enough to display the screen image, play audio, and transfer mouse, key commands and video, and audio information over the network. All data is stored on the server, so it is easier to back up and the desktop VMs are easier to support and troubleshoot. They are better "locked" against unsecure user practices because any changes to the VM can easily be overwritten from the template image. With VDI, it is also easier for a company to completely offload their IT infrastructure to a third-party services company.

## Application Virtualization and Container virtualization
Rather than run the whole client desktop as a virtual platform, the client either accesses an application hosted on a server or streams the application from the server to the client for local processing.\
Most application virtualization solutions are based on Citrix XenApp (formerly MetaFrame/Presentation Server), though Microsoft has developed an App-V product with its Windows Server range and VMware has the ThinApp product. These solution types are now often used with HTML5 remote desktop apps, referred to as "clientless" because users can access them through ordinary web browser software.

Container Virtualization.\
It enforces resource separation at the OS level, defining CPU and memory resources all run through the native OS kernel.These containers may run slightly different OS distributions but cannot run guest OSes of different types (you could not run Windows or Ubuntu in a RedHat Linux container, for instance). Alternatively, the containers might run separate application processes, in which case the variables and libraries required by the application process are added to the container.

## VM Escape Protection
VM escaping - An attack where malware running in a VM is able to interact directly with the hypervisor or host kernel.\
The malware must identify that it is running in a virtual environment, which is usually simple to do. One means of doing so is through a timing attack.
The classic timing attack is to send multiple usernames to an authentication server and measure the server response times. An invalid username will usually be rejected very quickly, but a valid one will take longer (while the authentication server checks the password). The attacker is able to harvest valid usernames.

Malware can use a timing attack within a guest OS to detect whether it is running in a VM(Certain operations take distinct amount of time compared to a real environment) combined with other signatures.

Next step is compromising the hyperisor.\
One serious implication of VM escaping is where virtualization is used for hosted applications. If you have a hosted web server, apart from trusting the hosting provider with your data, you have no idea what other applications might be running in other customers' VMs. For example, consider a scenario where you have an e-commerce web server installed on a virtual server leased from an ISP. If a third-party installs another guest OS with malware that can subvert the virtual server's hypervisor, they might be able to gain access to your server or to data held in the memory of the physical server. Having compromised the hypervisor, they could make a copy of your server image and download it to any location. This would allow the attacker to steal any unencrypted data held on the e-commerce server. Even worse, it could conceivably allow them to steal encrypted data, by obtaining the private encryption keys stored on the server or by sniffing unencrypted data or a data encryption key from the physical server's memory.

It is imperative to monitor security bulletins for the hypervisor software that you operate and to install patches and updates promptly. You should also design the VM architecture carefully so that the placement of VMs running different types of applications with different security requirements does not raise unnecessary risks.

Preventing VM escaping is dependent on the virtualization vendor identifying security vulnerabilities in the hypervisor and on these being patched. The impact of VM escaping can be reduced by using effective service design and network placement when deploying VMs

## VM Sprawl Avoidance
VM Sprawl - Configuration vulnerability where provisioning and deprovisioning of virtual assets is not properly authorized and monitored.\
Each VM needs to be installed with its own security software suite to protect against malware and intrusion attempts. Each guest must also have a patch management process. This might mean installing updates locally or replacing the guest instance from an updated VM template image.

# Cloud Security Solutions
## Cloud Security Intergration and Auditing
Cloud-based services must be integrated within regular security policies and procedures and audited for compliance. Where indicators of on-premises attacks are found in local application logs and network traffic, indicators of cloud-based attacks are found in API logs and metrics.\
The source of this data is the cloud service provider (CSP). Accessing this auditing information in real time may be difficult, depending on the cloud service type. There are many cloud-based SIEM solutions that can perform this collection, aggregation, and correlation of security data from both on-premises and cloud-based networks and instances.

Where critical tasks are the responsibility of the service provider, you should try to ensure that there is a reporting mechanism to show that these tasks are being completed, that their disaster recovery plans are effective, and so on.\
You must also consider the risk of insider threat, where the insiders are administrators working for the service provider. Without effective security mechanisms such as separation of duties and quorum authentication (also known as M of N access control), it is highly likely that they would be able to gain privileged access to your data

## Cloud Security Controls
Clouds use the same types of security controls as on-premises networks, including identity and access management (IAM), endpoint protection (for virtual instances), resource policies to govern access to data and services, firewalls to filter traffic between hosts, and logging to provide an audit function.

Most CSPs will provide these security controls as native functionality of the cloud platform. Google's firewall service is an example of this type of cloud-native control (cloud.google.com/firewalls). The controls can be deployed and configured using either the CSP's web console, or programmatically via a command line interface (CLI) or application programming interface (API). A third-party solution would typically be installed as a virtual instance within the cloud. For example, you might prefer to run a third-party next-generation firewall. This can be configured as an appliance and deployed to the cloud. The virtual network architecture can be defined so that this appliance instance is able to inspect traffic and apply policies to it, either by routing the traffic through the instance or by using some type of bridging or mirroring.

### Application Security and IAM
Application security in the cloud refers both to the software development process and to identity and access management (IAM) features designed to ensure authorized use of applications.\
Just as with on-premises solutions, cloud-based IAM enables the creation of user and user security groups, plus role-based management of privileges.

### Secrets Management
A cloud service is highly vulnerable to remote access. A failure of credential management is likely to be exploited by malicious actors. You must enforce strong authentication policies to mitigate risks:
- Do not use the root user for the CSP account for any day-to-day logon activity.
- Require strong multifactor authentication (MFA) for interactive logons. Use conditional authentication to deny or warn of risky account activity.
- Principals—user accounts, security groups, roles, and services—can interact with cloud services via CLIs and APIs. Such programmatic access is enabled by assigning a secret key to the account. Only the secret key (not the ordinary account credential) can be used for programmatic access. When a secret key is generated for an account, it must immediately be transferred to the host and kept securely on that host.

## Cloud Compute Security
Cloud provides resources abstracted from physical hardware via one or more layers of virtualization. The compute component provides process and system memory (RAM) resource as required for a particular workload.\
The virtualization layer ensures that the resources required for this task are made available on-demand. This can be referred to as dynamic resource allocation. It will be the responsibility of the CSP to ensure this capability is met to the standards agreed in the SLA.

- Container Security - A container uses many shared components on the underlying platform, meaning it must be carefully configured to reduce the risk of data exposure. In a container engine such as Docker, each container is isolated from others through separate namespaces and control groups (docs.docker.com/engine/security/security). Namespaces prevent one container reading or writing processes in another, while control groups ensure that one container cannot overwhelm others in a DoS-type attack.

- API Inspection and Intergration - The API is the means by which consumers interact with the cloud infrastructure, platform, or application. 
    - Number of requests
    - Latency
    - Error rates
    - Unauthorized and suspicious endpoints

- Instance Awareness - As with on-premises virtualization, it is important to manage instances (virtual machines and containers) to avoid sprawl, where undocumented instances are launched and left unmanaged. As well as restricting rights to launch instances, you should configure logging and monitoring to track usage.

## Cloud Storage Security
- Permissions and Resource Policies - As with on-premises systems, cloud storage resources must be configured to allow reads and/or writes only from authorized endpoints.
- Encryption - Cloud storage encryption equates to the on-premises concept of full disk encryption (FDE).The purpose is to minimize the risk of data loss via an insider or intruder attack on the CSP's storage systems. Each storage unit is encrypted using an AES key. If an attacker were to physically access a data center and copy or remove a disk, the data on the disk would not be readable.\
The key will be stored in a hardware security module (HSM) within the cloud. The HSM and separation of duties policies protect the keys from insider threat. Alternatively, customers can manage keys themselves, taking on all responsibility for secure distribution and storage.

## High Availabiity
High availability (HA) refers to storage provisioned with a guarantee of 99.99% uptime or better. As with on-premises architecture, the CSP uses redundancy to make multiple disk controllers and storage devices available to a pool of storage resource. Data may be replicated between pools or groups, with each pool supported by separate hardware resources.
- Replication - Data replication allows businesses to copy data to where it can be utilized most effectively. The cloud may be used as a central storage area, making data available among all business units. Data replication requires low-latency network connections, security, and data integrity. Hot storage retrieves data more quickly than cold, but the quicker the data retrieval, the higher the cost. Different applications have diverse replication requirements. A database generally needs low-latency, synchronous replication, as a transaction often cannot be considered complete until it has been made on all replicas. 

- High Availability across zones - CSPs divide the world into regions. Each region is independent of the others. The regions are divided into availability zones. The availability zones have independent data centers with their own power, cooling, and network connectivity. You can choose to host data, services, and VM instances in a particular region to provide a lower latency service to customers. Provisioning resources in multiple zones and regions can also improve performance and increases redundancy, but requires an adequate level of replication performance.
    - Local replication—replicates your data within a single data center in the region where you created your storage account. The replicas are often in separate fault domains and update domains.
    - Regional replication (also called zone-redundant storage)—replicates your data across multiple data centers within one or two regions. This safeguards data and access in the event a single data center is destroyed or goes offline
    - Geo-redundant storage (GRS)—replicates your data to a secondary region that is distant from the primary region. This safeguards data in the event of a regional outage or a disaster.

## Cloud Networking Security
Within the cloud, the Cloud Service Provider (CSP) establishes a virtualization layer that abstracts the underlying physical network. This allows the CSP to operate a public cloud where the networking performed by each customer account is isolated from the others. In terms of customer-configured cloud networking, there are various contexts:
- Networks by which the cloud consumer operates and manages the cloud systems.
- Virtual networks established between VMs and containers within the cloud.
- Virtual networks by which cloud services are published to guests or customers on the Internet.

### Virtual Private Clouds(VPCs)
A private network segment made available to a single cloud consumer on a public cloud.\
Each customer can create one or more virtual private clouds (VPCs) attached to their account. By default, a VPC is isolated from other CSP accounts and from other VPCs operating in the same account. This means that customer A cannot view traffic passing over customer B's VPC. The workload for each VPC is isolated from other VPCs. Within the VPC, the cloud consumer can assign an IPv4 CIDR block and configure one or more subnets within that block. Optionally, an IPv6 CIDR block can be assigned also. 

### Public and Private Subnets
Each subnet within a VPC can either be private or public. To configure a public subnet, first an Internet gateway (virtual router) must be attached to the VPC configuration. Secondly, the Internet gateway must be configured as the default route for each public subnet.  If a default route is not configured, the subnet remains private, even if an Internet gateway is attached to the VPC. Each instance in the subnet must also be configured with a public IP in its cloud profile. The Internet gateway performs 1:1 network address translation (NAT) to route Internet communications to and from the instance. 
There are other ways to provision external connectivity for a subnet if it is not appropriate to make it public:
- NAT gateway—this feature allows an instance to connect out to the Internet or to other services in AWS, but does not allow connections initiated from the Internet.
- VPN—there are various options for establishing connections to and between VPCs using virtual private networks (VPNs) at the software layer or using CSP-managed features.

## VPCs and Transit Gateways
Routing can be configured between subnets within a VPC. This traffic can be subject to cloud native ACLs allowing or blocking traffic on the basis of host IPs and ports. Alternatively, traffic could be routed through a virtual firewall instance, or other security appliance.

Connectivity can also be configured between VPCs in the same account or with VPCs belonging to different accounts, and between VPCs and on-premises networks. Configuring additional VPCs rather than subnets within a VPC allows for a greater degree of segmentation between instances. A complex network might split segments between different VPCs across different cloud accounts for performance or compliance reasons.

Traditionally, VPCs can be interconnected using peering relationships and connected with on-premises networks using VPN gateways. These one-to-one VPC peering relationships can quickly become difficult to manage, especially if each VPC must interconnect in a mesh-like structure. A transit gateway is a simpler means of managing these interconnections. Essentially, a transit gateway is a virtual router that handles routing between the subnets in each attached VPC and any attached VPN gateways (aws.amazon.com/transit-gateway).

## Cloud Firewall Security
Filtering decisions can be made based on packet headers and payload contents at various layers, identified in terms of the OSI model:
- Network layer(layer 3) - the firewall accepts or denies connections on the basis of IP addresses or address ranges and TCP/UDP port numbers (the latter are actually contained in layer 4 headers, but this functionality is still always described as basic layer 3 packet filtering).
- Transport layer (layer 4)—the firewall can store connection states and use rules to allow established or related traffic. Because the firewall must maintain a state table of existing connections, this requires more processing power (CPU and memory).
- Application layer (layer 7)—the firewall can parse application protocol headers and payloads (such as HTTP packets) and make filtering decisions based on their contents. This requires even greater processing capacity (or load balancing), or the firewall will become a bottleneck and increase network latency.

On premises cloud based firewalls to impliment security
- As software running on an instance. This sort of host-based firewall is identical to ones that you would configure for an on-premises host. It could be a stateful packet filtering firewall or a web application firewall (WAF) with a ruleset tuned to preventing malicious attacks. The drawback is that the software consumes instance resources and so is not very efficient. Also, managing the rulesets across many instances can be challenging.
- As a service at the virtualization layer to filter traffic between VPC subnets and instances. This equates to the concept of an on-premises network firewall.

## Security Groups
In AWS, basic packet filtering rules managing traffic that each instance will accept can be managed through security groups.\
A security group provides stateful inbound and outbound filtering at layer 4. The stateful filtering property means that it will allow established and related traffic if a new connection has been accepted.

## Cloud Access Security Groups
A cloud access security broker (CASB) is enterprise management software designed to mediate access to cloud services by users across all types of devices.

CASBs provide you with visibility into how clients and other network nodes are using cloud services. Some of the functions of a CASB are:
- Enable single sign-on authentication and enforce access controls and authorizations from the enterprise network to the cloud provider.
- Scan for malware and rogue or non-compliant device access
- Monitor and audit user and resource activity.
- Mitigate data exfiltration by preventing access to unauthorized cloud services from managed devices

It is implimented in three ways:
- Forward proxy - this is a security appliance or host positioned at the client network edge that forwards user traffic to the cloud network if the contents of that traffic comply with policy. This requires configuration of users' devices or installation of an agent.
- Reverse proxy - this is positioned at the cloud network edge and directs traffic to cloud services if the contents of that traffic comply with policy. This does not require configuration of the users' devices. This approach is only possible if the cloud application has proxy support.
- API - rather than placing a CASB appliance or host inline with cloud consumers and the cloud services, an API-based CASB brokers connections between the cloud service and the cloud consumer. For example, if a user account has been disabled or an authorization has been revoked on the local network, the CASB would communicate this to the cloud service and use its API to disable access there too.

### Next-Generation Secure Web Gateway
Enterprise networks often make use of secure web gateways (SWG). An on-premises SWG is a proxy-based firewall, content filter, and intrusion detection/prevention system that mediates user access to Internet sites and services. 

# Infrastructure as Code Concepts
## Services Intergration and Microservices
With virtualization, the provision of these applications is much less dependent on where you put the box and the OS that the box runs. Virtualization helps to make the design architecture fit to the business requirement rather than accommodate the business workflow to the platform requirement.

### Service-Oriented Architecture
Service-oriented architecture (SOA) conceives of atomic services closely mapped to business workflows.  Each service takes defined inputs and produces defined outputs. The service may itself be composed of sub-services. The key features of a service function are that it is self-contained, does not rely on the state of other services, and exposes clear input/output (I/O) interfaces. 

Because each service has a simple interface, interoperability is made much easier than with a complex monolithic application. The implementation of a service does not constrain compatibility choices for client services, which can use a different platform or development language. This independence of the service and the client requesting the service is referred to as loose coupling. 

### Microservices
Microservice-based development shares many similarities with Agile software project management and the processes of continuous delivery and deployment. It also shares roots with the Unix philosophy that each program or tool should do one thing well. The main difference between SOA and microservices is that SOA allows a service to be built from other services. By contrast, each microservice should be capable of being developed, tested, and deployed independently.

### Service Integration and Orchestration
Services integration refers to ways of making these decoupled service or microservice components work together to perform a workflow.\ 
Where SOA used the concept of an enterprise service bus, microservices integration and cloud services/virtualization/automation integration generally is very often implemented using orchestration tools. 

Where automation focuses on making a single, discrete task easily repeatable, orchestration performs a sequence of automated tasks. For example, you might orchestrate adding a new VM to a load-balanced cluster. This end-to-end process might include provisioning the VM, configuring it, adding the new VM to the load-balanced cluster, and reconfiguring the load-balancing weight distribution given the new cluster configuration. In doing this, the orchestrated steps would have to run numerous automated scripts or API service calls.

## Serverless Architecture
A software architecture that runs functions within virtualized runtime containers in a cloud rather than on dedicated server instances.\
The applications are developed as functions and microservices, each interacting with other functions to facilitate client requests. When the client requires some operation to be processed, the cloud spins up a container to run the code, performs the processing, and then destroys the container. Billing is based on execution time, rather than hourly charges. This type of service provision is also called function as a service (FaaS)

The serverless paradigm eliminates the need to manage physical or virtual server instances, so there is no management effort for software and patches, administration privileges, or file system security monitoring. There is no requirement to provision multiple servers for redundancy or load balancing. As all of the processing is taking place within the cloud, there is little emphasis on the provision of a corporate network. This underlying architecture is managed by the service provider. The principal network security job is to ensure that the clients accessing the services have not been compromised in a way that allows a malicious actor to impersonate a legitimate user. This is a particularly important consideration for the developer accounts and devices used to update the application code underpinning the services. These workstations must be fully locked down, running no other applications or web code than those necessary for development.

Serverless does have considerable risks. As a new paradigm, use cases and best practices are not mature, especially as regards security. There is also a critical and unavoidable dependency on the service provider, with limited options for disaster recovery should that service provision fail.

Serverless architecture depends heavily on the concept of event-driven orchestration to facilitate operations. For example, when a client connects to an application, multiple services will be called to authenticate the user and device, identify the device location and address properties, create a session, load authorizations for the action, use application logic to process the action, read or commit information from a database, and write a log of the transaction. This design logic is different from applications written to run in a "monolithic" server-based environment. This means that adapting existing corporate software will require substantial development effort.

## Infrastructure as a Code
The use of cloud technologies encourages the use of scripted approaches to provisioning, rather than manually making configuration changes, or installing patches. An approach to infrastructure management where automation and orchestration fully replace manual configuration is referred to as infrastructure as code (IaC).

One of the goals of IaC is to eliminate snowflake systems. A snowflake is a configuration or build that is different from any other. The lack of consistency—or drift—in the platform environment leads to security issues, such as patches that have not been installed, and stability issues, such as scripts that fail to run because of some small configuration difference. 

By rejecting manual configuration of any kind, IaC ensures idempotence. Idempotence means that making the same call with the same parameters will always produce the same result. Note that IaC is not simply a matter of using scripts to create instances. Running scripts that have been written ad hoc is just as likely to cause environment drift as manual configuration. IaC means using carefully developed and tested scripts and orchestration runbooks to generate consistent builds.

## Software-Defined Networking
IaC is partly facilitated by physical and virtual network appliances that are fully configurable via scripting and APIs.\
With so many devices to configure, it is better to take a step back and consider an abstracted model about how the network functions. In this model, network functions can be divided into three "planes":
- Control plane—makes decisions about how traffic should be prioritized and secured, and where it should be switched.
- Data plane—handles the actual switching and routing of traffic and imposition of security access controls.
- Management plane—monitors traffic conditions and network status.

A software-defined networking (SDN) application can be used to define policy decisions on the control plane. These decisions are then implemented on the data plane by a network controller application, which interfaces with the network devices using APIs.\
The interface between the SDN applications and the SDN controller is described as the "northbound" API, while that between the controller and appliances is the "southbound" API. SDN can be used to manage compatible physical appliances, but also virtual switches, routers, and firewalls. The architecture supporting rapid deployment of virtual networking using general-purpose VMs and containers is called network functions virtualization (NFV) 

## Software-defined Visibility
Where SDN addresses secure network "build" solutions, software-defined visibility (SDV) supports assessment and incident response functions. Visibility is the near real-time collection, aggregation, and reporting of data about network traffic flows and the configuration and status of all the hosts, applications, and user accounts participating in it.

This can provide you with a more robust ability to detect anomalies—anomalies that may suggest an incident. SDV therefore gives you a high-level perspective of network flow and endpoint/user account behavior that may not be possible with traditional appliances. SDV supports designs such as zero trust and east/west (paloaltonetworks.com/cyberpedia/what-is-a-zero-trust-architecture), plus implementation of security orchestration and automated response (SOAR).

## FOG and Edge Computing
FOG computing - Provisioning processing resource between the network edge of IoT devices and the data center to reduce latency.\
Sensors may generate huge quantities of data only a selection of which needs to be prioritized for analysis.\
It addresses these requirements by placing fog node processing resources close to the physical location for the IoT sensors. The sensors communicate with the fog node, using Wi-Fi, ZigBee, or 4G/5G, and the fog node prioritizes traffic, analyzes and remediates alertable conditions, and backhauls remaining data to the data center for storage and low-priority analysis.

Edge computing - Provisioning processing resource close to the network edge of IoT devices to reduce latency.\
It is a broader concept partially developed from fog computing and partially evolved in parallel to it. Fog computing is now seen as working within the concept of edge computing. Edge computing uses the following concepts:
- Edge devices are those that collect and depend upon data for their operation
- Edge gateways perform some pre-processing of data to and from edge devices to enable prioritization. They also perform the wired or wireless connectivity to transfer data to and from the storage and processing networks.
- Fog nodes can be incorporated as a data processing layer positioned close to the edge gateways, assisting the prioritization of critical data transmission.
- The cloud or data center layer provides the main storage and processing resources, plus distribution and aggregation of data between sites.

## Addtional Notes
- Service Level Agreement establish what risks are available and who is responsible for them