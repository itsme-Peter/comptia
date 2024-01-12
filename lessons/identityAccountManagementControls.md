# Implimenting Identiy and Account Management Controls

## Objectives 
- Impliment Identity and Account types
- Impliment Account Policies
- Impliment Authorization solutions
- Importance of Personnel policies

## Identity Management Controls
Provide for user authenticaion
- Certificates and Smart Cards
    - Using PKInfrastracture in manaegement of certs
- Tokens 
    - Provide single sign on token to access resources as they are authenticated by the Identity Provider
- Identity providers 
    -  service that provisions the user account and processes authentication requests.

### Personnel policies for privilege management
- Separation of duties
- Least privilege
- Job rotation
- Mandatory vacation

### Offboarding policies
- Account disabling
- Returning company assets
- Personnel assets

### Security Group-based privileges
Assigning users to a group to access its permissions

### Service Accounts
used by scheduled processes and application server software, such as databases. Windows has several default service account types. These do not accept user interactive logons but can be used to run processes and background services:
- System - Has the most permissions in windows
- Local Service - has the same privileges as the standard user account. It can only access network resources as an anonymous user.
- Network Service - has the same privileges as the standard user account but can present the computer's account credentials when accessing network resources./

### Shared credentials
Is one where passwords (or other authentication credentials) are known to more than one person.
- Credential policies for devices.\
    Network appliances designed for enterprise use are unlikely to be restricted to a single default account, and will use TACACS+ to support individual accounts and role-based permissions.
- Privilege Access Management.\
    Enterprise privilege access management products provide a solution for storing these high-risk credentials somewhere other than a spreadsheet and for auditing elevated privileges generally
    
## Account Policies
### Account attributes
- A user account is defined by unique security identifier(SID), name, credential.
### Access policies
Each account can be assigned permissions over files and other network resources and access policies or privileges over the use and configuration of network hosts.\
Access policies determine things like the right to log on to a computer locally or via remote desktop.\
On a Windows Active Directory network, access policies can be configured via group policy objects (GPOs). GPOs can be used to configure access rights for user/group/role accounts. GPOs can be linked to network administrative boundaries in Active Directory, such as sites, domains, and Organizational Units (OU). 

#### Account password policy settings
- Password length
- Password complexity
- Password aging
- Password reuse and history

#### Account restrictions
- Location based policies.\
    A user account may be prevented from logging on locally to servers within a restricted Organisational Unit.\
    Geolocation mechanism can provide for location:
    - IP address - ISP
    - Location services(GPS),cell towers, Wi-Fi hotspots, and Bluetooth signals.

    Geofencing - refers to accepting or rejecting access requests based on location.\
    Geotagging refers to the addition of location metadata to files or devices. This is often used for asset management to ensure devices are kept with the proper location.  

- Time-Based restrictions
    - A time of day policy - hours for authorized logons
    - A time based login policy - max amount of time an acc may be logged on.
    - An impossible travel time/risky login policy tracks the location of login events over time. If these do not meet a threshold, the account will be disabled. 

#### Account Audits
Accounting and auditing processes are used to detect whether an account has been compromised or is being misused. 
- Accounting for all actions that have been performed by users. 
- Detecting intrusions or attempted intrusions

#### Usage audits
Usage auditing means configuring the security log to record key indicators and then reviewing the logs for suspicious activity.\
categories include
- Account logon and management events.
- Process creation.
- Object access (file system/file shares).
- Changes to audit policy.
- Changes to system security and integrity (antivirus, host - firewall, and so on).

#### Account lockout and Disablement
Account disablement means that login is permanently prevented until an administrator manually re-enables the account. Note that disabling the account does not close existing sessions. 

An account lockout means that login is prevented for a period. This might be done manually if a policy violation is detected, but there are several scenarios for automatically applying a lockout:
- An incorrect account password is entered repeatedly.
- The account is set to expire. 
- When using time- or location-based restrictions, the server periodically checks whether the user has the right to continue using the network. 

## Authorization solutions
An important consideration in designing a security system is to determine how users receive rights or permissions. The different models are referred to as access control schemes.

#### Discretionary Access Control
Based on the resource owner. The owner is granted full control over the resource, meaning that he or she can modify its access control list (ACL) to grant rights to others.
- Widely used and flexible
- Easiest to compromise cause of insider threats and abuse of accounts

#### Role-Based Access COntrol(RBAC)
A set of organizational roles are defined, and subjects allocated to those roles. Under this system, the right to modify roles is reserved to a system owner. Therefore, the system is non-discretionary, as each subject account has no right to modify the ACL of a resource, even though they may be able to change the resource in other ways. Users are said to gain rights implicitly (through being assigned to a role) rather than explicitly (being assigned the right directly).\
The permissions of a role should end when a task is complete rather than have them permanently.

#### File System permissions
An access control model can be applied to any type of data or software resource but is most closely associated with network, file system, and database security. With file system security, each object in the file system has an ACL associated with it. The ACL contains a list of accounts (principals) allowed to access the resource and the permissions they have over it. Each record in the ACL is called an access control entry (ACE). The order of ACEs in the ACL is important in determining effective permissions for a given account. ACLs can be enforced by a file system that supports permissions, such as NTFS, ext3/ext4, or ZFS.

Linux
> chmod u=rwx, g=rx, o=rx home
> chmod 755 home > r=4,w=2,x=1

#### Mandatory Access Control(MAC)
Based on the idea of security clearance levels. A subject is granted a clearance level and can only(lable) and can access resources on his clearance level or below.\
The labelling of objects and subjects takes place using pre-established rules. The critical point is that these rules cannot be changed by any subject account, and are therefore non-discretionary.

#### Attribute-Based Access Control(ABAC)
ABAC system is capable of making access decisions based on a combination of subject and object attributes plus any context-sensitive or system-wide attributes.

#### Rule Based Access Control
Refers to any sort of access control model where access control policies are determined by system-enforced rules rather than system users. As such, RBAC, ABAC, and MAC are all examples of rule-based (or non-discretionary) access control.

#### Conditional Access
A form of rule based access control.\
Monitors account or device behavior throughout a session. If certain conditions are met, the account may be suspended or the user may be required to reauthenticate, perhaps using a 2-step verification method.

The User Account Control (UAC) and sudo restrictions on privileged accounts are examples of conditional access.The user is prompted for confirmation or authentication when requests that require elevated privileges are made. 

#### Privileged Access Management(PAM)
A privileged account is one that can make significant configuration changes to a host, such as installing software or disabling a firewall or other security system.\
Privileged access management (PAM) refers to policies, procedures, and technical controls to prevent the malicious abuse of privileged accounts and to mitigate risks from weak configuration control over privileges.

#### Directory Services
The principal means of providing privilege management and authorization on an enterprise network, storing information about users, computers, security groups/roles, and services.

The Lightweight Directory Access Protocol (LDAP) is a protocol widely used to query and update X.500 format directories. 

#### Federation
It means that the company trusts accounts created and managed by a different network.

Notion that a network needs to be accessible to more than just a well-defined group of employees. A company might need to make parts of its network open to partners, suppliers, and customers. The company can manage its employee accounts easily enough. 

As another example, in the consumer world, a user might want to use both Google Apps and Twitter.

#### Identity Providers and Attestation
Network performs federated identity management, A user from one network is able to provide attestation that proves their identity. 
- The user(pricipal) attempts a service provider(SP) or relying provider(RP) res=directs principal to identity provider(idP) to authenticate
- Principal authenticates with identity provider and obtains attestation of identity(token/document signed bt idP)
- The principal presents the attestation to the service provider. The SP can validate that the IdP has signed the attestation because of its trust relationship with the IdP.
- The service provider can now connect the authenticated principal to its own accounts database. It may be able to query attributes of the user account profile held by the IdP, if the principal has authorized this type of access.

#### Cloud cersus on-premises requirements
Where a company needs to make use of cloud services or share resources with business partner networks, authentication and authorization design comes with more constraints and additional requirements.\
Web applications might not support Kerberos, while third-party networks might not support direct federation with Active Directory/LDAP. The design for these cloud networks is likely to require the use of standards for performing federation and attestation between web applications.

#### Security Assertion Markup Language
A federated network or cloud needs specific protocols and technologies to implement user identity assertions and transmit attestations between the principal, the relying party, and the identity provider.\
Security Assertion Markup Language (SAML) is one such solution. SAML attestations (or authorizations) are written in eXtensible Markup Language (XML). Communications are established using HTTP/HTTPS and the Simple Object Access Protocol (SOAP).\
These secure tokens are signed using the XML signature specification. The use of a digital signature allows the relying party to trust the identity provider.\
Amazon Web Services (AWS) can function as a SAML service provider. This allows companies using AWS to develop cloud applications to manage their customers' user identities and provide them with permissions on AWS without having to create accounts for them on AWS directly.

#### Open Authentication
Representational State Transfer(REST/restful apis) is commonly used rather than SOAP and offers more choice of implimentation than SOAP and SAML.

RESTful API is often implemented using the Open Authorization (OAuth) protocol.\
OAuth is designed to facilitate sharing of information (resources) within a user profile between sites. The user creates a password-protected account at an identity provider (IdP). The user can use that account to log on to an OAuth consumer site without giving the password to the consumer site. A user (resource owner) can grant a client an authorization to access some part of their account. A client in this context is an app or consumer site.

User account hosted by one more resource servers. A resource server is also called API server as it hosts functions that allow clients(consumer) to access user attributes. Requests are processed by authorization server. A single server can manage multiple resources servers,  equally the resource and authorization server could be the same server instance.

The client app or service must be registered with the authorization server.As part of this process, the client registers a redirect URL, which is the endpoint that will process authorization tokens. Registration also provides the client with an ID and a secret.\
ID can be publicly exposed but secret is kept confidential btwn client and authorization server.\
When the client application requests authorization, the user approves the authorization server to grant the request using an appropriate method.\
Depending on the flow type, the client will end up with an access token validated by the authorization server. The client presents the access token to the resource server, which then accepts the request for the resource if the token is valid.

OAuth uses the JavaScript object notation (JSON) web token (JWT) format for claims data. JWTs can easily be passed as Base64-encoded strings in URLs and HTTP headers and can be digitally signed for authentication and integrity

#### OpenID Connect(OIDC)
OAuth is explicitly designed to authorize claims and not to authenticate users.\
The implementation details for fields and attributes within tokens are not defined. There is no mechanism to validate that a user who initiated an authorization request is still logged on and present. The access token once granted has no authenticating information. 

OpenID Connect(OIDC) is an authentication protocol that can be implemented as special types of OAuth flows with precisely defined token fields.

## Personnel Policies
You will need to make sure that your personnel follow appropriate security procedures and policies. The human element can represent a significant attack surface, especially when social engineering attacks are involved. 

### Conduct policies
Operational policies include privilege/credential management, data handling, and incident response. Other important security policies include those governing employee conduct and respect for privacy.

#### Acceptable Use Policy(UAP)
It  is important to protect the organization from the security and legal implications of employees misusing its equipment. 

Typically, the policy will forbid the use of equipment to defraud, to defame, or to obtain illegal material. It will prohibit the installation of unauthorized hardware or software and explicitly forbid actual or attempted snooping of confidential data that the employee is not authorized to access.

Acceptable use guidelines must be reasonable and not interfere with employees' fundamental job duties or privacy rights. An organization's AUP may forbid use of Internet tools outside of work-related duties or restrict such use to break times.

#### Code of conduct and Social Media Analysis
A code of conduct, or rules of behavior, sets out expected professional standards.

Rules of behavior are also important when considering employees with privileged access to computer systems. Technicians and managers should be bound by clauses that forbid them from misusing privileges to snoop on other employees or to disable a security mechanism.

#### Use of Personally Owned devices in the workplace
Portable devices, such as smartphones, USB sticks, media players, and so on, pose a considerable threat to data security, as they make file copy so easy. Camera and voice recording functions are other obvious security issues.

Network access control, endpoint management, and data loss prevention solutions can be of some use in preventing the attachment of such devices to corporate networks. Some companies may try to prevent staff from bringing such devices on site. This is quite difficult to enforce, though.

Also important to consider is the unauthorized use of personal software by employees or employees using software or services that has not been sanctioned for a project (shadow IT). Personal software may include either locally installed software or hosted applications, such as personal email or instant messenger, and may leave the organization open to a variety of security vulnerabilities. 

#### Clean desk policy
A clean desk policy means that each employee's work area should be free from any documents left there. The aim of the policy is to prevent sensitive information from being obtained by unauthorized staff or guests at the workplace.

#### User and Role based Training
Another essential component of a secure system is effective user training.\
There should also be a system for identifying staff performing security-sensitive roles and grading the level of training and education required

#### Diversity of Training Techniques
It is necessary to frame security training in language that end users will respond to. Education should focus on responsibilities and threats that are relevant to users in language that users understand.

#### Phishing Campaigbs
A phishing campaign training event means sending simulated phishing messages to users. Users that respond to the messages can be targeted for follow-up training

#### Capture the Flag(CTF)
Participants must complete a series of challenges within a virtualized computing environment to discover a flag. The flag will represent either threat actor activity (for blue team exercises) or a vulnerability (for red team exercises) and the participant must use analysis and appropriate tools to discover it. Capturing the flag allows the user to progress to the next level and start a new challenge. 

#### Computer Based Training(CBT) and Gamification
This type of gamification can be used to boost security awareness for other roles too. 
CBT might use video game elements to improve engagement. 
It allows a student to acquire skills and experience by completing various types of practical activities:
- Simulations - recreating system interfaces or using emulators so students can practice configuration tasks.
- Branching scenarios - students choose between options to find the best choices to solve a cybersecurity incident or configuration problem.

