# Data Privacy and Protection

### Objectives 
- Privacy and Data Sensitivity Concepts
- Privacy and Data Protection controls

# Privacy and Data Sensitivity
Data security privacy is an area where policies and procedures are crucial controls in ensuring compliance. They can be expressed as agreements btwn external partners, suppliers, customers and even employees.

## Privacy and Sensitive Data Concepts
The value of information assets can be thought of in terms of how a compromise of the data's security attributes of the (CIA) triad would impact the organization.
- Privacy VS Security - Privacy is a governance requirement that arises when collecting and processing personal data(identifiable individual person)/data subject where security focuses on CIA triad.

- Information Life Cycle Management - An information life cycle model identifies discrete steps to assist security and privacy policy design. Most models identify the following general stages:
    - Creation/collection
    - Distribution/use
    - Retention
    - Disposal

## Data Roles and Responsibility
A data governance policy describes the security controls that will be applied to protect data at each stage of its life cycle. 
- Data Owner - senior with ultimate responsibility on the data(labeling)
- Data steward - Primary responsibility for data quality
- Data custodian - managing system on which data is stored
- Data Privacy Officer(DPO) - responsible for oversight of PII

In context of legislation and regulations 2 roles are important
- Data Controller - the entity responsible for determining why and how data is stored, collected, and used and for ensuring that these purposes and means are lawful. The data controller has ultimate responsibility for privacy breaches, and is not permitted to transfer that responsibility.
- Data Processor - an entity engaged by the data controller to assist with technical collection, storage, or analysis tasks. A data processor follows the instructions of a data controller with regard to collection or processing.

## Data Classifications
Data classification and typing schemas tag data assets so that they can be managed through the information life cycle. Classification schema is based on decision tree by applying one or more tags on the data. Based on level/degree of confidentiality 
- Public - No restriction on viewing the data. No risk if it is modified/disclosed
- Confidential(secret) - Highly sensitive,approved persons only avalaible to 3rd party under NDA
- Critical(top secret) - the information is too valuable to allow any risk of its capture. Viewing is severely restricted.

The kind of information asset
- Proprietary - proprietary information or intellectual property (IP) is information created and owned by the company, typically about the products or services that they make or perform. 
- Private/personal data - Information that relates to an individual
- Sensitive - Relates to private info that could be of harm if made public

## Data Types
Applies a more delailed lable to data

Personal Identifiable Information(PII)\
This is data that can be used to identify, contact, locate an individual

Customer Data\
Customer data can be institutional information, but also personal information about the customer's employees, such as sales and technical support contacts. This personal customer data should be treated as PII. Institutional information might be shared under a nondisclosure agreement (NDA), placing contractual obligations on storing and processing it securely.

Health Information\
Personal health information (PHI)—or protected health information—refers to medical and insurance records, plus associated hospital and laboratory test results. PHI may be associated with a specific person or used as an anonymized or deidentified data set for analysis and research. An anonymized data set is one where the identifying data is removed completely. A deidentified set contains codes that allow the subject information to be reconstructed by the data provider

Financial Information\
Financial information refers to data held about bank and investment accounts, plus information such as payroll and tax returns. Payment card information comprises the card number, expiry date, and the multi-digit card verification value (CVV). Cards are also associated with a PIN, but this should never be transmitted to or handled by the merchant. Abuse of the card may also require the holder's name and the address the card is registered to. The Payment Card Industry Data Security Standard (PCI DSS) defines the safe handling and storage of this information (pcisecuritystandards.org/pci_security).

Government Data\
Internally, government agencies have complex data collection and processing requirements. In the US, federal laws place certain requirements on institutions that collect and process data about citizens and taxpayers. This data may be shared with companies for analysis under strict agreements to preserve security and privacy.

## Privacy Notices and Data Retention
Data owners should be aware of any legal or regulatory issues that impact collection and processing of personal data

Privacy Notices\
Informed consent means that the data must be collected and processed only for the stated purpose, and that purpose must be clearly described to the user in plain language, not legalese. \
The data cannot be used for any other purpose.\
Purpose limitation restricts ability to transfer data to third parties

Impact Assessments\
A data protection impact assessment is a process designed to identify the risks of collecting and processing personal data in the context of a business workflow or project and to identify mechanisms that mitigate.

Data Retention\
Data retention refers to backing up and archiving information assets in order to comply with business policies and/or applicable laws and regulations.

## Data Sovereignty and Geographical Considerations
#### Data sovereignty
Data sovereignty refers to a jurisdiction preventing or restricting processing and storage from taking place on systems which do not physically reside within that jurisdiction. Data sovereignty may demand certain concessions on your part, such as using location-specific storage facilities in a cloud service.

#### Geographical Considerations
- Storage locations might have to be carefully selected to mitigate data sovereignty issues. Most cloud providers allow choice of data centers for processing and storage, ensuring that information is not illegally transferred from a particular privacy jurisdiction without consent.

- Employees needing access from multiple geographic locations. Cloud-based file and database services can apply constraint-based access controls to validate the user's geographic location before authorizing access.

## Privacy Breaches and Data Breaches
A data breach occurs when information is read, modified, or deleted without authorization.\
A privacy breach refers specifically to loss or disclosure of personal and sensitive data. 

Organizational Consequences\
A data or privacy breach can have severe org consequenses.
- Reputation damage
- Identity theft
- Fines
- Intellectual Property Theft

Notification of Breaches\
The requirements for different types of breaches are set out in law and/or in regulations. The requirements indicate who must be notified. A data breach can mean the loss or theft of information, the accidental disclosure of information, or the loss or damage of information. Note that there are substantial risks from accidental breaches if effective procedures are not in place. If a database administrator can run a query that shows unredacted credit card numbers, that is a data breach, regardless of whether the query ever leaves the database server.

Escalation\
Even with a minor breach mostly concerning that of Intellectual Property need to be escalated to decision makers and impacts of legislation and regulation considered.

Public Notification and Disclosure
Other than the regulator, notification might need to be made to law enforcement, individuals and third-party companies affected by the breach, and publicly through press or social media channels.

## Data Sharing and Privacy Terms of Agreement
The org is resnsible for the actions of 3rd parties they have delegated the services to. Issues of security risk awareness, shared duties, and contractual responsibilities can be set out in a formal legal agreement. The following types of agreements are common:

- Service level agreement (SLA)—a contractual agreement setting out the detailed terms under which a service is provided. This can include terms for security access controls and risk assessments plus processing requirements for confidential and private data.

- Nondisclosure agreement (NDA)—legal basis for protecting information assets. NDAs are used between companies and employees, between companies and contractors, and between two companies. If the employee or contractor breaks this agreement and does share such information, they may face legal consequences. NDAs are useful because they deter employees and contractors from violating the trust that an employer places in them.

- Data sharing and use agreement—under privacy regulations such as GDPR or HIPAA, personal data can only be collected for a specific purpose. Data sets can be subject to pseudo-anonymization or deidentification to remove personal data, but there are risks of reidentification if combined with other data sources. A data sharing and use agreement is a legal means of preventing this risk. It can specify terms for the way a data set can be analyzed and proscribe the use of reidentification techniques.

Interconnection security agreement (ISA)—ISAs are defined by NIST's SP800-47 "Managing the Security of Information Exchanges" (https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-47r1.pdf). Any federal agency interconnecting its IT system to a third party must create an ISA to govern the relationship. An ISA sets out a security risk awareness process and commits the agency and supplier to implementing security controls.

# Privacy and Data Protection Controls
## Data Protection
Data stored within a trusted OS can be subject to authorization mechanisms where OS mediates access using ACL.
Data states:
- Data at Rest - means data stored in some sort of persistent storage.\In this state, it is usually possible to encrypt the data, using techniques such as whole disk encryption, database encryption, and file- or folder-level encryption. It is also possible to apply permissions—access control lists (ACLs)—to ensure only authorized users can read or modify the data. ACLs can be applied only if access to the data is fully mediated through a trusted OS.

- Data in Trasit(Data in Motion) - This where data is transmitted over a network. In this state, data can be protected by a transport encryption protocol, such as TLS or IPSec. 

- Data in Use(Data in Processing) - this is the state when data is present in volatile memory, such as system RAM or CPU registers and cache. Trusted execution environment (TEE) mechanisms, such as Intel Software Guard Extensions (software.intel.com/content/www/us/en/develop/topics/software-guard-extensions/details.html) are able to encrypt data as it exists in memory, so that an untrusted process cannot decode the information.

## Data Exfiltration
This is unauthorized copying or retrieval of data from a system.\
Uses a variety of mechanisms
- Copying data to removable media/storage
- Using a network protocol, such as HTTP, FTP, SSH, email, or Instant Messaging (IM)/chat. A sophisticated adversary might use a Remote Access Trojan (RAT) to perform transfer of data over a nonstandard network port or a packet crafter to transfer data over a standard port in a nonstandard way.
- Using VoIP or text message
- Using picture or video of the data

Controls measures
- Encryption of data at rest
- Maintaining backups in case of ransomware
- Using ACLs in data data systems
- Restrict the types of network channels that attackers can use to transfer data from the network to the outside. 
- Train users about document confidentiality and use of encryption to store and transmit data securely.

## Data Loss Preention(DLP)
DLP products automate the discovery and classification of data types and enforce rules so that data is not viewed or transferred without authorization.
Components:
- Policy server - to configure classification, confidentiality, and privacy rules and policies, log incidents, and compile reports.
- Endpoint agents - to enforce policy on client computers, even when they are not connected to the network.
- Network agents - to scan communications at network borders and interface with web and messaging servers to enforce policy.

Remediation is the action the DLP software takes when it detects a policy violation. The following remediation mechanisms are typical:
- Alert only - system records incident and may alert admin
- Block - The incident is blocked, logged and may/may not be alerted
- Quarantine - access to the original file is denied thru encryption or moving it.
- Tombstone - the original file is quarantined and replaced with one describing the policy violation and how the user can release it again.

## Rights Management Services
As another example of data protection and information management solutions, Microsoft provides an Information Rights Management (IRM) feature in their Office productivity suite, SharePoint document collaboration services, and Exchange messaging server. IRM works with the Active Directory Rights Management Services (RMS) or the cloud-based Azure Information Protection. These technologies provide administrators with the following functionality:

- Assign file permissions for different document roles, such as author, editor, or reviewer.
- Restrict printing and forwarding of documents, even when sent as file attachments.
- Restrict printing and forwarding of email messages.

## Priacy Enhancing Technologies
Data minimization is the principle that data should only be processed and stored if it is necessary to perform the purpose it is collected for.\ To prove compliance any process that uses personal data should be documented.
- How long it has been stored.
- Does retention support a legitimate process
- forbids use of personal info in tests
- Data only for stated purpose in each transaction

A fully anonymized data set is one where individual subjects can no longer be identified(deidentification), even if the data set is combined with other data sources.\
Pseudo-anonymization modifies or replaces identifying information so that reidentification depends on an alternate data source, which must be kept separate. With access to the alternate data, pseudo-anonymization methods are reversible.

## Database Deitentification Methods
Deidentification methods are usually implemented as part of the database management system (DBMS) hosting the data. Sensitive fields will be tagged for deidentification whenever a query or report is run.

#### Data Masking
Data masking can mean that all or part of the contents of a field are redacted, by substituting all character strings with "x" for example. A field might be partially redacted to preserve metadata for analysis purposes. For example, in a telephone number, the dialing prefix might be retained, but the subscriber number redacted. Data masking can also use techniques to preserve the original format of the field. Data masking is an irreversible deidentification technique.

#### Tokenization
Tokenization means that all or part of data in a field is replaced with a randomly generated token. The token is stored with the original value on a token server or token vault, separate to the production database. An authorized query or app can retrieve the original value from the vault, if necessary, so tokenization is a reversible technique. Tokenization is used as a substitute for encryption, because from a regulatory perspective an encrypted field is the same value as the original data

#### Aggregation/Banding
Another deidentification technique is to generalize the data, such as substituting a specific age with a broader age band. 

#### Hashing and Salting
A cryptographic hash produces a fixed-length string from arbitrary-length plaintext data using an algorithm such as SHA. If the function is secure, it should not be possible to match the hash back to a plaintext. Hashing is mostly used to prove integrity. If two sources have access to the same plaintext, they should derive the same hash value. Hashing is used for two main purposes within a database:
- As an indexing method to speed up searches and provide deidentified references to records.
- As a storage method for data such as passwords where the original plaintext does not need to be retained.

