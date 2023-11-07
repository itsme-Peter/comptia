# Implimenting Authentication Controls

### Objectives
- Summarize authentication design concepts
- Implement knowledge-based authentication
- Implement authentication technologies.
- Summarize biometrics authentication concepts.

IAM(Identitiy and Access Management) - authentication technologies ensure that only valid subjects (users or devices) can operate an account

### Identity and Access Management(IAM)
IAM(Identity and Access Management) - authentication technologies ensure that only valid subjects (users or devices) can operate an account
- It governs the how subjects(users,devices,processes), interact with objects(resources)
IAM is  built on 4 main processes
- Identification - creating an account or ID that uniquely represents the user, device, or process on the network.
- Authentication - proving that a subject is who or what it claims to be when it attempts to access the resource. 
- Authorization - determining what rights subjects should have on each resource, and enforcing those rights. 
- Accounting - tracking authorized usage of a resource or use of rights by a subject and alerting when unauthorized use is detected or attempted. 
The servers and protocols that implement these functions are referred to as authentication, authorization, and accounting (AAA).

### Authentication Factors
After succesful creation of acc, we need to ensure that verification of only acc holder gets access after submitting appropriate credentials

- Something You Know Authentication 
    - It comprises main on logon details such as username & password. A paasphrase composed of multiple words is most used or rather a Personal Identification Number(PIN) and Swipe patterns for touch based devices

- Something You Have Authentication
    - This involves where the subject has sth in their possession such a card, smartphone or sth physical to identify them.
    - Mostly used for brief times

- Something You Are/ Do Authentication
    - A biometric factor uses either physiological identifiers, biometrica,behavioral identifiers
    - The identifiers are scanned and recorded as a template. When the user authenticates, another scan is taken and compared to the template.

### Authentication Design
Authentication design refers to selecting a technology that meets requirements for confidentiality, integrity, and availability
- Confidentiality
    - If details are leaked impersonation becomes an option and have their rights(authority)

- Integrity 
    - Ensures it is reliable by not allowing threat actors to bypass n=and trick with counterfeit data

- Availability 
    - Means that the time taken to authenticate does not impede workflows and is easy enough for users to operate.

### MultiFactor Authentication(MFA)
- It combines more than one type of knowledge
- 2-Factor Authentication - combines either an ownership-based smart card or biometric identifier with something you know, such as a password or PIN. 
- Three-factor authentication combines all three technologies, or incorporates an additional attribute, such as location;

### Authentication Attributes
Its either a non-unique property or a factor that cannot be used independently.
- Somwehere You Are Authentication
    - Its location based about where u are, It relies on IP address to detern=mine net segmentor location service(DPS).

- Something You Can Do Authentication
    - Behaviours can identify to a considerable degree.Not practicable for primary authentication unless continual and contexual

- Something You Exhibit Authentication
    - Also focuses on behaviour with emphasis on personality.

- Something You Know Authentication
    - It uses a web of trust model, where new users are vouched for by existing users. As the user participates in the network, their identity becomes better established. One example is the decentralized web of trust model, used by Pretty Good Privacy (PGP) as an alternative to PKI
    [link](weboftrust.info/index.html).

## Implimenting Knowledge-Based Authentication
It refers primarily to issuing users with password-based account access mechanisms and relies on cryptographic hashes.

Authentication provider - s/w architecture code that underpins the mechanism before starting a shell.Login(Linus), Logon(windows). Basic Configuration using a password/PIN relying on cryptography hashes.
The password hash is stored in DB and when authenticating the hashes are compared.

### Windows Authentication
More on windows auth [link](docs.microsoft.com/en-us/windows-server/security/windows-authentication/credentials-processes-in-windows-authentication)
- Local Signin
    - LSA compares submitted credentials to a hash stored in Security Accounts Manager(SAM) file part of registry.(Interactive logon)
    - It uses NTLM suite protocol
        - Vulnerable to pass-the-hash attacks.
    - Local Security Authority(LSA)
        - A protected subsystem that authenticates and signs users to the local computer
        - Maintains information about all aspects of local security(Local Policy)
        - Provides various services for translation btwn names and security identifiers(SIDs)
        - These policies are Stored in Sctive Directory. 
        - Provides services for validating access to objects, checking user rights, and generating audit messages.

- Network Signin
    - LSA can pass credentials to a network service(KERBEROS) but legacy apps use NT LAN Manager(NTLM/) authenticaion
    - KERBROS is the preffered network authentication

- Remote Signin
    - if the user's device is not connected to the local network, authentication can take place over some type of virtual private network (VPN) or web portal.

- Windows Server
    - Authentication through the SSPI(Security Support Provider Interface), it is an API that offers for authentication, message integrity, message privacy, and security quality-of-service for any distributed application protocol.
    
### Linux Authentication
- Local user accounts are stored in /etc/passwd. When user logs in password is checked against a hash stored in /etc/shadow
- Interactive login over a network is typically accomplished using Secure Shell (SSH). With SSH, the user can be authenticated using cryptographic keys instead of a password.
- A <u>Pluggable Authentication Modeule(PAM)</u> is a package for enabling diff authentication providers such as smart-card login[link](tecmint.com/configure-pam-in-centos-ubuntu-linux)
- The PAM framework can also be used to implement authentication to network servers.

### Single Sign-On(SSO)
- SSO system allows the user to authenticate once to a local device and be authenticated to compatible application servers without having to enter credentials again. 
- In Windows, SSO is provided by the Kerberos framework.

## Kerberos 
### Authentication
Its a Single Sign-on authentication and authorization protocol used on many networks, as implimented by Microsoft`s Active Directory(AD) service.
Consists of 3 parts
- Key Distribution Center
    It performs two functions, Authentication and Tickect Granting. Runs on port 88 uses both TCP and UDP.
    - The Client sends the Authentication server a <u>Tcket Granting Ticket(TGT) request </u>.
        - Composed by encrypting the date and time on local comp with the user`s password hash as the key.
        - Time stamping is used to prevent replay attacks

    - The Authentication Server(AS) 
        - If it decodes the request by matching the users`s password hash with the one in AD DB and request has not expired.
        - If valid the AS sends client
            - <u>Ticket Granting Ticket</u> - Contains clients info(name, IP) plus a timestamp and validity period.
                - Encrypted using KDC`s secret key

            - <u>Ticket Granting Service session key</u> - For use in communication between client and Ticket Granting Service
                - Encrypted using users password. 

    - Ticket Granting Service(TGS)   
        - Client sends the Ticket Granting Ticket with the request of application server it wants,timestamped client id where TGS will decrypt it with the KDC shared key. encrypted with the TGS session key.
        - TGS issues the client a token encrypted secret key shared btwn TGS and Application Server

    - The client Sends the token to the application server
    - The Application Server sends encrypted token with the TGS shared key 
    - The client is then able to send and receive data through the application server

### Authorization
After authentication, authorization to resources starts
 - Ticket Granting Service(TGS)   
    - Client sends the Ticket Granting Ticket with the application server it wants,timestamped client id where TGS will decrypt it with the KDC shared key. encrypted with the TGS session key.
    - TGS issues the client a token encrypted secret key shared btwn TGS and Application Server
- TGS responds with 
    - Service Session Key - for use between the client and the application server. This is encrypted with the TGS session key.
    - Service Ticket - containing information about the user, such as a timestamp, system IP address, Security Identifier (SID)  encrypted using the application server's secret key.
- The Client sends service ticket(cannot decrypt) add timestanmped authenticator encrypted using service session key
- Application Server decrypts the service ticket using its secret key, the using service session key, confirming that the client has sent an untampered message. It then decrypts the authenticator using the service session key.
- - the application server responds to the client with the timestamp used in the authenticator, which is encrypted by using the service session key. The client decrypts the timestamp and verifies that it matches the value already sent, and concludes that the application server is trustworthy.
- The server now responds to client requests (assuming they conform to the server's access control list).

This offer remote access protocols
### Password Authentication Protocol(PAP)
Unsophisticated authentication method developed as part of the Point-to-Point Protocol (PPP), used to transfer TCP/IP data over serial or dial-up connections. Used in HTTP, it relies on clear text password exchange and is therefore obsolete

### Challenge Handshake Authentication Protocol(CHAP)
Developed as part of PPP as a means of authenticating users over a remote link. CHAP relies on an encrypted challenge in a system called a three-way handshake.
- Challenge - the server challenges the client, sending a randomly generated challenge message.
- Response - the client responds with a hash calculated from the server challenge message and client password (or other shared secret).
- Verification - the server performs its own hash using the password hash stored for the client. If it matches the response, then access is granted; otherwise, the connection is dropped.
- Problems
    - Vulnerable causes it uses NTLM Vulnerable hashes
    - Needs secure communication
### MS-CHAPv2
Microsoft's implementation of CHAP. Because of the way it uses vulnerable NTLM hashes, MS-CHAP should not be deployed without the protection of a secure connection tunnel so that the credentials being passed are encrypted. 

## Password Attacks
The password is converted to a hash using a cryptographic function, such as MD5 or SHA.
Some exploit weak credentials chosen by users, some in storage mechanism. Windows SAM SB can be configured to store hashes in older versions(LM & NTLM1 hashes) for compatibility and they are cryptographically weak and highly vulnerable to password cracking.
- Plaintext/Unencrypted Attacks
    - Exploits password storage or a network authentication protocol that does not use encryption. 
    - PAP, basic HTTP/FTP, Telnet
    - Passwords embedded in application code that has subsequently been uploaded to a public repository.

- Online Attacks
    - Where the threat actor interacts with authentication service directly
    - Online tools Brutus, Medusa, THC Hydra, 
    - Password and username DBs [url](haveibeenpwned.com)
    - Suppressing the number of logons per time/ what time can be the soln

- Password Spraying
    - Horizontal brute-force online attack
    - Attacker choses one or more common passwords then with multiple usernames

- Offline Attack
    - It means the attacker has managed to obtain a DB of password hashes
    - Windows
        > %SystemRoot%\System32\config\SAM, %SystemRoot%\NTDS\NTDS.DIT
    - Linux 
        > /etc/passwd
    - Only indicator is audit of file system log. They can read credentials from host memory in which case the only reliable indicator might be the presence of attack tools on a host.
        - Credential dumping tool
            - Mimikatz [link](attack.mitre.org/software/S0002)
    
    - A packet sniffer might be used to obtain client response to a server challenge in a protocol such as NTLM or CHAP/MS-CHAP. 
        - Although these protocols avoid sending the hash of the password directly, the response is derived from it in some way. 
        -  Password crackers can exploit weaknesses in a protocol to calculate the hash and match it to a dictionary word or brute force it.
        

#### Brute-Force 
- attempts every possible combination in the output space in order to match a captured hash and guess at the plaintext that generated it.
- Output is by determined number of bit of algo / length of characters in plaintext and more complicated
- Limited by time required or computing resources distribution among h/w components
- Multi h/w components, like high end graphics card can crack even larger passwords

#### Dictionary Attacks
- A dictionary attack can be used where there is a good chance of guessing the likely value of the plaintext, such as a non-complex password. The software generates hash values from a dictionary of plaintexts to try to match one to a captured hash.

#### Rainbow Attack Tables
Rainbow table attacks refine the dictionary approach.
The attacker uses a precomputed lookup table of all possible passwords and their matching hashes. Not all possible hash values are stored, as this would require too much memory. Values are computed in chains, and only the first and last values need to be stored. The hash value of a stored password can then be looked up in the table and the corresponding plaintext discovered.

Using salt to add random value to the plain text as it helps in slowing rainbow attacks as the hashes will not have been computed

Impractical in discovering long passwords + unix/linux use salt in their storage mechanism

#### Hybrid Attack
It uses a combination of attack methods when trying to crack a password. A typical hybrid password attack uses a combination of dictionary and brute force attacks. It is principally targeted against naïve passwords with inadequate complexity, such as james1. 

#### Password Cracking Tools
- John The Ripper
- Hashcat
    > hashcat -m HashType -a AttackMode -o OutputFile InputHashFile

#### Authentication Management 
An authentication management solution for passwords mitigates this risk by using a device or service as a proxy for credential storage

Password key—USB tokens for connecting to PCs and smartphones. Some can use nearfield communications (NFC) or Bluetooth as well as physical connectivity (theverge.com/2019/2/22/18235173/the-best-hardware-security-keys-yubico-titan-key-u2f).

Password vault—software-based password manager, typically using a cloud service to allow access from any device (pcmag.com/picks/the-best-password-managers). A USB key is also likely to use a vault for backup. Most operating systems and browsers implement native password vaults. Examples include Windows Credential Manager and Apple's iCloud Keychain (imore.com/icloud-keychain).

## Implimenting Authentication Technologies
Can be used as something you have/ possess / own. Smart cards
### Key Management Devices
- Provisioned to work as non-user devices
- Hardware security module(HSM) - a network appliance designed to perform centralized PKI management for a network of devices.This means that it can act as an archive or escrow for keys in case of loss or damage.
    - strength cryptographically secure pseudorandom number generators (CSPRNGs). 
#### Smart Card Authentication
Programming cryptographic information onto a card equipped with a secure processing chip. The chip stores the user's digital certificate, the private key associated with the certificate, and a personal identification number (PIN) used to activate the card. 


For kerbros it requires a cryptoprocessor
- The user presents the smart card to a reader and is prompted to enter a PIN.
- Inputting the correct PIN authorizes the smart card's cryptoprocessor to use its private key to create a Ticket Granting Ticket (TGT) request, which is transmitted to the authentication server (AS). 
- The AS is able to decrypt the request because it has a matching public key and trusts the user's certificate, either because it was issued by a local certification authority or by a third-party CA that is a trusted root CA.
- The AS responds with the TGT and Ticket Granting Service (TGS) session key.

#### Usb key 
A cryptoprocessor can also be implemented in the USB form factor.

#### Trusted Platform Module(TPM)
A secure cryptoprocessor enclave implemented on a PC, laptop, smartphone, or network appliance. The TPM is usually a module within the CPU. Modification of TPM data is only permitted by highly trusted processes.

#### Extensible Authentication Protocol(IEEE802.1X)
Used where the computer is not attached to the local network and the user is logging on to Windows.When the user is accessing a wireless network and needs to authenticate with the network database. When a device is connecting to a network via a switch and network policies require the user to be authenticated before the device is allowed to communicate. When the user is connecting to the network over a public network via a virtual private network (VPN).

Extensible Authentication Protocol(EAP) - provides framework for deploying multiple types of authentication protocols and technologies. There are diff techs, Many use digital certs , then creating a secure tunnel without user password.

IEEE802.1X Port-based Network Access Control(NAC) standard provides means of using an EAP method when a device connects thru Ethernet, access point(enterprise),VPN gateway. 802.1X uses authentication, authorization, and accounting (AAA) architecture :-

    Supplicant - the device requesting access, such as a user's PC or laptop.
    Network Access Server(NAS) - edge network appliances, such as switches, access points, and VPN gateways. These are also referred to as RADIUS clients or authenticators.
    AAA server - the authentication server, positioned within the local network.

There are 2 types of AAA servers, RADIUS and TACACS+.

### Remote Authentication Dial-in User Service(RADIUS)
The Network Access Server(NAS)/Network AccessPoint(NAP) device(RADIUS client) is condifgured with IP address of RADIUS server and with shared secret

Primarily used for network access control. AAA Services  used for the purpose of centralizing logins for the administrative accounts for network appliances.This allows network administrators to be allocated specific privileges on each switch, router, access point, and firewall. 

- The user's device (the supplicant) makes a connection to the NAS appliance, such as an access point, switch, or remote access server. NAS is configured with shared key to communicate to RADIUS AAA server
- NAS promts user for auth details. It supports PAP,CHAP,EAP. If EAP, NAS enables supplicant to submit over <u>EAP over LAN(EAPol)</u> data bt no other traffic
- Supplicant submits credentials as EAPoL. RADIUS client uses it to create an Access-Request packet encrypted with shared key.
It sends the packet to AAA server on UDP port 1812 (default)
- AAA decrypts using shared key, if correct server responds
    - With EAP, there will be an exchange of Access-Challenge and Access-Request packets as the authentication method is set up and the credentials verified. The NAS acts as a pass-thru, taking RADIUS messages from the server, and encapsulating them as EAPoL to transmit to the supplicant.
- At the end of this exchange, if the supplicant is 
authenticated, the AAA server responds with an Access-Accept packet; otherwise, an Access-Reject packet is returned

Optionally, the NAS can use RADIUS for accounting (logging). Accounting uses port 1813. The accounting server can be different from the authentication server.

### Terminal Access Controller Access-Control System(TACACS+)
Primarily designed network administration role.\
It uses TCP cmmunication port 49 making it easier to detect when a server is down.\
All packets are encrypted(except header identifying packet as TACACS). Ensures confidentiality & integrity when trasferring data.\
Authentication, authorization, and accounting functions are discrete. It supports reauthentication better than RADIUS./

#### Token Keys
* One-Time Password(OTP).\
    One that is generated automatically, rather than being chosen by a user, and used only once.\
    Not vulnerable to password guessing or sniffing attacks.\
    An OTP is generated using some sort of hash function on a secret value plus a synchronization value (seed), such as a timestamp or counter.

* Static codes -  transmit a static token programmed into the device. For example, many building entry systems work on the basis of static codes. These mechanisms are highly vulnerable to cloning and replay attacks.

There are other diff ways of implimenting h/w tokens
- Fast Identity Online(FIDO)
- Universal Second Factor(U2F)

### Open Authentication
The Initiative for Open Authentication (OATH) is an industry body established with the aim of developing an open, strong authentication framework.

#### HMAC-Based One-Time Password(HOTP)
An algo for token based authentication.\
The authentication server and client token are configured with the same shared secret. This should be an 8-byte value generated by a cryptographically strong random number generator. The token could be a fob-type device or implemented as a smartphone.\

The Secret is combined with a counter to create a one time password when user wants to authenticate. The device and server both compute the hash and derive an HOTP value that is 6-8 digits long. This is the value that the user must enter to authenticate with the server. The counter is incremented by one.

One issue with HOTP is that tokens can be allowed to persist unexpired, raising the risk that an attacker might be able to obtain one and decrypt data in the future. 
#### Time Based One Time Password(TOTP)
A refinement of HOTP.\
In TOTP, the HMAC is built from the shared secret plus a value derived from the device's and server's local timestamps. TOTP automatically expires each token after a short window (60 seconds, for instance).\
For this to work, the client device and server must be closely time-synchronized. One well-known implementation of HOTP and TOTP is Google Authenticator.

#### 2-Step Verification
Generate a software token on a server and send it to a resource assumed to be safely controlled by the user. The token can be transmitted to the device in a number of ways:
- Short Message Service(SMS) - via text to the phone no.
- Phone Call - automated voice call
- Push notification - sent as a push or pop up on pc/phone
- Email - registered email

Anyone can intercept within the given time

## Biometrics Authentication Concepts
Allow users to access an account through a physiological feature (fingerprint or iris pattern, for instance) or behavioral pattern. 

### Biometric Authentication
It starts with enrollement.\
The chosen biometric information is scanned by a biometric reader and converted to binary information.(fingerprint, eye, and facial recognition) or behavioral (voice, signature, and typing pattern matching). 
Scanning process
- A sensor module acquires the biometric sample from the target.
- A feature extraction module records the features in the sample that uniquely identify the target.

Biometric is stored in authentication DB.\
Efficiency is on acquisition and matching of :-
- False Rejection Rate(FRR) - legitimate user is not recognized
    - Type I error or false non-match rate (FNMR). 
    - FRR is measured as a percentage.

- False Acceptance Rate(FAR) - illegitimate is accepted
    - Type II error or false match rate [FMR].
    - FAR is measured as a percentage.

- Crossover Error Rate(CER) - point at which FRR and FAR meet
    - The lower the efficient and more reliable

- Speed(throughput) - Time to create user and authenticate
    - Considered when more traffic

- Failure to Enroll(FER) - incidents in which a template cannot be created and matched for a user during enrollment.

- Cost/implementation—some scanner types are more expensive, whereas others are not easy to incorporate on mobile devices.

- Users can find it intrusive and threatening to privacy.

- The technology can be discriminatory or inaccessible to those with disabilities. 

### Facial Recognition
Facial recognition suffers from relatively high false acceptance and rejection rates and can be vulnerable to spoofing. Much of the technology development is in surveillance, rather than for authentication, although it is becoming a popular method for use with smartphones.

- Retinal Scan
    an infrared light is shone into the eye to identify the pattern of blood vessels.\
    The equipment required is expensive and the process is relatively intrusive and complex. False negatives can be produced by disease, such as cataracts.

- Iris Scan
    matches patterns on the surface of the eye using near-infrared imaging and so is less intrusive than retinal scanning (the subject can continue to wear glasses, for instance) and a lot quicker..\
    Iris scanning is the technology most likely to be rolled out for high-volume applications, such as airport security. There is a chance that an iris scanner could be fooled by a high-resolution photo of someone's eye.

### Behavioral Technologies
Something You Do, such as typing, writing a signature, or walking/moving. The variations in motion, pressure, or gait are supposed to uniquely verify each individual. In practice, however, these methods are subject to higher error rates, and are much more troublesome for a subject to perform

- Voice recognition - relatively cheap, as the hardware and software required are built into many standard PCs and mobiles. However, obtaining an accurate template can be difficult and time-consuming.Due to background noice/ interference

- Gait analysis - produces a template from human movement (locomotion). The technologies can either be camera-based or use smartphone features, such as an accelerometer and gyroscope.

- Signature recognition - signatures are relatively easy to duplicate, but it is more difficult to fake the actual signing process. Signature matching records the user applying their signature (stroke, speed, and pressure of the stylus).

- Typing - matches the speed and pattern of a user’s input of a passphrase.

Other functions of biometric
- Biometric identification
- Continuous authentication