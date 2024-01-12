# Secure Mobile Solutions

### Objectives
- Mobile Device Development
- Secure Mobile Device Connections

# Mobile Device Deployment
Mobile devices have replaced computers for many email and daily management tasks and are integral to accessing many other business processes and cloud-based applications. A mobile device deployment model describes the way employees are provided with mobile devices and applications.
- Bring Your Own Device(BYOD) - the mobile device is owned by the employee. The mobile will have to meet whatever profile is required by the company (in terms of OS version and functionality) and the employee will have to agree on the installation of corporate apps and to some level of oversight and auditing. This model is usually the most popular with employees but poses the most difficulties for security and network managers.

- Corporate owned, business only (COBO)—the device is the property of the company and may only be used for company business.

- Corporate owned, personally-enabled (COPE)—the device is chosen and supplied by the company and remains its property. The employee may use it to access personal email and social media accounts and for personal web browsing (subject to whatever acceptable use policies are in force).

- Choose your own device (CYOD)—much the same as COPE but the employee is given a choice of device from a list.

## Enterprise Mobility Management
Enterprise mobility management (EMM) is a class of management software designed to apply security policies to the use of mobile devices and apps in the enterprise. The challenge of identifying and managing attached devices is often referred to as visibility. EMM software can be used to manage enterprise-owned devices as well as BYOD. There are two main functions of an EMM product suite:
- Mobile device management (MDM)—sets device policies for authentication, feature use (camera and microphone), and connectivity. MDM can also allow device resets and remote wipes.
- Mobile application management (MAM)—sets policies for apps that can process corporate data, and prevents data transfer to personal apps. This type of solution configures an enterprise-managed container or workspace.

Unified endpoint management (UEM) - Enterprise software for controlling device settings, apps, and corporate data storage on all types of fixed, mobile, and IoT computing devices.\
The core functionality of endpoint management suites extends the concept of network access control (NAC) solutions. The management software logs the use of a device on the network and determines whether to allow it to connect or not, based on administrator-set parameters. When the device is enrolled with the management software, it can be configured with policies to allow or restrict use of apps, corporate data, and built-in functions, such as a video camera or microphone.

## IOS in the Enterprise
In Apple's iOS ecosystem, third-party developers can create apps using Apple's Software Development Kit, available only on macOS. Apps have to be submitted to and approved by Apple before they are released to users via the App Store. Corporate control over iOS devices and distribution of corporate and B2B (Business-to-Business) apps is facilitated by participating in the Device Enrollment Program (support.apple.com/business), the Volume Purchase Program, and the Developer Enterprise Program (developer.apple.com/programs/enterprise). Another option is to use an EMM suite and its development tools to create a "wrapper" for the corporate app.

## Android in the Enterprise
The app model is also more relaxed, with apps available from both Google Play and third-party sites, such as Amazon's app store. The SDK is available on Linux, Windows, and macOS. The Android Enterprise (android.com/enterprise) program facilitates use of EMM suites and the containerization of corporate workspaces. Additionally, Samsung has a workspace framework called KNOX (samsung.com/us/business/solutions/samsung-knox) to facilitate EMM control over device functionality.

Since version 4.3, Android has been based on Security-Enhanced Linux. SEAndroid (source.android.com/security/selinux) uses mandatory access control (MAC) policies to run apps in sandboxes. When the app is installed, access is granted (or not) to specific shared features, such as contact details, SMS texting, and email. 

## Mobile Access Control Systems
Smartphone Authentication\
Access control can be implemented by configuring a screen lock that can only be bypassed using the correct password, PIN, or swipe pattern. Many devices now support biometric authentication, usually as a fingerprint reader but sometimes using facial or voice recognition.

Screen Lock\
The screen lock can also be configured with a lockout policy. This means that if an incorrect passcode is entered, the device locks for a set period and can be escalated.

Context-Aware Authentication\
It is also important to consider newer authentication models, such as context-aware authentication. For example, smartphones now allow users to disable screen locks when the device detects that it is in a trusted location, such as the home. Conversely, an enterprise may seek more stringent access controls to prevent misuse of a device. For example, even if the device has been unlocked, accessing a corporate workspace might require the user to authenticate again.

## Remote Wipe
A remote wipe or kill switch means that if the handset is stolen it can be set to the factory defaults or cleared of any personal data (sanitization). Some utilities may also be able to wipe any plug-in memory cards too. The remote wipe could be triggered by several incorrect passcode attempts or by enterprise management software. Other features include backing up data from the phone to a server first and displaying a "Lost/stolen phone—return to XX" message on the handset.

## Full device Encryption and External media
Only the key is wiped rather than all the storage locations.\
Email data and any apps using the "Data Protection" option are subject to a second round of encryption using a key derived from and protected by the user's credential. This provides security for data in the event that the device is stolen.

## Location Services
Geolocation is the use of network attributes to identify (or estimate) the physical position of a device. Location services can make use of two systems:

- Global Positioning System (GPS)—a means of determining the device's latitude and longitude based on information received from satellites via a GPS sensor.
- Indoor Positioning System (IPS)—works out a device's location by triangulating its proximity to other radio sources, such as cell towers, Wi-Fi access points, and Bluetooth/RFID beacons.

## Application management
When a device is joined to the corporate network through enrollment with management software, it can be configured into an enterprise workspace mode in which only a certain number of authorized applications can run.

Unlike iOS, Android allows for selection of different stores and installation of untrusted apps from any third party, if this option is enabled by the user. With unknown sources enabled, untrusted apps can be downloaded from a website and installed using the .apk file format. This is referred to as sideloading.\
Conversely, a management suite might be used to prevent the use of third-party stores or sideloading and block unapproved app sources.

## Content Management
Containerization allows the employer to manage and maintain the portion of the device that interfaces with the corporate network. An enterprise workspace with a defined selection of apps and a separate container is created. This container isolates corporate apps from the rest of the device. There may be a requirement for additional authentication to access the workspace.

The container can also enforce storage segmentation. With storage segmentation the container is associated with a directory on the persistent storage device that is not readable or writable by apps that are not in the container. Conversely, apps cannot write to areas outside the container, such as external media or using copy and paste to a non-container app. App network access might be restricted to a VPN tunneled through the organization's security system.

Containerization also assists content management and data loss prevention (DLP) systems. A content management system tags corporate or confidential data and prevents it from being shared or copied to unauthorized external media or channels, such as non-corporate email systems or cloud storage services. 

## Rooting
- Rooting—this term is associated with Android devices. Some vendors provide authorized mechanisms for users to access the root account on their device. For some devices it is necessary to exploit a vulnerability or use custom firmware. Custom firmware is essentially a new Android OS image applied to the device. This can also be referred to as a custom ROM, after the term for the read only memory chips that used to hold firmware.

- Jailbreaking—iOS is more restrictive than Android so the term "jailbreaking" became popular for exploits that enabled the user to obtain root privileges, sideload apps, change or add carriers, and customize the interface. iOS jailbreaking is accomplished by booting the device with a patched kernel. For most exploits, this can only be done when the device is attached to a computer when it boots (tethered jailbreak)

- Carrier unlocking—for either iOS or Android, this means removing the restrictions that lock a device to a single carrier.

# Mobile Device Connections
As well as authentication and authorization for features and apps, management suites can also assist with networking options for mobile. You must be able to disable communication types that are not secure for local networks, and advise users about the security of communications when they use their devices remotely.

## Cellular and GPS Connection methods
Cellular Data Connections
Smartphones and some tablets use the cell phone network for calls and data access. A cellular data connection is less likely to be subject to monitoring and filtering. It may be appropriate to disable it when a device has access to an enterprise network or data, to prevent its use for data exfiltration.

Global Positioning System (GPS)
A global positioning system (GPS) sensor triangulates the device position using signals from orbital GPS satellites. As this triangulation process can be slow, most smartphones use Assisted GPS (A-GPS) to obtain coordinates from the nearest cell tower and adjust for the device's position relative to the tower. A-GPS uses cellular data. GPS satellites are operated by the US Government. Some GPS sensors can use signals from other satellites, operated by the EU (Galileo), Russia (GLONASS), or China (BeiDou).\
GPS signals can be jammed or even spoofed using specialist radio equipment. This might be used to defeat geofencing mechanisms, for instance (kaspersky.com/blog/gps-spoofing-protection/26837).

## Wi-Fi and Tethering Connection Methods
Mobile devices usually default to using a Wi-Fi connection for data, if present. If the user establishes a connection to a corporate network using strong WPA3 security, there is a fairly low risk of eavesdropping or man-in-the-middle attacks. The risks from Wi-Fi come from users connecting to open access points or possibly a rogue access point imitating a corporate network

### Personal Area Networks(PANs)
Personal area networks (PANs) enable connectivity between a mobile device and peripherals.Ad hoc (or peer-to-peer) networks between mobile devices or between mobile devices and other computing devices can also be established. In terms of corporate security, these peer-to-peer functions should generally be disabled. It might be possible for an attacker to exploit a misconfigured device and obtain a bridged connection to the corporate network.

### Ad Hoc Wifi and Wifi Direct
Wireless stations can establish peer-to-peer connections with one another, rather than using an access point. This can also be called an ad hoc network, meaning that the network is not made permanently available. There is no established, standards-based support for ad hoc networking, however. MITRE have a project to enable Android smartphones to configure themselves in an ad hoc network (mitre.org/research/technology-transfer/open-source-software/smartphone-ad-hoc-networking-span).

Wi-Fi Direct allows one-to-one connections between stations, though in this case one of the devices actually functions as a soft access point. Wi-Fi Direct depends on Wi-Fi Protected Setup (WPS), which has many vulnerabilities. Android supports operating as a Wi-Fi Direct AP, but iOS uses a proprietary multipeer connectivity framework. You can connect an iOS device to another device running a Wi-Fi direct soft AP, however.

There are also wireless mesh products from vendors such as Netgear and Google that allow all types of wireless devices to participate in a peer-to-peer network. These products might not be interoperable, though more are now supporting the EasyMesh standard (wi-fi.org/discover-wi-fi/wi-fi-easymesh).

### Tethering and Hotspots
A smartphone can share its Internet connection with another device, such as a PC. Where this connection is shared over Wi-Fi with multiple other devices, the smartphone can be described as a hotspot. Where the connection is shared by connecting the smartphone to a PC over a USB cable or with a single PC via Bluetooth, it can be referred to as tethering. However, the term "Wi-Fi tethering" is also quite widely used to mean a hotspot. This type of functionality would typically be disabled when the device is connected to an enterprise network, as it might be used to circumvent security mechanisms, such as data loss prevention or a web content filtering policies.

## Bluetooth Connection Methods
Bluetooth is one of the most popular technologies for implementing Personal Area Networks (PANs). While native Bluetooth has fairly low data rates, it can be used to pair with another device and then use a Wi-Fi link for data transfer. This sort of connectivity is implemented by iOS's AirDrop feature.

Security issues
- Device discovery—a device can be put into discoverable mode meaning that it will connect to any other Bluetooth devices nearby. Unfortunately, even a device in non-discoverable mode is quite easy to detect.
- Authentication and authorization—devices authenticate ("pair") using a simple passkey configured on both devices. This should always be changed to some secure phrase and never left as the default. Also, check the device's pairing list regularly to confirm that the devices listed are valid.
- Malware—there are proof-of-concept Bluetooth worms and application exploits, most notably the BlueBorne exploit (armis.com/blueborne), which can compromise any active and unpatched system regardless of whether discovery is enabled and without requiring any user intervention. 

Unless some sort of authentication is configured, a discoverable device is vulnerable to bluejacking, a sort of spam where someone sends you an unsolicited text (or picture/video) message or vCard (contact details). 

Bluesnarfing refers to using an exploit in Bluetooth to steal information from someone else's phone. The exploit (now patched) allows attackers to circumvent the authentication mechanism. Even without an exploit, a short (4 digit) PIN code is vulnerable to brute force password guessing.

## Infrared and RFID Connection Methods
Infrared signaling has been used for PAN in the past (IrDA), but the use of infrared in modern smartphones and wearable technology focuses on two other uses:
- IR blaster - this allows the device to interact with an IR receiver and operate a device such as a TV or HVAC monitor as though it were the remote control handset.
- IR sensor—these are used as proximity sensors (to detect when a smartphone is being held to the ear, for instance) and to measure health information (such as heart rate and blood oxygen levels)

Radio Frequency ID (RFID) is a means of encoding information into passive tags, which can be easily attached to devices, structures, clothing, or almost anything else. A passive tag can have a range from a few centimeters to a few meters. When a reader is within range of the tag, it produces an electromagnetic wave that powers up the tag and allows the reader to collect information from it or to change the values encoded in the tag. There are also battery-powered active tags that can be read at much greater distances (hundreds of meters).

One type of RFID attack is skimming, which is where an attacker uses a fraudulent RFID reader to read the signals from a contactless bank card. Any reader can access any data stored on any RFID tag, so sensitive information must be protected using cryptography. It is also possible (in theory) to design RFID tags to inject malicious code to try to exploit a vulnerability in a reader.

## Near Field Communications and Mobile Payment Services
NFC is based on a particular type of radio frequency ID (RFID). NFC sensors and functionality are now commonly incorporated into smartphones. An NFC chip can also be used to read passive RFID tags at close range. It can also be used to configure other types of connections (pairing Bluetooth devices for instance) and for exchanging information, such as contact cards.

The typical use case is in "smart" posters, where the user can tap the tag in the poster to open a linked web page via the information coded in the tag. Attacks could be developed using vulnerabilities in handling the tag (securityboulevard.com/2019/10/nfc-false-tag-vulnerability-cve-2019-9295). It is also possible that there may be some way to exploit NFC by crafting tags to direct the device browser to a malicious web page where the attacker could try to exploit any vulnerabilities in the browser.

The widest application of NFC is to make payments via contactless point-of-sale (PoS) machines. To configure a payment service, the user enters their credit card information into a mobile wallet app on the device. The wallet app does not transmit the original credit card information, but a one-time token that is interpreted by the card merchant and linked back to the relevant customer account. There are three major mobile wallet apps: Apple Pay, Google Pay (formerly Android Pay), and Samsung Pay.

## USB Connection Methods
Some Android USB ports support USB On The Go (OTG) and there are adapters for iOS devices. USB OTG allows a port to function either as a host or as a device. For example, a port on a smartphone might operate as a device when connected to a PC, but as a host when connected to a keyboard or external hard drive. The extra pin communicates which mode the port is in.

There are various ways in which USB OTG could be abused. Media connected to the smartphone could host malware. The malware might not be able to affect the smartphone itself but could be spread between host computers or networks via the device. It is also possible that a charging plug could act as a Trojan and try to install apps (referred to as juice-jacking), though modern versions of both iOS and Android now require authorization before the device will accept the connection.

