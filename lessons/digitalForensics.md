# Digital Forensics

### Objectives
- Key aspects of Digital forensics documentation
- Key aspects of Digital forensics acquisition

# Digital Forensics Documentation
Documentation is critical to collecting, preserving, and presenting valid digital proofs. 

## Keys aspects
Digital forensics is the practice of collecting evidence from computer systems to a standard that will be accepted in a court of law.

- Evidence, Documentation and Admissibility 
- Legal Hold
- Chain of Custody

## Reports
- Performed without bias
- Repeatable by third parties
Not be altered or changed

## E-Discovery
It is a means of filtering relevant evidence produced from all gathered data and storing it in a db in a d=format that can be used as evidence in trial.
functions
- Identify and duplicate files and metadata
- Search - allow investigators to locate files of interest to the case
- Tags - standardized keywords or labels to files and metadata for organisation
- Security - evidence of no tampering
- Disclosure - made available to plaintiff and defedant

# Digital Forensics Acquisition
It is the process of obtainig copy of data from device held as evidence.

Proceeds by using a tool to make an image from data held on target device. The genral principle is from more voltile to less one.
- CPU registers and cache memory
- Contents of nonpersistent memory(RAM),routing table,ARP cache, process table,kernel statistics
- Data on persistent memory(HDDs,SSDs)
    - partion and file system blocks
    - System memory caches
    - Temporary file caches
    - User, application and OS files and directories
- Remote logging and monitoring data
- Physical configuration and network topology
- Archival media and printed documents

## Forensics Softwares
- EnCase Forensic - Case management is assisted by built-in pathways, or workflow templates, showing the key steps in diverse types of investigation. In addition to the core forensics suite, there are separate products for e-discovery (digital evidence management) and Endpoint Investigator (for over-the-network analysis of corporate desktops and servers).

- Forensic Toolkit(FTK) - is another commercial investigation suite designed to run on Windows Server (or server cluster).

- The Sleuth Kit - is an open-source collection of command line tools and programming libraries for disk imaging and file analysis. Autopsy is a graphical front-end for these tools and acts as a case management/workflow tool. The program can be extended with plug-ins for various analysis functions. Autopsy is available for Windows and Linux systems.

- X-Ways Forensics - is a commercial tool for forensic recovery and analysis of binary data, with support for a range of file systems and memory dump types (depending on version).

- The Volatility Framework (github.com/volatilityfoundation/volatility) is widely used for system memory analysis.

## System Memory Acquisition
It is volatile data held in RAM. A system memory dump creates an image file that can be analyzed to identify the processes that are running, the contents of temporary file systems, registry data, network connections, cryptographic keys, and more. It can also be a means of accessing data that is encrypted when stored on a mass storage device. 

- Live Acquisition -  specialist hardware or software tool can capture the contents of memory while the host is running.\ 
    - On Windows
        - WinHex
        - Memoryze 
        - F-Response
        - Tactical
    - On Linux
        - Memdump
        - pmem
        - fmem / LiME

- Crash Dump - When Windows encounters an unrecoverable kernel error, it can write contents of memory to a dump file at C:\Windows\MEMORY.DMP. On modern systems, there is unlikely to be a complete dump of all the contents of memory, as these could take up a lot of disk space. However, even mini dump files, stored in C:\Windows\Minidumps, may be a valuable source of information.

- Hibernation File and Pagefile - A hibernation file is created on disk in the root folder of the boot volume when a Windows host is put into a sleep state. If it can be recovered, the data can be decompressed and loaded into a software tool for analysis. The drawback is that network connections will have been closed, and malware may have detected the use of a sleep state and performed anti-forensics.\
The pagefile/swap file/swap partition stores pages of memory in use that exceed the capacity of the host's RAM modules. The pagefile is not structured in a way that analysis tools can interpret, but it is possible to search for strings.

## Disk Image Acquisition
Acquiring data from a nonvolatile storage.
- Live Acquisition - this means copying the data while the host is still running. This may capture more evidence or more data for analysis and reduce the impact on overall services, but the data on the actual disks will have changed, so this method may not produce legally acceptable evidence. It may also alert the adversary and allow time for them to perform anti-forensics.

- Static acquisition by shutting down the host - this runs the risk that the malware will detect the shutdown process and perform anti-forensics to try to remove traces of itself.

- Static acquisition by pulling the plug—this means disconnecting the power at the wall socket (not the hardware power-off button). This is most likely to preserve the storage devices in a forensically clean state, but there is the risk of corrupting data.

## Preservation and Integrity of Evidence
- A cryptographic hash of the disk media is made, using either the MD5 or SHA hashing function. The output of the function can be described as a checksum.
- A bit-by-bit copy of the media is made using the imaging utility.
- A second hash is then made of the image, which should match the original hash of the media.
- A copy is made of the reference image, validated again by the checksum. Analysis is performed on the copy.

