# awesome-winows-redteam-tools

The awesome windows red team tools and guides you through tools for post-explosion, C&C, and simulation.

This is a list of [Free](https://en.wikipedia.org/wiki/Free_software) Software and Non-Free software.


**Contributing:**


Thanks to all [contributors](https://github.com/offense360/awesome-winows-redteam-tools); you rock!


> _If you see a package or project here that is no longer maintained or is not a good fit, please submit a pull request to improve this file. Thank you!_

--------------------
  
## Table of contents  

<!-- TOC start -->

- [Windows Enemeration](#windows-enemeration)
  - [Unclassified]
  - [Powershell]
  - [C#]
  - [Articles]
- [Windows Privilege Escalation](#windows-privilege-escalation)
  - [Unclassified]
  - [Articles]
- [Windows Post Exploitation](#windows-post-exploitation)
  - [Powershell]
  - [Articles]
- [C2](#c2)
  - [Multi Platform]
  - [Windows]
  - [Unclassified]
- [BAS OR Lab](#bas-or-lab)
  - [Multi Platform]
  - [Legacy]
  - [AWS]
  - [Azure]
- [Ariticles]

<!-- TOC end -->

--------------------

## Windows Enemeration

<!-- BEGIN Enemeration LIST -->


### Unclassified

**[`^        back to top        ^`](#)**


- [BloodHound](https://github.com/BloodHoundAD/BloodHound) - BloodHound is an Active Directory (AD) reconnaissance tool that can reveal hidden relationships and identify attack paths within an AD environment. , [Document](https://bloodhound.readthedocs.io/en/latest/index.html)

- [ADExplorerSnapshot](https://github.com/c3c/ADExplorerSnapshot.py) - ADExplorerSnapshot.py is an AD Explorer snapshot parser. It is made as an ingestor for [BloodHound](https://bloodhound.readthedocs.io/), and also supports full-object dumping to NDJSON. AD Explorer allows you to connect to a DC and browse LDAP data. It can also create snapshots of the server you are currently attached to. This tool allows you to convert those snapshots to BloodHound-compatible JSON files, or dump all available objects in the snapshot to NDJSON for easier processing.

- [PlumHound](https://github.com/PlumHound/PlumHound) - PlumHound operates by wrapping BloodHoundAD's powerhouse graphical Neo4J backend cypher queries into operations-consumable reports. Analyzing the output of PlumHound can steer security teams in identifying and hardening common Active Directory configuration vulnerabilities and oversights.

- [ImproHound](https://github.com/improsec/ImproHound) - Identify the attack paths in BloodHound breaking your AD tiering. ImproHound is a dotnet standalone win x64 exe with GUI. To use ImproHound, you must run SharpHound to collect the necessary data from the AD.

- [BloodHound.py](https://github.com/fox-it/BloodHound.py) - BloodHound.py is a Python based ingestor for [BloodHound](https://github.com/BloodHoundAD/BloodHound), based on [Impacket](https://github.com/CoreSecurity/impacket/).


### Powershell

**[`^        back to top        ^`](#)**


- [Access to Memory (AtoM)](https://www.accesstomemory.org/) - A lightweight tool to quickly extract valuable information from the Active Directory environment for both attacking and defending. , [Source Code](https://github.com/dev-2null/ADCollector)) `C#`



### Csharp

**[`^        back to top        ^`](#)**


- [ADCollector](https://github.com/dev-2null/ADCollector) - A lightweight tool to quickly extract valuable information from the Active Directory environment for both attacking and defending. , [Source Code](https://github.com/dev-2null/ADCollector) `C#`


### Articles

**[`^        back to top        ^`](#)**


- [awesome-bloodhound](https://github.com/chryzsh/awesome-bloodhound) - A curated list of awesome BloodhoundAD resources
- [Easy Domain Enumeration with ADSI](https://dev-2null.github.io/Easy-Domain-Enumeration-with-ADSI/)
- [Windows Enumeration](https://nored0x.github.io/red-teaming/windows-enumeration/) by NoRed0x
- [SPN scan](https://www.codetd.com/en/article/7383878/) by codetd


## Windows Privilege Escalation

<!-- BEGIN Windows Privilege Escalation LIST -->


### Unclassified

**[`^        back to top        ^`](#)**


- [Impacket](https://github.com/p3nt4/impacket/) - Impacket is a collection of Python classes for working with network protocols. Impacket is focused on providing low-level programmatic access to the packets and for some protocols (e.g. SMB1-3 and MSRPC) the protocol implementation itself. References [https://www.secureauth.com/labs/open-source-tools/impacket/](https://www.secureauth.com/labs/open-source-tools/impacket/)

- [BloodyAD](https://github.com/CravateRouge/bloodyAD) - BloodyAD is an Active Directory Privilege Escalation Framework, it can be used manually using `bloodyAD.py` or automatically by combining `pathgen.py` and `autobloody.py`.   This framework supports NTLM (with password or NTLM hashes) and Kerberos authentication and binds to LDAP/LDAPS/SAMR services of a domain controller to obtain AD privesc. It is designed to be used transparently with a SOCKS proxy.  

- [Krbrelayx](https://github.com/dirkjanm/krbrelayx) - Toolkit for abusing Kerberos. Requires [impacket](https://github.com/SecureAuthCorp/impacket), [ldap3](https://github.com/cannatag/ldap3) and dnspython to function. It is recommended to install impacket from git directly to have the latest version available.  [Document](https://dirkjanm.io/krbrelayx-unconstrained-delegation-abuse-toolkit/)

- [BeRoot](https://github.com/AlessandroZ/BeRoot) - BeRoot Project is a post exploitation tool to check common misconfigurations to find a way to escalate our privilege.  

- [Powerview](https://github.com/the-useless-one/pywerview) - A (partial) Python rewriting of [PowerSploit](https://github.com/PowerShellMafia/PowerSploit)'s [PowerView](https://github.com/PowerShellMafia/PowerSploit/tree/master/Recon).


### Articles - Guide and Checklists

**[`^        back to top        ^`](#)**


- [Windows Privilege Escalation Fundamentals by fuzzysecurity](http://www.fuzzysecurity.com/tutorials/16.html)
- [Windows Privilege Escalation guide](https://github.com/netbiosX/Checklists/blob/master/Windows-Privilege-Escalation.md)
- [Privilege Escalation Windows - OSCP](https://sushant747.gitbooks.io/total-oscp-guide/content/privilege_escalation_windows.html) - We now have a low-privileges shell that we want to escalate into a privileged shell.
- [Understanding Lateral Movement and Privilege Escalation](https://stealthbits.com/blog/understanding-lateral-movement-and-privilege-escalation/) by stealthbits
- [Checklist - Local Windows Privilege Escalation](https://book.hacktricks.xyz/windows/checklist-windows-privilege-escalation) by hacktricks
- [Active Directory forest trusts part 1 - How does SID filtering work?](https://dirkjanm.io/active-directory-forest-trusts-part-one-how-does-sid-filtering-work/) by Dirk-jan Mollema
- [Active Directory forest trusts part 2 - Trust transitivity and finding a trust bypass](https://dirkjanm.io/active-directory-forest-trusts-part-two-trust-transitivity/) by Dirk-jan Mollema


## Windows Post Exploitation

<!-- BEGIN Windows Post Exploitation LIST -->


### Windows

**[`^        back to top        ^`](#)**


- [Mimikatz](https://github.com/gentilkiwi/mimikatz/) - A little tool to play with Windows security  [Document](https://blog.gentilkiwi.com/mimikatz) 

- [UACME](https://github.com/hfiref0x/UACME) - Defeating Windows User Account Control

- [Rubeus](https://github.com/GhostPack/Rubeus) - Rubeus is a C# toolset for raw Kerberos interaction and abuses.  

- [PowerHub](https://github.com/AdrianVollmer/PowerHub/) - PowerHub is a convenient post exploitation tool for PowerShell which aids a pentester in transferring data, in particular code which may get flagged by endpoint protection. , [Document](https://github.com/AdrianVollmer/PowerHub/wiki/)


### Multi Platform

**[`^        back to top        ^`](#)**


- [Mythic](https://github.com/its-a-feature/Mythic) - A cross-platform, post-exploit, red teaming framework built with python3, docker, docker-compose, and a web browser UI.  

- [Merlin](https://github.com/Ne0nd0g/merlin) - Merlin is a cross-platform post-exploitation Command & Control server and agent written in Go. [Document](https://merlin-c2.readthedocs.io/en/latest/)

### Unclassified

**[`^        back to top        ^`](#)**


- [ibombshell - Dynamic Remote Shell](https://github.com/Telefonica/ibombshell/) - ibombshell is a tool written in Powershell that allows you to have a prompt at any time with post-exploitation functionalities (and in some cases exploitation).

### Articles - Guide and Checklists

**[`^        back to top        ^`](#)**


- [How To Attack Kerberos 101](https://m0chan.github.io/2019/07/31/How-To-Attack-Kerberos-101.html) by m0chan
- [Next-Gen Open Source C2 Frameworks in a Post PSEmpire World: Covenant](https://stealthbits.com/blog/next-gen-open-source-c2-frameworks/) by stealthbits
- [Windows Domains, Pivot & Profit](http://www.fuzzysecurity.com/tutorials/25.html)


## C2

<!-- BEGIN C&C LIST -->


### Multi Platform

**[`^        back to top        ^`](#)**


- [PoshC2](https://github.com/nettitude/PoshC2) - PoshC2 is a proxy aware C2 framework used to aid penetration testers with red teaming, post-exploitation and lateral movement. [Document](https://poshc2.readthedocs.io/en/latest/index.html)

- [Sliver](https://github.com/BishopFox/sliver) - Sliver is an open source cross-platform adversary emulation/red team framework, it can be used by organizations of all sizes to perform security testing. The server and client support MacOS, Windows, and Linux. Implants are supported on MacOS, Windows, and Linux. [Document](https://github.com/BishopFox/sliver/wiki/Getting-Started)  

- [Nuages](https://github.com/p3nt4/Nuages) - Nuages aims at being a C2 framework in which back end elements are open source, whilst implants and handlers must be developed ad hoc by users. [Document](https://github.com/p3nt4/Nuages/wiki/)  

- [Merlin](https://github.com/Ne0nd0g/merlin) - Merlin is a cross-platform post-exploitation Command & Control server and agent written in Go. [Document](https://merlin-c2.readthedocs.io/en/latest/)


### Windows

**[`^        back to top        ^`](#)**


- [Covenant](https://github.com/cobbr/Covenant) - Covenant is a .NET command and control framework and web application that aims to highlight the attack surface of .NET, make the use of offensive .NET tradecraft easier, and serve as a collaborative command and control platform for red teamers. [Document](https://github.com/cobbr/Covenant/wiki)  

- [Octops](https://github.com/mhaskar/Octopus) - Octopus is an open source, pre-operation C2 server based on python which can control an Octopus powershell agent through HTTP/S.


### Unclassified

**[`^        back to top        ^`](#)**


- [SILENTTRINITY](https://github.com/byt3bl33d3r/SILENTTRINITY/) - SILENTTRINITY is modern, asynchronous, multiplayer & multiserver C2/post-exploitation framework powered by Python 3 and .NETs DLR. [Document](https://github.com/byt3bl33d3r/SILENTTRINITY/wiki/) by [Defensive Origins](https://defensiveorigins.com/)  

- [ibombshell - Dynamic Remote Shell](https://github.com/Telefonica/ibombshell/) - The compromised computer will be connected to a C2 panel through HTTP. Therefore, it will be possible to control the warrior and be able to load functions in memory that help the pentester. This is happening whithin the post-exploitation phase. 

- [godoh](https://github.com/sensepost/godoh) - godoh is a proof of concept Command and Control framework, written in Golang, that uses DNS-over-HTTPS as a transport medium. [Document](https://sensepost.com/blog/2018/waiting-for-godoh/)
  

## BAS OR Lab

<!-- BEGIN simulation LIST -->


### Multi Platform

**[`^        back to top        ^`](#)**


- [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) - Atomic Red Team™ is library of tests mapped to the [MITRE ATT&CK® framework](https://attack.mitre.org/). Security teams can use Atomic Red Team to quickly, portably, and reproducibly test their environments.

- [DetectionLab](https://github.com/clong/DetectionLab) - Automate the creation of a lab environment complete with security tooling and logging best practices. [Document](https://www.detectionlab.network/introduction/)


### AWS

**[`^        back to top        ^`](#)**


- [stratus-red-team](https://github.com/DataDog/stratus-red-team) - Stratus Red Team is ["Atomic Red Team™"](https://github.com/redcanaryco/atomic-red-team) for the cloud, allowing to emulate offensive attack techniques in a granular and self-contained manner. by datadog


### Azure

**[`^        back to top        ^`](#)**


- [DO-LAB](https://github.com/DefensiveOrigins/DO-LAB) - Defensive Origins Lab Environment is used within the Defensive Origins courses provided by Defensive Origins, AntiSyphon Security, and Black Hills Information Security. 

- [APT-Lab_Terraform](https://github.com/DefensiveOrigins/APT-Lab-Terraform) - The platform included here automates much of the threat-optic lab environment built on the Azure cloud network. 

- [Blacksmith](https://github.com/OTRF/Blacksmith) - The Blacksmith project focuses on providing dynamic easy-to-use templates for security researches to model and provision resources to automatically deploy applications and small networks in the cloud. It currently leverages [AWS CloudFormation](https://aws.amazon.com/cloudformation/) and [Microsoft Azure Resource Manager (ARM)](https://github.com/OTRF/Blacksmith/blob/master) templates to implement infrastructure as code for cloud solutions.


### Active Dirctory

**[`^        back to top        ^`](#)**


- [PurpleSharp](https://github.com/mvelazc0/PurpleSharp) - PurpleSharp is a C# adversary simulation tool that executes adversary techniques with the purpose of generating attack telemetry in monitored Windows environments. , [Document](https://www.purplesharp.com/en/latest/index.html#) 

- [Adaz](https://github.com/christophetd/Adaz) - This project allows you to easily spin up Active Directory labs in Azure with domain-joined workstations, Windows Event Forwarding, Kibana, and Sysmon using [Terraform](https://www.terraform.io/) / [Ansible](https://github.com/ansible/ansible). , [Document](https://blog.christophetd.fr/automating-the-provisioning-of-active-directory-labs-in-azure/)  

- [ActiveDirectory Lab](https://github.com/cfalta/activedirectory-lab/) - Terraform config to spin up a domain controller and some member servers in azure.  

- [Purple Teaming Attack & Hunt Lab - TerraForm](https://github.com/DefensiveOrigins/APT-Lab-Terraform) - Applied Purple Teaming Threat Optics Lab - Azure TerraForm by [Defensive Origins](https://defensiveorigins.com/)

### Articles

**[`^        back to top        ^`](#)**


- [Automating the provisioning of Active Directory labs in Azure](https://blog.christophetd.fr/automating-the-provisioning-of-active-directory-labs-in-azure/)
- [Introducing Stratus Red Team, an Adversary Emulation Tool for the Cloud](https://blog.christophetd.fr/introducing-stratus-red-team-an-adversary-emulation-tool-for-the-cloud/)
- [A-Z Index of Windows CMD commands](https://ss64.com/nt/)
- [Building an Active Directory Lab - Part 1](https://blog.spookysec.net/ad-lab-1/)


## Articles

<!-- BEGIN articles LIST -->


**[`^        back to top        ^`](#)**


- [Windows & Active Directory Exploitation Cheat Sheet and Command Reference](https://casvancooten.com/posts/2020/11/windows-active-directory-exploitation-cheat-sheet-and-command-reference/)
