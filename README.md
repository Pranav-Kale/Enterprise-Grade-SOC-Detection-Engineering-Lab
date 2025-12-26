# Enterprise Grade SOC & Detection Engineering Lab

---
## 1. Project Overview

Modern cybersecurity failures rarely happen because security tools are missing. They occur when tools operate in silos, telemetry is not correlated, alerts lack context, and response workflows are fragmented ⚠️. A real Security Operations Center (SOC) is not defined by dashboards alone, but by how effectively security data is collected, analyzed, and acted upon 🛡️.

The Enterprise Grade SOC & Detection Engineering Lab is a fully integrated SOC environment built to replicate how security operations function inside an enterprise network. This project focuses on how individual security components work together, rather than showcasing tools in isolation 🔗.

The lab reflects real SOC thinking — visibility first, detection second, response always 🚨.

Project Intent

This project was built to validate whether a security monitoring environment is actually capable of detecting and responding to real attacker behavior. Instead of relying on simulated data or pre-generated alerts, the lab ingests live telemetry and processes real attack activity 🧠.

The environment captures:

authentication activity across operating systems 🔐

endpoint behavior before and after compromise

network connections associated with command-and-control traffic 🌐

security control tampering and defense evasion

Each detection implemented in this SOC is directly tied to an observable action performed during an attack.

Operational Scope

The SOC environment covers the full operational security lifecycle:

private, identity-based access to infrastructure using Zero Trust principles 🔒

centralized telemetry ingestion from Windows and Linux endpoints

detection engineering for brute-force, execution, and post-exploitation behavior 🧩

visualization of threats using dashboards and geographic maps 🗺️

automated escalation of alerts into a ticketing system

structured investigation, documentation, and resolution workflows 📄

The goal is not visibility alone, but actionable security operations.

Enterprise SOC Design Approach

The lab follows an enterprise-oriented design philosophy throughout its implementation:

Zero Trust networking instead of publicly exposed services 🚫🌍

private SIEM access controlled by identity and device posture

detection rules engineered around attacker techniques, not static signatures 🎯

validation through controlled adversary simulation ⚔️

automation to reduce response time and analyst fatigue 🤖

This approach ensures that the SOC is not theoretical, but operationally realistic and defensible.

---
## 2. SOC Architecture & Design Philosophy
Architecture Mindset

This SOC is designed with a visibility-first mindset 🔍.
Instead of starting with alerts or dashboards, the architecture focuses on how telemetry flows from endpoints to detections and finally into response workflows 🧱.

Each component has a defined role, forming a layered SOC pipeline rather than isolated tools.

Zero Trust Foundation

All SOC components operate behind a Zero Trust access model 🔐.
No services are publicly exposed, and access is granted only through identity-based authentication, ensuring the SOC itself does not become an attack surface 🛡️.

Telemetry-Driven Design

Detections in this SOC are powered by high-fidelity telemetry 📊.
Windows and Linux endpoints generate authentication, process, network, and security logs that are centrally collected and correlated for analysis 🧠.

Detection Engineering Focus

Detections are intentionally engineered to represent real attacker behavior 🎯.
Brute-force attempts, unauthorized access, execution activity, network callbacks, and defense evasion are all monitored and validated ⚔️.

Closed-Loop SOC Workflow

The architecture enforces a complete SOC lifecycle 🔁:

Telemetry → Detection → Alert → Ticket → Investigation → Resolution


Alerts are treated as investigation starting points, with full documentation and auditability 📑.


---
## 3. High-Level Architecture
Overall Architecture Overview

The SOC environment is built as a private, cloud-based security infrastructure where all components communicate internally over a controlled network 🧱.
No core security services are exposed directly to the public internet, ensuring isolation and reduced attack surface 🔒.

The architecture separates:

defender infrastructure (SOC, SIEM, ticketing),

monitored endpoints (Windows & Linux),

and attacker infrastructure (C2 server) ⚔️.

Network & Access Flow

Access to the SOC follows an identity-driven path 🔐:

Analyst → Zero Trust Access → Private Network → SOC Services


Endpoints send telemetry inward, while analysts access dashboards and alerts only after authentication 🛡️.
This mirrors enterprise SOC access patterns where visibility is private and controlled.

Telemetry & Detection Flow

Security data flows through the SOC in a structured pipeline 📊:

Endpoints → Agents → SIEM → Detections → Alerts


Telemetry from Windows and Linux systems is centralized, correlated, and evaluated against engineered detection rules 🧠.
This ensures detections are based on behavior, not isolated events.

Response & Case Management Flow

Once an alert is triggered, it enters the response layer 🔁:

Alert → Ticket → Investigation → Resolution


Alerts are automatically converted into tickets, enabling documentation, analyst ownership, and audit-ready incident tracking 📑.

Adversary Interaction Boundary

Attacker-controlled infrastructure operates outside the SOC boundary 🧨.
Any interaction with internal systems is intentional and monitored, allowing detections to be validated against real attack behavior 🎯.




---
## 4. Secure Private Access & Zero Trust Foundation

This section documents the initial foundation setup of the SOC environment.
All later components (Elastic, endpoints, OS Ticket, detections) rely on this layer for secure private access.


### 4.1 Creating the Vultr VPC Network

A dedicated private network was created to host all SOC infrastructure.

VPC CIDR: 10.0.0.0/24

Steps performed:

Navigated to Vultr → Network → VPC

Created a new VPC network

Assigned private CIDR block

<img src="/screenshots/Add VPC Network.png" width="700" height="420"> <img src="/screenshots/VPC Conf.png" width="700" height="420"> <img src="/screenshots/VPC network created.png" width="700" height="420">

This VPC serves as the isolated internal SOC network.


### 4.2 Deploying the VPC Gateway VM

A gateway VM was deployed inside the VPC to act as:

the ingress point for Zero Trust traffic

the routing and NAT device for internal systems

Steps performed:

Deployed a new Ubuntu server

Attached it to the SOC VPC

Verified instance creation

<img src="/screenshots/Compute and deploy button.png" width="700" height="420"> <img src="/screenshots/VPC gateway conf.png" width="700" height="420"> <img src="/screenshots/VPC Gateway Created and Running.png" width="700" height="420"> <img src="/screenshots/VPC Gateway.png" width="700" height="420">


### 4.3 Verifying Gateway Connectivity

Before introducing Cloudflare, direct SSH access was validated.

<img src="/screenshots/ssh to 10.0.0.3 success.png" width="700" height="420">

This confirmed:

instance availability

VPC networking functionality


### 4.4 Cloudflare Account & Zero Trust Setup

Cloudflare Zero Trust was configured to enable identity-based private access.

Steps performed:

Created Cloudflare account

Accessed Zero Trust dashboard

Defined team name

<img src="/screenshots/Cloudflare signup.png" width="700" height="420"> <img src="/screenshots/Cloudflare Dashboard.png" width="700" height="420"> <img src="/screenshots/Team Name.png" width="700" height="420"> <img src="/screenshots/Zero Trust Dashboard.png" width="700" height="420">

### 4.5 Installing Cloudflare WARP on Analyst Device

WARP was installed to provide Zero Trust connectivity from the analyst workstation.

Steps performed:

Added device in Zero Trust dashboard

Downloaded WARP client

Installed and connected WARP

<img src="/screenshots/Add a device.png" width="700" height="420"> <img src="/screenshots/Download WARp.png" width="700" height="420"> <img src="/screenshots/WARP Download.png" width="700" height="420"> <img src="/screenshots/Cloudflare Warp installation.png" width="700" height="420"> <img src="/screenshots/WARP Connected.png" width="700" height="420">

### 4.6 Installing Cloudflare Tunnel on the Gateway

The gateway VM was configured as a Cloudflare Tunnel endpoint.

Steps performed:

Created Cloudflare Tunnel connector

Selected Debian install method

Installed and started cloudflared

<img src="/screenshots/Create a Connector.png" width="700" height="420"> <img src="/screenshots/Select Cloudflare connector.png" width="700" height="420"> <img src="/screenshots/name the tunnel.png" width="700" height="420"> <img src="/screenshots/Choose Debian.png" width="700" height="420"> <img src="/screenshots/Install cloudflared.png" width="700" height="420"> <img src="/screenshots/Cloudflared Installed and configured.png" width="700" height="420">

### 4.7 Adding Private Routes to the Tunnel

Private routing was configured so WARP clients could reach the SOC VPC.

<img src="/screenshots/Create Routes.png" width="700" height="420"> <img src="/screenshots/Route Conf.png" width="700" height="420">

### 4.8 Validating Private Connectivity

Connectivity tests were performed through the tunnel.

<img src="/screenshots/check ping .png" width="700" height="420"> <img src="/screenshots/ssh to 10.0.0.3 success but to 10.0.0.4 failed.png" width="700" height="420"> <img src="/screenshots/ping from 0.3 to 0.4 successful.png" width="700" height="420">

This validated:

WARP routing

tunnel functionality

internal VPC communication


### 4.9 Enabling IP Forwarding & NAT on Gateway

To allow traffic flow between WARP clients and internal hosts, NAT was configured.

<img src="/screenshots/Run these MASquerade commands.png" width="700" height="420">

### 4.10 WARP Enrollment Policies

Device enrollment policies were configured to restrict access.

<img src="/screenshots/WARP Preferences.png" width="700" height="420"> <img src="/screenshots/WARP Zero trust login button.png" width="700" height="420"> <img src="/screenshots/WARP Login page.png" width="700" height="420"> <img src="/screenshots/WARP zero trust success.png" width="700" height="420"> <img src="/screenshots/Device Enrollement manage button.png" width="700" height="420"> <img src="/screenshots/Edit default policy.png" width="700" height="420"> <img src="/screenshots/Enrollment policy added.png" width="700" height="420">

### 4.11 Split Tunnel Configuration

Only SOC VPC traffic was routed through WARP.

<img src="/screenshots/Cloudflare plans.png" width="700" height="420"> <img src="/screenshots/Screenshot 2025-12-07 173351.png" width="700" height="420"> <img src="/screenshots/Split Tunnel Changes.png" width="700" height="420">



---
## 5. Core SIEM Deployment – Elastic Stack (Elasticsearch & Kibana)

This section documents the deployment and configuration of the Elastic Stack inside the SOC private network.
Elasticsearch acts as the central data store, while Kibana provides visibility, analysis, and detection management.


### 5.1 Deploying the Elasticsearch Server

A dedicated VM was deployed inside the SOC VPC to host Elasticsearch.

<img src="/screenshots/ELK Server created.png" width="700" height="420">

### 5.2 Verifying Private Connectivity to Elasticsearch Server

SSH access was tested using the private VPC IP.

<img src="/screenshots/SSh to elk server.png" width="700" height="420"> <img src="/screenshots/Check private ip on vultr.png" width="700" height="420">

This confirmed:

Cloudflare Tunnel routing

VPC gateway forwarding

no public exposure


### 5.3 Updating the Elasticsearch Server

System packages were updated to ensure stability and compatibility.

Commands executed:

apt-get update

apt-get upgrade -y

<img src="/screenshots/initial command on elk server.png" width="700" height="420">

### 5.4 Downloading Elasticsearch Installer

The official Elasticsearch .deb installer link was copied from the Elastic website.

<img src="/screenshots/Elasticsearch copy link address.png" width="700" height="420">

### 5.5 Installing Elasticsearch

Elasticsearch was downloaded and installed using wget and dpkg.

<img src="/screenshots/wget command for elastic search.png" width="700" height="420"> <img src="/screenshots/install elastic search.png" width="700" height="420">

### 5.6 Saving Elasticsearch Security Credentials

During installation, Elasticsearch generated:

elastic superuser password

enrollment information

These credentials were saved for later use.

<img src="/screenshots/install elastic search and save in notepad.png" width="700" height="420">

### 5.7 Configuring Elasticsearch Network Settings

The Elasticsearch configuration file was modified to bind only to the private VPC IP.

<img src="/screenshots/open elasticsearch conf file.png" width="700" height="420"> <img src="/screenshots/Elastic.yml changes.png" width="700" height="420">

Configuration applied:

network.host: 10.0.0.4

http.port: 9200


### 5.8 Starting and Verifying Elasticsearch Service

Elasticsearch was enabled and started as a system service.

<img src="/screenshots/elasticsearch up and running.png" width="700" height="420">

Status confirmed:

service running

no startup errors


### 5.9 Downloading Kibana

The Kibana .deb installer was downloaded from Elastic’s official site.

<img src="/screenshots/Copy kibana link.png" width="700" height="420">

### 5.10 Installing Kibana

Kibana was installed using the downloaded package.

<img src="/screenshots/Install kibana.png" width="700" height="420">

### 5.11 Configuring Kibana Network Settings

Kibana configuration file was edited to define host and port.

<img src="/screenshots/open kibana.yml.png" width="700" height="420"> <img src="/screenshots/Changes in kibana.yml.png" width="700" height="420">

Initial configuration:

server.port: 5601

server.host: 10.0.0.4


### 5.12 Starting Kibana Service

Kibana was enabled and started.

<img src="/screenshots/Kibana up and running.png" width="700" height="420">

### 5.13 Generating Kibana Enrollment Token

An enrollment token was generated from the Elasticsearch server.

<img src="/screenshots/Enrollment token generated and now copy and save the token in notepad.png" width="700" height="420">

### 5.14 Firewall Configuration for Kibana Access

Firewall rules were updated to allow HTTP/HTTPS traffic.

<img src="/screenshots/ufw changes.png" width="700" height="420">

### 5.15 Verifying WARP Connectivity

WARP-assigned IP on analyst workstation was verified.

<img src="/screenshots/ipconfig on laptop to know WARP assigned ip.png" width="700" height="420">

Additional routing commands were executed on the VPC gateway.

<img src="/screenshots/run these command on vpc gateway.png" width="700" height="420">

### 5.16 Fixing Kibana Accessibility

Kibana was updated to listen on all interfaces.

<img src="/screenshots/Kibana server host changes.png" width="700" height="420">

### 5.17 Configuring Kibana via Browser

Enrollment token was entered to complete Kibana setup.

<img src="/screenshots/Paste the enrollment token.png" width="700" height="420">

Verification code was generated and entered.

<img src="/screenshots/Kibana Verification Required.png" width="700" height="420"> <img src="/screenshots/get verififcation code for kibana.png" width="700" height="420">

### 5.18 Logging into Kibana

Elastic superuser credentials were used to log in.

<img src="/screenshots/credentials to login to the kibana from saved in notepad.png" width="700" height="420">

### 5.19 Resolving Kibana Alert Encryption Errors

Initial alert errors were observed.

<img src="/screenshots/go to alerts in security on kibana.png" width="700" height="420">

Encryption keys were generated and added.

<img src="/screenshots/Getting encryption keys to solve the problem of errors in alerts.png" width="700" height="420"> <img src="/screenshots/Enter the encryption keys in kibana keystore.png" width="700" height="420">

After restart, errors were resolved.

<img src="/screenshots/no error now in kibana security alerts.png" width="700" height="420">



---
## 6. Endpoint Infrastructure Setup (Windows & Linux Targets)

This section documents the deployment of endpoint systems that later act as attack targets and telemetry sources within the SOC.
At this stage, no detections or agents are installed — the focus is strictly on infrastructure preparation.


### 6.1 Windows Server Deployment (Target Endpoint)

A Windows Server 2022 virtual machine was deployed inside the Vultr environment to serve as the primary attack target for RDP-based intrusion and post-exploitation simulations 🪟.

Steps performed:

Navigated to Vultr → Compute

Deployed a new instance

Selected Windows Server 2022

Assigned default configuration

Completed provisioning

<img src="/screenshots/Windows Server created.png" width="700" height="420">

At this stage:

No hardening was applied

No agents were installed

No firewall rules were modified

The server was intentionally left in a baseline state for later attack validation 🎯.


### 6.2 Linux SSH Server Deployment (Authentication Target)

A Linux server was deployed to act as an SSH authentication target, allowing observation of real-world brute-force behavior commonly seen on internet-exposed SSH services 🐧.

Deployment configuration:

OS: Ubuntu 24.04

Purpose: SSH authentication telemetry

Role: Linux attack surface

<img src="/screenshots/Linux ssh server added.png" height="370">

### 6.3 Accessing the Linux Server and Locating Logs

After deployment, an SSH connection was established to the Linux server.

Steps performed:

Connected via SSH

Navigated to system log directory

Identified authentication log file

<img src="/screenshots/linux logs file.png" height="370">

The file /var/log/auth.log was confirmed as the primary source for:

SSH login attempts

Failed authentication events

Brute-force activity 🔐


### 6.4 Observing Real SSH Brute-Force Activity

After leaving the server exposed for some time, failed login attempts began appearing automatically — a common behavior for publicly reachable SSH services 🌍.

To filter failed authentication attempts:

grep -i failed auth.log | grep -i root

<img src="/screenshots/We can see logs of failed authentication.png" height="370">

Observed patterns:

repeated login failures

multiple source IPs

repeated targeting of root

This confirmed that the Linux server was already receiving real attacker traffic, making it suitable for detection engineering later ⚔️.



---
## 7. Fleet Server Setup & Elastic Agent Enrollment

This section documents the deployment of the Fleet Server and the onboarding of the Windows endpoint into the Elastic Stack.
Fleet Server enables centralized agent management, policy enforcement, and telemetry control across all endpoints 🧠.


### 7.1 Accessing Fleet in Kibana

Fleet management was accessed from the Kibana dashboard.

Steps performed:

Opened Kibana

Clicked the hamburger menu

Navigated to Management → Fleet

<img src="/screenshots/Fleet in Management on Kibana.png" width="700" height="420">

### 7.2 Adding a Fleet Server

A Fleet Server was added to centrally manage Elastic Agents.

<img src="/screenshots/Add fleet server.png" width="700" height="420">

### 7.3 Fleet Server Quick Start Configuration

The Quick Start option was selected for Fleet Server setup.

Configuration details:

Fleet Server Name: fleet-server

Fleet Server URL:
https://<FLEET_SERVER_PUBLIC_IP>:8220

<img src="/screenshots/kibana fleet sdd conf 1.png" width="700" height="420">

### 7.4 Preparing the Fleet Server VM

Connected to the Fleet Server VM and updated the system packages.

<img src="/screenshots/Update fleet server repository.png" width="700" height="420">

### 7.5 Copying Fleet Server Installation Command

The installation command generated by Kibana was copied.

<img src="/screenshots/Select fleet host and copy command.png" width="700" height="420">

### 7.6 Installing Fleet Server

The copied command was executed on the Fleet Server VM.

<img src="/screenshots/paste command in fleet server.png" width="700" height="420">

The installation initially failed due to connectivity issues.

<img src="/screenshots/We get bunch of error.png" width="700" height="420">

### 7.7 Allowing Required Port on Elasticsearch Server

To resolve the issue, port 9200 was allowed on the Elasticsearch server firewall.

<img src="/screenshots/Add a rule in elk server.png" width="700" height="420">

### 7.8 Retrying Fleet Server Installation

The Fleet Server installation command was re-executed.

<img src="/screenshots/Run this command agan.png" width="700" height="420">

### 7.9 Fleet Server Enrollment Successful

Fleet Server successfully enrolled into Elasticsearch.

<img src="/screenshots/Elastic agent successfully enrolled.png" width="700" height="420">

### 7.10 Verifying Fleet Server in Kibana

Fleet Server health status was verified in Kibana.

<img src="/screenshots/continue enrolling fleet server.png" width="700" height="420">

### 7.11 Creating a Windows Agent Policy

A dedicated agent policy was created for the Windows Server.

Policy name: windows-policy

<img src="/screenshots/policy name.png" width="700" height="420">

### 7.12 Copying Windows Elastic Agent Installer Command

The Elastic Agent installation command for Windows was copied.

<img src="/screenshots/copy commands for fleet server.png" width="700" height="420">

### 7.13 Installing Elastic Agent on Windows Server

On the Windows Server:

Opened PowerShell as Administrator

Pasted the copied install command

<img src="/screenshots/Paste the coppied command.png" width="700" height="420">

### 7.14 Fixing Certificate Validation Issue

Enrollment failed due to certificate validation.

To fix this, the --insecure flag was added.

<img src="/screenshots/Make some correction in command.png" width="700" height="420"> <img src="/screenshots/changes in the command for elastic agent.png" width="700" height="420">

Final command format:

.\elastic-agent.exe install --url=https://<FLEET_SERVER_IP>:8220 \
--enrollment-token=<TOKEN> --insecure


### 7.15 Elastic Agent Enrollment Successful

The Windows Elastic Agent enrolled successfully.

<img src="/screenshots/Elastic agent successful.png" width="700" height="420">

### 7.16 Verifying Agent Health in Fleet

Both Fleet Server and Windows Agent showed Healthy status.

<img src="/screenshots/Fleet server added.png" width="700" height="420">

### 7.17 Validating Windows Logs in Kibana

Windows telemetry was verified in Discover.

<img src="/screenshots/We are seeing logs related to windows server.png" width="700" height="420">

This confirmed:

agent connectivity

telemetry ingestion

centralized management is active 📊



---
## 8. Windows Endpoint Telemetry Engineering (Sysmon & Defender Logs)

This section documents how high-fidelity Windows telemetry was enabled on the Windows Server endpoint.
The focus here is on process, network, and security visibility, which is essential for detection engineering 🧠.


### 8.1 Downloading Sysmon on Windows Server

Sysmon was downloaded from the official Microsoft Sysinternals page.

<section> <img src="/screenshots/Download sysmon.png" alt="Download Sysmon" height="350"> </section>

### 8.2 Downloading Olaf’s Sysmon Configuration

Olaf’s modular Sysmon configuration was used to enable rich endpoint telemetry.

Steps performed:

Searched for Olaf Sysmon Config GitHub

Opened the repository

Viewed sysmonconfig.xml

Clicked Raw

Saved the file into the Sysmon directory

<section> <img src="/screenshots/olaf sysmon config file then click raw and then save it in sysmon folder.png" alt="Olaf Sysmon Config" height="350"> </section>

### 8.3 Navigating to Sysmon Directory

PowerShell was opened with administrator privileges and navigated to the Sysmon folder.

<section> <img src="/screenshots/navigate to sysmon in powershell and run it.png" alt="Navigate to Sysmon directory" height="350"> </section>

### 8.4 Installing Sysmon with Configuration

Sysmon was installed using Olaf’s configuration file.

Command executed:

.\Sysmon64.exe -i SysmonConfig.xml


The license agreement was accepted during installation.

<section> <img src="/screenshots/Sysmon 2nd command.png" alt="Sysmon install command" height="350"> </section>

### 8.5 Verifying Sysmon Service

Sysmon service creation was verified via Windows Services.

<section> <img src="/screenshots/We can see sysmon in services.png" alt="Sysmon running in services" height="350"> </section>

Status confirmed:

Service name: Sysmon64

State: Running ⚙️


### 8.6 Verifying Sysmon Logs in Event Viewer

Sysmon logs were confirmed in Event Viewer.

Navigation path:

Applications and Services Logs
→ Microsoft
→ Windows
→ Sysmon
→ Operational

<section> <img src="/screenshots/Sysmon in event viewer.png" alt="Sysmon logs in Event Viewer" height="350"> </section>

This confirmed that:

Sysmon is actively collecting telemetry

Process, network, and file events are being logged 📊


### 8.7 Configuring Sysmon Log Ingestion in Kibana

To ingest Sysmon logs into Elasticsearch, the Custom Windows Event Logs integration was used.

Steps performed:

Opened Kibana

Navigated to Add Integrations

Selected Custom Windows Event Logs

<section> <img src="/screenshots/click integration.png" alt="Click integrations" height="370"> </section> <section> <img src="/screenshots/Select custom windows integration.png" alt="Select custom windows integration" height="370"> </section>

### 8.8 Configuring Sysmon Event Channel

Sysmon logs were configured using the following channel:

Microsoft-Windows-Sysmon/Operational

<section> <img src="/screenshots/windows log integration conf 1.png" height="370"> <br> <img src="/screenshots/windows log integration conf 2.png" height="370"> </section>

After saving, the integration was added to the Windows agent policy.

<section> <img src="/screenshots/windows log integration added.png" height="370"> </section>

### 8.9 Configuring Microsoft Defender Log Ingestion

The Defender Operational log channel was identified via Event Viewer.

<section> <img src="/screenshots/channel name.png" alt="Defender channel name" height="370"> </section>

Configured channel:

Microsoft-Windows-Windows Defender/Operational


High-value Defender event IDs added:

1116 – Malware detected

1117 – Malware remediation

50001 – Real-time protection disabled 🚨

<section> <img src="/screenshots/windows defender log integration conf 1.png" height="370"> <br> <img src="/screenshots/windows defender log integration conf 2.png" height="370"> <br> <img src="/screenshots/windows defender log integration conf 3.png" height="370"> </section> <section> <img src="/screenshots/windows defender log integration added.png" height="370"> </section>

### 8.10 Restarting Elastic Agent on Windows

To apply updated policies, the Elastic Agent was restarted.

<section> <img src="/screenshots/Restart eleastic agent.png" alt="Restart Elastic Agent" height="370"> </section>

### 8.11 Verifying Sysmon & Defender Logs in Kibana

Sysmon process creation events were verified using Event ID 1.

<section> <img src="/screenshots/windows sysmon logs are visible.png" alt="Sysmon logs visible" height="370"> </section>

Defender events were verified using Event ID 50001.

<section> <img src="/screenshots/windows defender logs are visible.png" alt="Defender logs visible" height="370"> </section>

This confirmed:

Sysmon telemetry ingestion

Defender security signal ingestion

Windows endpoint visibility is fully operational 🛡️



---
## 9. Linux SSH Telemetry Engineering (Elastic Agent & Authentication Logs)

This section documents how the Linux SSH server was integrated into the SOC for authentication telemetry, enabling visibility into real-world SSH brute-force activity 🐧🔐.


### 9.1 Deploying the Linux SSH Server

A dedicated Linux server was deployed to act as an SSH authentication target.

Deployment details:

OS: Ubuntu 24.04

Role: SSH attack surface

Purpose: Generate authentication telemetry

<section> <img src="/screenshots/Linux ssh server added.png" alt="Linux SSH Server Added" height="370"> </section>

### 9.2 Connecting to the Linux Server

An SSH connection was established to the newly deployed Linux server.

Once connected, the system log directory was accessed.

<section> <img src="/screenshots/linux logs file.png" alt="Linux Logs Directory" height="370"> </section>

### 9.3 Identifying SSH Authentication Log Source

The SSH authentication log file was identified at:

/var/log/auth.log


This file records:

failed SSH login attempts

successful authentications

usernames and source IP addresses 📄


### 9.4 Observing Live SSH Brute-Force Attempts

After leaving the SSH service exposed for some time, automated brute-force attempts began appearing in the logs 🌍.

To filter failed authentication attempts targeting the root account:

grep -i failed auth.log | grep -i root

<section> <img src="/screenshots/We can see logs of failed authentication.png" alt="SSH Failed Authentication Logs" height="370"> </section>

Observed behavior:

repeated failed password attempts

multiple external IP addresses

consistent targeting of high-value accounts ⚠️

This confirmed that the server was receiving real attacker traffic, not simulated data.


### 9.5 Creating a Linux Agent Policy in Fleet

To ingest Linux logs into Elasticsearch, a dedicated agent policy was created.

Steps performed in Kibana:

Navigated to Fleet

Opened Agent Policies

Created a new policy named linux-policy

<section> <img src="/screenshots/select fleet.png" alt="Select Fleet" height="370"> </section> <section> <img src="/screenshots/Screenshot 2025-12-09 012916.png" alt="Create Agent Policy" height="370"> </section> <section> <img src="/screenshots/create new agent policy.png" alt="Linux Policy Created" height="370"> </section> <section> <img src="/screenshots/policy conf 1.png" alt="Linux Policy Configuration" height="370"> </section> <section> <img src="/screenshots/go in policy.png" alt="Open Linux Policy" height="370"> </section>

### 9.6 Enabling System Integration for Linux Logs

The System integration was enabled within the Linux agent policy.

This integration collects:

/var/log/auth.log

system logs

host metrics 📊

<section> <img src="/screenshots/select system 3.png" alt="Select System Integration" height="370"> </section>

### 9.7 Installing Elastic Agent on Linux SSH Server

The Add Agent workflow was used to generate the Linux install command.

Configuration selected:

Agent Policy: linux-policy

Enrollment method: Enroll in Fleet

<section> <img src="/screenshots/add agent.png" alt="Add Agent" height="370"> </section> <section> <img src="/screenshots/add agent conf 1.png" alt="Add Agent Configuration" height="370"> </section> <section> <img src="/screenshots/add agent conf 2.png" alt="Linux Install Command" height="370"> </section>

The command was executed on the Linux SSH server.

<section> <img src="/screenshots/paste the command in terminal.png" alt="Paste Command in Terminal" height="370"> </section>

### 9.8 Fixing Certificate Validation Issue

The initial installation failed due to a certificate trust error.

To resolve this, the --insecure flag was added to the command.

<section> <img src="/screenshots/make changes in command.png" alt="Modify Command" height="370"> </section>

After correction, the Elastic Agent installed successfully.

<section> <img src="/screenshots/elastic agent added on linux.png" alt="Elastic Agent Installed on Linux" height="370"> </section>

### 9.9 Verifying Linux Agent Enrollment

The Linux SSH server appeared in Fleet → Agents with a healthy status.

<section> <img src="/screenshots/Agent enrollment complete on kibana fleet.png" alt="Linux Agent Healthy" height="370"> </section>

### 9.10 Validating SSH Logs in Kibana Discover

SSH authentication logs from the Linux server were confirmed in Discover.

<section> <img src="/screenshots/Lofs from linux server.png" alt="Linux SSH Logs in Kibana" height="370"> </section>

This validated:

Elastic Agent connectivity

auth.log ingestion

availability of real SSH attack telemetry 🛡️



---
## 10. SSH Brute-Force Detection & Visualization Dashboards

This section documents how SSH authentication telemetry collected from the Linux server was transformed into detections, alerts, and visual dashboards inside the SOC 🛡️.


### 10.1 Identifying SSH Failed Authentication Events

SSH authentication telemetry was analyzed using Kibana Discover.

Steps performed:

Opened Kibana → Discover

Filtered logs for the Linux SSH server

Added key fields for visibility

Fields added:

@timestamp

system.auth.ssh.event

user.name

source.ip

source.geo.country_name

<section> <img src="/screenshots/SSH activity on linux.png" alt="SSH Activity Logs" height="370"> </section>

### 10.2 Filtering Failed SSH Authentication Attempts

To isolate brute-force behavior, the following filter was applied:

system.auth.ssh.event : failed

<section> <img src="/screenshots/SSH failed activity on linux.png" alt="SSH Failed Authentication Activity" height="370"> </section>

This view clearly showed:

repeated failed login attempts

multiple usernames

multiple source IPs 🌍


### 10.3 Saving the SSH Failed Authentication Query

The filtered query was saved for reuse in alerts and dashboards.

Saved search name:

SSH Failed Activity


This saved query acts as the base dataset for detection logic.


### 10.4 Creating SSH Brute-Force Alert Rule

An automated alert was created using a search threshold rule.

Steps performed:

Clicked Alerts

Selected Create search threshold rule

<section> <img src="/screenshots/create alert.png" alt="Create Alert" height="370"> </section> <section> <img src="/screenshots/create threshold rule.png" alt="Create Threshold Rule" height="370"> </section>

### 10.5 Configuring the SSH Brute-Force Rule

Rule configuration:

Time window: Last 5 minutes

Condition: Failed events greater than threshold

Rule name: ssh brute force activity

<section> <img src="/screenshots/create rule conf 1.png" height="370"> </section> <section> <img src="/screenshots/create rule conf 2.png" height="370"> </section>

Once enabled, the rule continuously monitors SSH failures 🚨.


### 10.6 Creating SSH Failed Authentication Map

To visualize attacker origin, a map visualization was created.

Filters used:

system.auth.ssh.event : failed
AND agent.name : "linux-ssh-server"

<section> <img src="/screenshots/create map - 1 for ssh failed activity.png" alt="Create SSH Failed Map Step 1" height="370"> </section> <section> <img src="/screenshots/create map - 2 for ssh failed activity.png" alt="Create SSH Failed Map Step 2" height="370"> </section>

### 10.7 Configuring Map Layer Settings

Map layer configuration:

Setting	Value
Boundary source	World countries
Data view	security_solution_default
Join field	source.geo.country_iso_code

The map was saved with the title:

ssh failed activity network map

<section> <img src="/screenshots/save the map.png" alt="Save SSH Map" height="370"> </section>

### 10.8 Creating Authentication Dashboard

A new dashboard was created to centralize SSH authentication activity.

<section> <img src="/screenshots/baic dashboard created for ssh failed auth.png" alt="Create SSH Dashboard" height="370"> </section>

The dashboard was saved as:

authentication-activity

<section> <img src="/screenshots/save new dashboard.png" alt="Save Dashboard" height="370"> </section>

### 10.9 (Optional) Successful SSH Authentication Visualization

A second visualization was created to track successful SSH logins.

Filter used:

system.auth.ssh.event : accepted

<section> <img src="/screenshots/baic dashboard created for ssh auth.png" alt="Successful SSH Dashboard" height="370"> </section>

This allows quick comparison between:

failed login noise

successful authentication events 🔍




---
## 11. Windows RDP Authentication Detection & Brute-Force Alerting

This section documents how Windows authentication telemetry was analyzed and converted into RDP brute-force detections using Windows Security Event Logs. The goal here was to achieve parity with SSH monitoring by applying the same detection rigor to Windows-based access 🔐🪟.


### 11.1 Identifying Failed Windows Authentication Events

Windows authentication logs were analyzed using Kibana → Discover.

Steps performed:

Opened Discover

Filtered logs for the Windows Server agent

Applied the following filter to identify failed logon attempts:

event.code : 4625

<section> <img src="/screenshots/RDP Failed Activity.png" alt="RDP Failed Authentication Logs" height="370"> </section>

Fields added for investigation context:

event.code

user.name

source.ip

This clearly surfaced repeated authentication failures consistent with brute-force behavior ⚠️.


### 11.2 Saving the RDP Failed Authentication Query

The filtered query was saved for reuse.

Saved search name:

RDP Failed Activity


This saved search acts as the base dataset for all RDP brute-force detections.


### 11.3 Creating RDP Brute-Force Alert from Discover

Using the saved search, a search threshold alert was created.

Steps performed:

Opened the saved search

Clicked Alerts

Selected Create search threshold rule

<section> <img src="/screenshots/alert for rdp failed activity.png" alt="Create RDP Alert" height="370"> </section>

### 11.4 Configuring the RDP Brute-Force Rule

Rule configuration applied:

Event filter: event.code : 4625

Threshold: More than 5 failures

Time window: Last 5 minutes

Rule schedule: Every 1 minute

Rule name: RDP Brute Force Activity

<section> <img src="/screenshots/Create Rule Conf - 1.png" height="370"> </section> <section> <img src="/screenshots/Create Rule Conf - 2.png" height="370"> </section> <section> <img src="/screenshots/Create Rule Conf - 3.png" height="370"> </section> <section> <img src="/screenshots/Create Rule Conf - 4.png" height="370"> </section>

### 11.5 Enabling and Verifying the RDP Alert Rule

After enabling the rule, alerts were verified in the Security module.

Navigation:

Security → Alerts

<section> <img src="/screenshots/Alert in stack management .png" height="370"> </section> <section> <img src="/screenshots/We will see alerts here.png" height="370"> </section>

This confirmed that RDP brute-force activity now triggers alerts 🚨.


### 11.6 Creating an Advanced RDP Detection Rule (Security Rules Engine)

To add richer context, a second detection rule was created using the Security → Rules engine.

Steps performed:

Opened Security → Rules

Clicked Create new rule

Selected Threshold rule

<section> <img src="/screenshots/create rule.png" height="370"> </section> <section> <img src="/screenshots/select create new rules.png" height="370"> </section> <section> <img src="/screenshots/Select threshold.png" height="370"> </section>

### 11.7 Configuring Advanced RDP Rule Logic

Rule logic applied:

event.code : 4625 AND user.name : administrator


Grouping fields:

source.ip

user.name

<section> <img src="/screenshots/for rdp rule.png" height="370"> </section> <section> <img src="/screenshots/for rdp rule 2.png" height="370"> </section>

This rule provides:

attacker IP attribution

targeted user visibility

frequency-based context 🎯


### 11.8 Confirming Alert Visibility

After enabling the rule, alerts were confirmed inside the Security dashboard.

This validated:

Windows authentication telemetry ingestion

detection logic correctness

SOC visibility for RDP attacks 🛡️



---
## 12. RDP Authentication Dashboards & Visualization (Windows Server)

This section documents how Windows RDP authentication activity was visualized using maps and tables, allowing quick identification of attack origins, login patterns, and successful access 🗺️🪟.


### 12.1 Creating RDP Failed Authentication Map

A geographic visualization was created to track failed RDP authentication attempts.

Filter used:

event.code : 4625 AND agent.name : <windows-server-name>


A choropleth map layer was added.

<section> <img src="/screenshots/map of rdp failed auth.png" alt="RDP Failed Authentication Map" width="650"> </section>

Map configuration:

Boundary source: World Countries

Data view: security_solution_default

Join field: source.geo.country_iso_code

The map was saved as:

RDP Failed Authentication

<section> <img src="/screenshots/Save map.png" alt="Save RDP Failed Map" width="650"> </section>

### 12.2 Creating RDP Successful Authentication Map

To visualize successful RDP logins, a second map was created.

Filter used:

event.code : 4624 AND 
(winlog.event_data.logon_type : 10 OR winlog.event_data.logon_type : 7)


Explanation:

Logon Type 10 → Remote Interactive (RDP)

Logon Type 7 → RDP unlock events

<section> <img src="/screenshots/map of RDP successful auth.png" alt="RDP Successful Authentication Map" width="650"> </section>

This map highlights confirmed successful remote access, helping distinguish noise from real intrusion 🔍.


### 12.3 Adding Visualizations to Authentication Dashboard

Both RDP maps were added to the existing Authentication Activity dashboard.

Steps performed:

Opened the dashboard

Clicked Add → Visualization

Selected saved map visualizations

<section> <img src="/screenshots/open visualization.png" alt="Open Visualization Menu" width="650"> </section>

### 12.4 Creating Table Visualization for RDP Failures

A table visualization was added to complement map-based views.

Configuration applied:

Top values: 10

Group remaining values as “Other”: Disabled

Sort order: Descending by count

Fields included:

user.name

source.ip

source.geo.country_name

Event count

<section> <img src="/screenshots/visualization for rdp failed.png" alt="RDP Failed Table Visualization" width="650"> </section>

### 12.5 Final Authentication Activity Dashboard

The completed dashboard now includes:

SSH failed authentication map

SSH successful authentication map

RDP failed authentication map

RDP successful authentication map

Tabular views for detailed analysis 📊

<section> <img src="/screenshots/Full Dashboard.png" alt="Full Authentication Dashboard" width="650"> </section>

This dashboard acts as the central authentication intelligence view of the SOC.



---
## 13. Attack Vector Design & Adversary Simulation Planning

This section documents the pre-attack planning phase, where the complete intrusion path against the Windows Server was designed before executing any attack.
The objective was to ensure that every attacker action would generate observable telemetry and map cleanly to existing detections 🧠⚔️.


### 13.1 Designing the Attack Flow

A detailed attack flow diagram was created to map the full adversary lifecycle from initial access to post-compromise activity.

The attack vector includes:

external attacker system

exposed RDP service on Windows Server

authentication brute-force

successful access

post-login activity

payload execution

command-and-control communication

This diagram serves as a blueprint for validating SOC visibility and detections.

<section> <img src="/screenshots/attack_diagram.png" alt="Attack Vector Diagram" width="650"> </section>

### 13.2 Mapping Attack Steps to Telemetry

Each stage of the attack was intentionally mapped to expected telemetry sources:

RDP brute-force
→ Windows Event ID 4625 (failed logon)

Successful RDP login
→ Windows Event ID 4624 (logon type 10)

Command execution
→ Sysmon Event ID 1 (process creation)

Network callbacks
→ Sysmon Event ID 3 (network connection)

Defense evasion
→ Microsoft Defender Event ID 50001 🚨

This ensured that detections built earlier would be provably testable, not theoretical.


### 13.3 Defining Validation Objectives

Before launching the attack, the following validation goals were defined:

confirm brute-force alerts trigger correctly

confirm dashboards reflect attacker geography

confirm successful authentication is visible

confirm post-compromise activity generates alerts

confirm detections can be investigated end-to-end 🔁

No attack activity was performed during this stage — only planning and validation alignment.


### 13.4 Preparing for Controlled Execution

With the attack vector finalized:

attacker infrastructure was prepared separately

Windows Server was left intentionally vulnerable

SOC monitoring remained active and unchanged

This ensured that when the attack was executed, all detections would be evaluated under real conditions, not adjusted mid-attack 🎯.




---
## 14. Command & Control Infrastructure Deployment (Mythic C2)

This section documents the deployment of the Mythic Command-and-Control (C2) server, which is used later to simulate real adversary post-compromise behavior against the Windows Server ⚔️🧠.

The C2 infrastructure is intentionally separated from the SOC network to accurately represent external attacker-controlled systems.


### 14.1 Deploying the Mythic C2 Server

A dedicated cloud VM was provisioned to host the Mythic C2 framework.

Deployment details:

Cloud Provider: Vultr

OS: Ubuntu

Location: Toronto

RAM: 4 GB

Purpose: Adversary C2 infrastructure

<img src="/screenshots/Mythic C2 Server Created.png" width="650">

### 14.2 Preparing the Server Environment

After deployment, the server was accessed via SSH and system packages were updated.

Commands executed:

apt-get update
apt-get upgrade -y


### 14.3 Installing Required Dependencies

Mythic relies on Docker, Docker Compose, and Make.

Steps performed:

Installed Docker Compose

Installed Make

<img src="/screenshots/install docker compose.png" width="650"> <img src="/screenshots/install make.png" width="650">

### 14.4 Cloning the Mythic Repository

The official Mythic repository was cloned from GitHub.

Command executed:

git clone https://github.com/its-a-feature/Mythic

<img src="/screenshots/clone github mythic repo.png" width="650">

### 14.5 Installing Docker Support for Mythic

Inside the Mythic directory, Docker support scripts were executed.

Command executed:

./install_docker_ubuntu.sh

<img src="/screenshots/install docker for ubuntu.png" width="650">

### 14.6 Resolving Docker Daemon Issue

The initial make command failed because the Docker daemon was not running.

<img src="/screenshots/we get error , after typing command make.png" width="650"> <img src="/screenshots/Reason for make to fail.png" width="650">

Fix applied:

systemctl restart docker
systemctl status docker


After restarting Docker, the build process succeeded.

<img src="/screenshots/now make works.png" width="650">

### 14.7 Starting the Mythic C2 Service

Mythic services were started using the Mythic CLI.

Command executed:

./mythic-cli start

<img src="/screenshots/Write command to run mythic cli.png" width="650">

This started:

Mythic web UI

database services

messaging components

C2 profiles infrastructure


### 14.8 Configuring Firewall Rules for Mythic

Firewall rules were configured to restrict access to the Mythic server.

Rules applied:

Block all inbound traffic by default

Allow access only from:

analyst public IP

Windows Server public IP

Linux SSH server public IP

<img src="/screenshots/create firewall for mythic.png" width="650"> <img src="/screenshots/my public ip address.png" width="650"> <img src="/screenshots/Mythic firewall conf.png" width="650"> <img src="/screenshots/Firewall updated.png" width="650">

This ensured the C2 server was not publicly exposed 🌐🚫.


### 14.9 Accessing the Mythic Web Interface

The Mythic UI was accessed via HTTPS on port 7443.

URL format:

https://<mythic-server-ip>:7443


Default credentials were retrieved from the .env file.

<img src="/screenshots/mythic login.png" width="650"> <img src="/screenshots/find password - 1.png" width="650"> <img src="/screenshots/find password - 2.png" width="650"> <img src="/screenshots/find password - 3.png" width="650">

### 14.10 Mythic Dashboard Verification

After authentication, the Mythic dashboard loaded successfully.

<img src="/screenshots/Mythic Dashboard.png" width="650">

Visible components:

payload types

C2 profiles

callback section (empty at this stage)

MITRE ATT&CK mappings

This confirmed the Mythic C2 infrastructure was fully operational and ready for payload deployment 🎯.



---
## 15. Full Attack Execution – RDP Brute Force, Payload Execution & C2 Callback

This section documents the complete adversary kill-chain execution against the Windows Server — from initial access to post-compromise command execution via Mythic C2 ⚔️🧠.
All actions performed here were intentionally designed to generate telemetry for validation in later detection stages.


### 15.1 Staging Fake Sensitive Data on Windows Server

Before launching the attack, a fake credentials file was created on the Windows Server to simulate sensitive data for post-compromise scenarios.

<section> <img src="/screenshots/create fake passwords file on windows server.png" width="620"> </section>

### 15.2 Preparing the Brute-Force Wordlist

A custom password list was prepared using rockyou.txt.

Steps performed:

Extracted the first 50 passwords

Opened the reduced wordlist

Appended the valid password manually

<section> <img src="/screenshots/attack from kali - 1.png" width="610"> </section> <section> <img src="/screenshots/attack from kali - 2.png" width="610"> </section> <section> <img src="/screenshots/attack from kali - 3.png" width="610"> </section>

### 15.3 Executing RDP Brute-Force Attack

The brute-force attack was executed using Hydra against the Windows Server RDP service.

<section> <img src="/screenshots/Using hydra to do brute force - 1.png" width="610"> </section>

Valid credentials were successfully discovered.

<section> <img src="/screenshots/Using hydra to do brute force - 2.png" width="610"> </section>

### 15.4 Establishing RDP Session

With valid credentials obtained, an interactive RDP session was established using xfreerdp.

<section> <img src="/screenshots/useing xfreerdp - 1.png" width="610"> </section>

Successful login confirmed access to the Windows desktop.

<section> <img src="/screenshots/brute force success.png" width="610"> </section>

### 15.5 Post-Login Discovery Commands

Basic reconnaissance commands were executed to enumerate system context and generate telemetry.

<section> <img src="/screenshots/commands executed.png" width="620"> </section>

### 15.6 Defense Evasion – Disabling Microsoft Defender

Microsoft Defender real-time protection was intentionally disabled to simulate attacker defense evasion.

<section> <img src="/screenshots/defense evasion using kali.png" width="620"> </section>

### 15.7 Installing Apollo Agent on Mythic

On the Mythic server, the Apollo agent was installed and made available.

<section> <img src="/screenshots/Installing apollo on mythic server.png" width="610"> </section> <section> <img src="/screenshots/apollo agent visible on mythic gui.png" width="610"> </section>

### 15.8 Installing HTTP C2 Profile

The HTTP C2 profile was installed and enabled.

<section> <img src="/screenshots/install mythic http profile.png" width="610"> </section> <section> <img src="/screenshots/http profile visible on mythic gui.png" width="610"> </section>

### 15.9 Building the Mythic Payload

A Windows executable payload was created using Apollo with the HTTP C2 profile.

<section> <img src="/screenshots/mythic-payload-creation-1.png" width="610"> </section> <section> <img src="/screenshots/mythic-payload-creation-2.png" width="610"> </section> <section> <img src="/screenshots/mythic-payload-creation-3.png" width="610"> </section> <section> <img src="/screenshots/mythic-payload-creation-4.png" width="610"> </section> <section> <img src="/screenshots/mythic-payload-creation-5.png" width="610"> </section>

Payload download link was copied.

<section> <img src="/screenshots/copy link for payload.png" width="610"> </section>

### 15.10 Hosting the Payload

The payload was downloaded, renamed, and hosted using a Python HTTP server.

<section> <img src="/screenshots/run wget command for the payload.png" width="610"> </section> <section> <img src="/screenshots/payload operations.png" width="610"> </section> <section> <img src="/screenshots/Started python server on port 9999 from mythic server.png" width="610"> </section>

### 15.11 Executing Payload on Windows Server

The payload was downloaded and executed on the Windows Server.

<section> <img src="/screenshots/executed svchost on windows server.png" width="610"> </section>

The process appeared in Task Manager.

<section> <img src="/screenshots/svchost-pranav runnig in task manager.png" width="610"> </section>

### 15.12 Observing Network Callback Attempt

Initial network connections were observed in a SYN_SENT state.

<section> <img src="/screenshots/in netstat -anob the coonection is SYN_Sent.png" width="610"> </section>

Firewall rules were updated to allow outbound traffic.

<section> <img src="/screenshots/made change in ufw port 80.png" width="610"> </section>

### 15.13 C2 Callback Established

After firewall changes, the C2 callback appeared in the Mythic dashboard.

<section> <img src="/screenshots/callback was seen on the mythic gui.png" width="610"> </section>

Connection status confirmed.

<section> <img src="/screenshots/connection established.png" width="610"> </section>

### 15.14 Executing Commands via Mythic C2

Commands were successfully executed through the Mythic interface against the compromised Windows Server.

<section> <img src="/screenshots/We can execute command on mythic hui after a callback.png" width="620"> </section>

This confirmed full post-compromise control of the endpoint 🎯.




---
## 16. Detecting Mythic C2 Activity & Suspicious Behavior

This section documents how post-compromise activity generated in Section 15 was detected using Sysmon telemetry, custom detection rules, and dashboards.
The goal here was to validate that real C2 activity leaves observable and actionable security signals 🧠🚨.


### 16.1 Identifying Payload Execution via Sysmon (Process Creation)

To detect execution of the Mythic Apollo payload, Sysmon Event ID 1 (Process Create) was analyzed.

Steps performed:

Opened Kibana → Discover

Filtered process creation events

Searched for the Apollo payload execution (svchost-pranav.exe)

<section> <img src="/screenshots/Mythic apollo process create.png" width="720"> </section>

This confirmed:

payload execution timestamp

file path

hash values

parent process context


### 16.2 Creating a Custom Detection Rule for Mythic Payload Execution

A custom rule was created to detect Apollo agent execution.

Navigation path:

Security → Rules → Create new rule → Custom query

<section> <img src="/screenshots/open rules to create rules.png" width="720"> </section>

Rule query used:

event.code : 1 AND (
  winlog.event_data.original_file_name : apollo.exe OR
  winlog.event_data.hashes : *
)


Rule configuration screens:

<section> <img src="/screenshots/rule configuration - 1.png" width="720"> </section> <section> <img src="/screenshots/rule configuration - 2.png" width="720"> </section> <section> <img src="/screenshots/rule configuration - 3.png" width="720"> </section>

Rule details:

Rule name: mythic-c2-apollo-agent-detected

Severity: Critical

Schedule: Every 5 minutes

Lookback: 5 minutes 🎯


### 16.3 Creating Suspicious Process Execution Visualization

A visualization was created to track suspicious process execution patterns, commonly used by attackers.

This includes:

PowerShell execution

unusual process names

non-standard execution paths

<section> <img src="/screenshots/creating visualization for dashboard.png" width="720"> </section>

### 16.4 Visualizing Outbound Network Connections

To detect C2-like behavior, a visualization was built to show process-initiated outbound connections 🌐.

This helps identify:

beaconing behavior

unexpected external communication

callback patterns

<section> <img src="/screenshots/creating 2nd visualization for dashboard.png" width="720"> </section>

### 16.5 Detecting Microsoft Defender Tampering

Defense evasion behavior was detected using Microsoft Defender Event ID 50001.

A visualization was created to highlight:

Defender real-time protection disable events

attacker attempts to weaken endpoint security 🛑

<section> <img src="/screenshots/creating 3rd visualization for dashboard.png" width="720"> </section>

### 16.6 Building the Suspicious Activity Dashboard

All detection-focused visualizations were combined into a single dashboard.

Dashboard contents:

suspicious process execution

outbound network activity

Defender tampering events

<section> <img src="/screenshots/Suspicious acticity dashboard created.png" width="720"> </section>

Dashboard name:

mydfir - suspicious activity


This dashboard provides centralized visibility into post-compromise behavior and C2-like activity 🔎.




---
## 17. Ticketing System Deployment – OS Ticket Setup

This section documents the deployment and configuration of OS Ticket, which acts as the case management and incident tracking system for the SOC.
This system is later integrated with Elastic to automate alert-to-ticket workflows 🧾⚙️.


### 17.1 Deploying the OS Ticket Server

A dedicated Windows Server 2022 virtual machine was deployed to host OS Ticket.

<section> <img src="/screenshots/osTicket vm created.png" width="720"> </section>

The server was accessed via Remote Desktop.

<section> <img src="/screenshots/open osTicket using remote desktop provider.png" width="720"> </section>

### 17.2 Installing XAMPP (Apache, PHP, MySQL)

OS Ticket requires a web server, PHP, and a database backend.
XAMPP was installed to provide all required services.

<section> <img src="/screenshots/download xampp.png" width="720"> </section> <section> <img src="/screenshots/xampp install.png" width="720"> </section>

### 17.3 Modifying XAMPP Configuration Files

Configuration changes were applied to ensure OS Ticket compatibility.

<section> <img src="/screenshots/cmade changes in properties file in xampp.png" width="720"> </section>

A backup of the configuration file was created.

<section> <img src="/screenshots/created a backup for config.inc.php.png" width="720"> </section>

Database configuration changes were applied.

<section> <img src="/screenshots/made changes in config.inc.php file in phpmyadmin.png" width="720"> </section>

### 17.4 Creating Windows Firewall Rules

Inbound firewall rules were created to allow HTTP and HTTPS traffic.

<section> <img src="/screenshots/create a new inbound rule.png" width="720"> </section> <section> <img src="/screenshots/new rule conf - 1.png" width="720"> </section> <section> <img src="/screenshots/new rule conf - 2.png" width="720"> </section> <section> <img src="/screenshots/new rule conf - 3.png" width="720"> </section> <section> <img src="/screenshots/new rule conf - 4.png" width="720"> </section>

### 17.5 Starting Apache & MySQL Services

Services were started from the XAMPP control panel.

<section> <img src="/screenshots/started the mysql and apache server.png" width="720"> </section>

The phpMyAdmin interface was opened.

<section> <img src="/screenshots/click admin.png" width="720"> </section> <section> <img src="/screenshots/click phpmyadmin.png" width="720"> </section>

### 17.6 Fixing phpMyAdmin Database Errors

Initial access to phpMyAdmin resulted in errors.

<section> <img src="/screenshots/got an eroor.png" width="720"> </section>

Several configuration and privilege fixes were applied.

<section> <img src="/screenshots/configuration changes.png" width="720"> </section> <section> <img src="/screenshots/click on root with localhost.png" width="720"> </section> <section> <img src="/screenshots/made changes in login information.png" width="720"> </section> <section> <img src="/screenshots/now make changes in config.inc.png" width="720"> </section> <section> <img src="/screenshots/now for pma account.png" width="720"> </section> <section> <img src="/screenshots/edit priveledges of pma.png" width="720"> </section> <section> <img src="/screenshots/change the pma config in config.inc.png" width="720"> </section>

After these changes, phpMyAdmin became fully accessible.


### 17.7 Downloading and Installing OS Ticket

OS Ticket was downloaded and the installer was launched.

<section> <img src="/screenshots/install osticket.png" width="720"> </section> <section> <img src="/screenshots/choose osticket version.png" width="720"> </section> <section> <img src="/screenshots/os ticket installer page.png" width="720"> </section>

### 17.8 Resolving OS Ticket Installation Issues

The initial installation attempt failed due to missing configuration.

<section> <img src="/screenshots/We got a problem now.png" width="720"> </section>

Required configuration changes were applied.

<section> <img src="/screenshots/made changes to ost-sampleconfig.png" width="720"> </section> <section> <img src="/screenshots/click on home icon.png" width="720"> </section> <section> <img src="/screenshots/check all boxex.png" width="720"> </section> <section> <img src="/screenshots/did some reset.png" width="720"> </section>

After correction, the installer completed successfully.


### 17.9 Verifying OS Ticket Access

OS Ticket web interface was successfully accessed via browser.

<section> <img src="/screenshots/osticket page.png" width="720"> </section>

This confirmed:

Apache is serving OS Ticket

database connectivity is functional

ticketing platform is ready for integration 🧠🧾



---
## 18. Alert-to-Ticket Automation (Elastic → OS Ticket Integration)

This section documents how Elastic detections were integrated with OS Ticket to automatically convert security alerts into tickets, enabling structured investigation and case tracking 🧾🔁.


### 18.1 Creating an API Key in OS Ticket

An API key was generated in OS Ticket to allow Elastic to create tickets programmatically.

Steps performed:

Logged into OS Ticket admin panel

Navigated to Manage → API

Created a new API key

Allowed access from the Elastic server’s private IP

<section> <img src="/screenshots/add new api key in osticket.png" width="720"> </section> <section> <img src="/screenshots/add key.png" width="720"> </section>

### 18.2 Enabling Elastic Connector Support

Webhook connectors require Elastic’s trial license.

Steps performed:

Opened Stack Management

Navigated to License Management

Activated the 30-day trial

<section> <img src="/screenshots/open stack management.png" width="720"> </section> <section> <img src="/screenshots/click manage 30 day licence.png" width="720"> </section>

### 18.3 Creating a Webhook Connector in Elastic

A webhook connector was created to send alert data to OS Ticket.

Steps performed:

Opened Stack Management → Connectors

Created a new Webhook connector

Connector configuration:

Method: POST

URL:
http://<OS_TICKET_IP>/osticket/upload/api/tickets.xml

Header:
X-API-Key: <OS_TICKET_API_KEY>

Payload format: XML

<section> <img src="/screenshots/go to connector.png" width="720"> </section> <section> <img src="/screenshots/webhook connector conf.png" width="720"> </section>

### 18.4 Resolving Network Connectivity Issue

Initial connector testing failed due to incorrect IP configuration on the OS Ticket server.

Steps performed:

Checked network adapter IP on OS Ticket server

Updated configuration to use the correct private VPC IP

<section> <img src="/screenshots/ipconfig on osticket server.png" width="720"> </section> <section> <img src="/screenshots/wrong ip problem solved.png" width="720"> </section>

### 18.5 Validating Webhook Connectivity

After fixing the IP issue, the webhook test was executed again.

<section> <img src="/screenshots/connector joined successfully.png" width="720"> </section>

This confirmed:

Elastic can reach OS Ticket

API authentication is valid

Ticket creation endpoint is functional 🎯


### 18.6 Test Ticket Creation in OS Ticket

A test alert generated a ticket inside OS Ticket.

This validated the full pipeline:

Elastic Alert → Webhook Connector → OS Ticket Ticket


The ticket contained:

rule name

alert metadata

timestamp

investigation reference




---
## 19. SOC Analyst Investigation Workflow (Alert → Ticket → Resolution)

This section documents how alerts generated by Elastic are handled by a SOC analyst, investigated using telemetry and dashboards, and finally resolved using OS Ticket 🧠🛡️.
The focus here is on operational response, not detection creation.


### 19.1 Receiving an Alert in Elastic Security

When a detection rule triggers, the alert appears in the Elastic Security dashboard.

Steps performed:

Opened Security → Alerts

Selected the SSH brute-force alert

Reviewed alert metadata

<img src="/screenshots/open alerts under security.png" width="750" height="420"> <img src="/screenshots/investigation - 1.png" width="750" height="420">

This view provides:

rule name

severity

affected host

timestamp

source IP 🌍


### 19.2 Automatic Ticket Creation in OS Ticket

Once the alert triggered, a ticket was automatically created in OS Ticket through the webhook connector.

Steps performed:

Logged into OS Ticket

Opened the newly created ticket

<img src="/screenshots/ticket generated.png" width="750" height="420"> <img src="/screenshots/ticket info.png" width="750" height="420">

The ticket contained:

alert title

description

event timestamp

SOC reference information 🧾


### 19.3 Assigning the Ticket to an Analyst

The ticket was assigned to an analyst for investigation.

<img src="/screenshots/assign ticket.png" width="750" height="420">

This ensures:

ownership

accountability

proper tracking of investigation progress 📌


### 19.4 Investigating the Alert in Kibana

The analyst pivoted back to Kibana to investigate the alert.

Steps performed:

Opened alert details

Reviewed surrounding authentication events

Checked if any login was successful

<img src="/screenshots/investigation - 2.png" width="750" height="420"> <img src="/screenshots/investigation - 3.png" width="750" height="420">

### 19.5 Validating Attacker Source and Behavior

Source IP addresses were analyzed for threat context.

Checks performed:

repeated login attempts

geographic origin

authentication success or failure

<img src="/screenshots/investigation - 2.png" width="750" height="420">

This helps differentiate between:

internet noise

targeted attack

successful intrusion ⚠️


### 19.6 Cross-Checking Dashboards

The analyst reviewed dashboards for broader context.

Dashboards checked:

SSH authentication map

RDP authentication dashboard

suspicious activity dashboard


This confirmed whether:

the attack escalated

lateral movement occurred

post-exploitation behavior was observed 🔍


### 19.7 Updating Ticket with Investigation Notes

Findings were documented directly inside the OS Ticket.

Steps performed:

Added investigation summary

Noted IP addresses and usernames

Recorded conclusion

<img src="/screenshots/post reply to ticket.png" width="750" height="420">

### 19.8 Closing the Ticket

After confirming no further malicious activity, the ticket was closed.

<img src="/screenshots/ticket status.png" width="750" height="420"> <img src="/screenshots/closed tickets.png" width="750" height="420">

This completes the SOC workflow:

Detect → Alert → Ticket → Investigate → Document → Close






---
## 20. Final SOC Capabilities & End-to-End Validation

This section documents the final operational state of the SOC after all infrastructure, detections, attack simulations, and response workflows were implemented and validated 🧠🛡️.
At this stage, the SOC is not a setup — it is a functioning security operations environment.


### 20.1 End-to-End SOC Lifecycle Validation

The SOC was validated using real attack activity and confirmed telemetry flow across all layers.

Validated lifecycle:

Endpoint Activity
→ Telemetry Collection
→ Detection Rule Trigger
→ Alert Generation
→ Ticket Creation
→ Analyst Investigation
→ Documentation
→ Ticket Closure


Each stage was observed live during SSH brute-force, RDP brute-force, and Mythic C2 attack execution 🔁.


### 20.2 Telemetry Coverage Validation

Telemetry sources confirmed operational:

Linux SSH authentication logs (auth.log)

Windows Security logs (Event ID 4624 / 4625)

Sysmon process creation and network telemetry

Microsoft Defender operational logs

Network callback behavior from compromised endpoint 📊

All logs were:

centrally ingested

searchable in Discover

correlated across dashboards


### 20.3 Detection Coverage Achieved

The SOC successfully detected:

SSH brute-force activity 🌍

RDP brute-force attempts on Windows 🪟

Successful remote logins

Post-login command execution

Suspicious process execution

Outbound C2 network callbacks 🌐

Microsoft Defender tampering 🚨

Each detection generated alerts that were actionable and traceable.


### 20.4 Dashboard & Visibility Confirmation

Dashboards confirmed working visibility across attack stages:

Authentication Activity Dashboard

SSH & RDP Geographic Maps

Suspicious Activity Dashboard

Process & Network Behavior Views 📈

These dashboards allowed rapid triage and context building during investigations.


### 20.5 Automated Case Management Validation

Alert-to-ticket automation functioned as designed:

Elastic alerts automatically created OS Ticket cases

Tickets contained alert context and metadata

Analysts were able to assign, investigate, update, and close tickets 🧾

This validated SOC operational maturity, not just alerting capability.


### 20.6 Separation of Attacker & Defender Infrastructure

A clear separation was maintained throughout:

SOC infrastructure remained private behind Zero Trust 🔒

Endpoints generated telemetry internally

Mythic C2 operated externally as attacker-controlled infrastructure ⚔️

This ensured realistic attack simulation without weakening defensive posture.


### 20.7 Final Operational State

At completion, the SOC environment delivered:

Private Zero Trust–based access

Centralized SIEM with Fleet-managed agents

Detection engineering across Linux and Windows

Real adversary simulation and validation

Automated alert escalation

Structured analyst investigation workflows 🧠

The SOC operated as a cohesive system, not a collection of tools.




---
## 21. Future Enhancements

This section outlines potential extensions to further strengthen detection depth and SOC maturity 🧠🚀.


### 21.1 MITRE ATT&CK Mapping

Map detections to MITRE ATT&CK techniques

Track coverage across attack stages

Identify visibility gaps and blind spots 🎯


### 21.2 EDR Correlations

Correlate process, network, and authentication events

Track parent–child process relationships

Improve confidence in post-exploitation detections 🛡️


### 21.3 Sigma Rule Integration

Import community Sigma rules

Convert Sigma logic into Elastic queries

Validate rules using existing attack simulations 📄


### 21.4 DNS & Beaconing Detection

Detect periodic outbound traffic patterns

Identify suspicious DNS behavior and beaconing 🌐

Enhance C2 detection beyond payload execution