# Configuring Microsoft Sentinel
**Lab Walkthrough | Najad VK**

---

## Overview

This document covers end-to-end configuration of Microsoft Sentinel as a cloud-native SIEM platform. It walks through workspace setup, data ingestion via connectors, threat detection using analytics rules, and automated incident response. The goal is to build a functioning security monitoring environment from scratch and understand how each component fits into a real SOC workflow.

---

## What is Microsoft Sentinel

Microsoft Sentinel is a cloud-native SIEM and SOAR platform built on Azure. It collects security data from virtually any source, runs analytics to detect threats, and can automatically respond to incidents. Unlike traditional on-premises SIEMs, Sentinel requires no infrastructure to manage and scales automatically with data volume.

| Capability | What It Does |
|---|---|
| Data Connectors | Pulls logs from Microsoft services, third-party tools, and custom sources |
| Analytics Rules | Detects threats by running KQL queries against ingested data |
| NRT Rules | Near-real-time detection that runs every minute for critical events |
| Workbooks | Visual dashboards for monitoring and reporting |
| Automation Rules | Triggers automatic actions when incidents are created |
| Playbooks | Logic Apps that execute complex responses like sending email or creating tickets |
| Hunting | Proactive threat investigation using custom KQL queries |
| Threat Intelligence | IOC management including malicious IPs, domains, and file hashes |

---

## Lab 01: Setting Up the Sentinel Environment

### Task 1: Create a Log Analytics Workspace

Sentinel does not store data itself. It sits on top of a Log Analytics workspace, which is the actual data store. Every log, alert, and event that flows into Sentinel lands in this workspace first.

| Setting | Value |
|---|---|
| Resource Group | RG2 |
| Workspace Name | Sentinel-Test |
| Region | West US |
| Pricing Tier | Pay-as-you-go (Per GB 2018) |

> **Note:** The Pay-as-you-go tier shows up even on free trial accounts. This is normal. Free credits cover the charges automatically. For lab purposes, data ingestion stays well within the free 5GB per month allowance.

> **Observation:** When I created the workspace it showed Pay-as-you-go pricing which looked concerning on a free account. After checking the Azure Cost Management portal the free credits were still fully intact. Don't let this put you off.

---

### Task 2: Deploy Microsoft Sentinel to the Workspace

Once the Log Analytics workspace is created, Sentinel is layered on top of it. This is a one-time deployment that activates all Sentinel capabilities for that workspace. After deployment the Sentinel dashboard becomes accessible and the workspace is ready to receive data.

---

### Task 3: Assign a Microsoft Sentinel Role

Sentinel uses Azure RBAC to control who can do what within the platform. In a SOC environment different team members have different levels of access depending on their responsibilities.

| Role | What They Can Do |
|---|---|
| Sentinel Reader | View incidents, workbooks, and data. No modifications. |
| Sentinel Responder | View and manage incidents. Cannot change configurations. |
| Sentinel Contributor | Full access including creating rules, configuring connectors, and managing workbooks. |

> **Note:** In a real enterprise environment, IT Admin handles user account creation. As a Security Engineer your job is selecting the right role and scope, not managing user identities.

---

## Lab 02: Connecting Data to Microsoft Sentinel

A Sentinel deployment with no data sources is watching nothing. Data connectors are what bring security telemetry into the workspace. Microsoft packages these connectors into solutions available through the Content Hub.

### What is the Content Hub

The Content Hub is Sentinel's built-in marketplace. Each solution bundles data connectors, analytics rules, workbooks, hunting queries, and playbooks, all preconfigured for a specific data source or use case. Installing a solution from the Content Hub deploys everything in a single operation.

> **Observation:** Old guides and YouTube tutorials still reference the Content Hub inside the Azure portal. Microsoft moved it to the unified Defender portal at security.microsoft.com in 2025. If you cannot find it in Azure, go to security.microsoft.com instead.

---

### Task 1: Windows Security Events via AMA

The Windows Security Events connector collects security log data from Windows machines. AMA stands for Azure Monitor Agent, a lightweight agent installed on each Windows machine that reads local event logs and forwards them to the Log Analytics workspace.

The connection works by pairing each agent with a specific workspace using a Workspace ID and Primary Key. These two values act as an address and credential, ensuring only authorised machines can send logs to your workspace.

| Setting | Value |
|---|---|
| Connector | Windows Security Events via AMA |
| Collection Type | All Security Events |
| Agent | Azure Monitor Agent (AMA) |
| Configuration Method | Data Collection Rule (DCR) |

> **Note:** A Data Collection Rule defines what to collect, from which machines, and where to send it. One DCR can cover multiple machines, making it scalable across large environments.

> **Note:** This task requires a virtual machine with a paid Azure subscription to deploy the AMA agent. A VM running in Azure incurs compute costs. Stop the VM after lab completion to avoid unnecessary charges.

---

### Task 2: Azure Activity Connector

The Azure Activity connector captures all administrative actions taken within an Azure subscription: resource creation, deletion, role assignments, policy changes, and more. This is essential for detecting insider threats and unauthorised changes to your cloud environment.

Unlike the Windows Security Events connector which uses an agent, the Azure Activity connector works through an Azure Policy assignment. The policy automatically configures all resources in the subscription to forward their activity logs to the Sentinel workspace.

| Configuration Step | Purpose |
|---|---|
| Launch Azure Policy Assignment Wizard | Creates a policy that enforces log forwarding |
| Set Scope to Subscription | Applies the policy to all current and future resources |
| Set Primary Workspace | Tells the policy where to send the logs |
| Create Remediation Task | Applies the policy retroactively to existing resources |

> **Observation:** The remediation task is easy to overlook. Without it the policy only applies to newly created resources going forward. The remediation task backfills existing resources so they immediately start forwarding logs. Do not skip it.

---

### Task 3: Microsoft Defender for Cloud Connector

The Defender for Cloud connector brings security alerts from Microsoft Defender for Cloud into Sentinel. Defender for Cloud monitors Azure resources, virtual machines, databases, and containers for misconfigurations and active threats.

The key setting here is Bi-directional sync, which keeps incident status synchronised between Defender for Cloud and Sentinel. When an analyst updates an incident in Sentinel, that change reflects in Defender for Cloud, and vice versa.

> **Note:** Bi-directional sync requires at least one Microsoft Defender plan enabled on the subscription. Free-tier Azure accounts without paid Defender plans cannot enable this setting.

---

### Task 4: Create an Analytics Rule

Analytics rules are the detection engine of Sentinel. They run KQL queries against ingested data on a schedule and generate alerts when the query return results matching defined conditions.

This task uses a built-in rule template for detecting suspicious resource creation or deployment activity, a common indicator of cryptomining attacks or unauthorised infrastructure deployment.

| Setting | Value |
|---|---|
| Rule Template | Suspicious number of resource creation or deployment activities |
| Run Query Every | 1 Hour |
| Lookup Data From Last | 1 Hour |

> **Note:** Aligning the run frequency with the lookup window avoids duplicate alerts. If the query runs every hour but looks back five hours, the same events trigger alerts five times.

---

### Task 5: Azure Activity Workbook

Workbooks are interactive dashboards that visualise data from the Log Analytics workspace. The Azure Activity workbook provides charts and tables showing who did what in your Azure environment, making it easier to spot unusual administrative patterns.

---

## Advanced Detection and Automation

### Task 1: Configure Windows Security Events via AMA (DCR)

This task configures a Data Collection Rule that tells the AMA agent on a specific virtual machine what to collect and where to send it. Scoping the DCR to a single machine rather than all machines is a deliberate choice to limit data ingestion to only what is needed.

> **Note:** This task requires a virtual machine named VM1 running in an Azure subscription without spending limits.

---

### Task 2: Create a Near-Real-Time (NRT) Query Rule

Standard analytics rules run on a minimum five-minute schedule. NRT rules run approximately every minute, making them suitable for detecting high-priority events where speed of detection matters.

This rule detects when a user account is added to the local Administrators group on a Windows machine. Event ID 4732 is the specific Windows Security Event that logs this action. Adding an unauthorised account to the Administrators group is a classic privilege escalation technique.

```kql
SecurityEvent
| where EventID == 4732
| where TargetAccount == "Builtin\\Administrators"
```

| Setting | Value |
|---|---|
| Rule Type | NRT (Near-Real-Time) |
| Tactic | Privilege Escalation |
| Event ID | 4732 - User added to local group |
| Target | Builtin Administrators group |
| Detection Latency | Approximately 1 minute |

> **Note:** Event ID 4732 only appears in Sentinel if the Windows Security Events connector is active and collecting All Security Events from the relevant machine. Without the connector this rule will never fire.

> **Observation:** This is the kind of detection rule that directly maps to a real world attack. Any time I see privilege escalation in an incident at work, this is the event I look for in the logs. Building it from scratch in Sentinel makes it much clearer why the connector configuration matters.

---

### Task 3: Configure an Automation Rule

Automation rules execute predefined actions automatically when an incident is created or updated. They run immediately when triggered with no human intervention required.

This automation rule assigns an owner to every incident generated by the NRT rule. In a real SOC this routes the incident directly to the on-call analyst or the team responsible for privilege escalation investigations.

| Setting | Value |
|---|---|
| Trigger | When incident is created |
| Action | Assign owner |
| Owner | Designated SOC analyst or Operator account |

> **Note:** Automation rules handle simple immediate actions: assigning owners, changing severity, adding tags. For complex responses such as sending email notifications, creating tickets in ServiceNow, or calling external APIs, you need a Playbook built on Azure Logic Apps.

---

## Lab 03: Connecting Sentinel to Microsoft Defender XDR

### The Unified Security Operations Platform

Microsoft's direction is to consolidate Sentinel and Defender XDR into a single operational experience. Connecting the two platforms means security teams can investigate threats, run KQL queries across both datasets, and manage incidents from one portal.

| Before Integration | After Integration |
|---|---|
| Sentinel in Azure portal | Sentinel accessible from security.microsoft.com |
| XDR alerts separate from Sentinel incidents | XDR alerts flow into Sentinel as incidents |
| KQL queries limited to one platform | Advanced Hunting queries span both platforms |
| Two portals to monitor | Single unified SOC experience |

### How the Connection Works

The Microsoft Defender XDR solution is installed from the Sentinel Content Hub, which adds a dedicated data connector. Activating this connector links the Sentinel workspace to the Defender XDR tenant. From that point, incidents created in Defender XDR automatically appear in Sentinel, and Sentinel capabilities become accessible directly within the Defender portal.

> **Note:** Connecting Sentinel to Defender XDR requires a Microsoft 365 E5 license or equivalent Defender XDR licensing. This is not available on free Azure accounts.

### What Changes After Connection

Once connected, the Defender portal gains a Microsoft Sentinel section covering Search, Threat Management, Content Management, and Configuration. Analysts no longer need to switch portals. Advanced Hunting gains access to Sentinel-specific tables such as ThreatIntelligenceIndicator.

---

## Core Concepts Reference

### XDR vs SIEM

These are complementary tools that serve different purposes and work best together.

| | Microsoft Defender XDR | Microsoft Sentinel |
|---|---|---|
| Primary Focus | Microsoft product ecosystem | Any data source, any vendor |
| Response Capability | Automated response built-in | Playbooks via Logic Apps |
| Data Retention | Short-term | Long-term, configurable |
| Compliance Reporting | Limited | Full audit trail support |
| Pricing Model | Included with M365 E5 | Pay-per-GB ingested |
| Setup Complexity | Minimal | Requires planning and configuration |
| Query Language | KQL | KQL |

---

### How Logs Travel from a Windows Machine to Sentinel

Understanding this data flow helps when troubleshooting gaps in coverage or planning connector deployment.

1. Windows generates a security event and writes it to the local Event Log at `C:\Windows\System32\winevt\Logs`
2. The AMA agent, running as a background Windows service, reads the event log based on the rules defined in the Data Collection Rule
3. AMA compresses and encrypts the data and transmits it over HTTPS to an Azure ingestion endpoint
4. The data lands in the Log Analytics workspace associated with the Sentinel deployment
5. Analytics rules and NRT rules evaluate the incoming data and generate alerts when conditions are met
6. Alerts are grouped into incidents based on correlation logic defined in the analytics rule

> **Note:** For Azure-hosted virtual machines, the AMA agent communicates over Azure's internal network rather than the public internet, which improves reliability and reduces latency.

---

### SOC Team Structure and How Sentinel Supports It

| Role | Sentinel Interaction |
|---|---|
| Security Engineer | Configures connectors, builds detection rules, maintains automation |
| SOC Analyst L1 | Monitors the incident queue, triages new incidents, escalates when needed |
| SOC Analyst L2 | Investigates complex incidents, performs threat hunting |
| Incident Responder | Executes containment and remediation actions |
| SOC Manager | Reviews dashboards, manages SLAs, oversees team performance |

Automation rules eliminate manual triage steps like assigning incidents to the right person. In a 24/7 SOC with rotating shifts, an incident triggered at 3am automatically lands with the analyst on duty without a manager needing to intervene.

---

