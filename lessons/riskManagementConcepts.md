# Risk Management Concepts

### Objectives 
- Risk Management Processes and Concepts
- Business Impact Analysis Concepts

# Risk Management Processes
The process of identifying, assessing and mitigating vulnerabilities and threats to essential functions that a business must perform to serve its customers.
- Identify mission essential
- Identify vulnerabilities
- Analyle business impacts
- Identify risk response

Likelihood of occurence.\
Impact is the severity of risk if realized as a security incident.\

## Risk types
- External
- Internal
- Multiparty
- Intellectual Property(IP) Theft
- Software Compliance/Licensing
- Legal Systems

## Quantitative Risk Assessment
Quantitative risk assessment aims to assign concrete values to each risk factor.

- Single Loss Expectancy (SLE)—the amount that would be lost in a single occurrence of the risk factor. This is determined by multiplying the value of the asset by an Exposure Factor (EF). EF is the percentage of the asset value that would be lost.
- Annualized Loss Expectancy (ALE)—the amount that would be lost over the course of a year. This is determined by multiplying the SLE by the Annualized Rate of Occurrence (ARO).

## Risk Management Strategies
Inherent Risk - before itigation

Risk mitigation(remediation)\
Risk deterrence(reduction)\

## Risk Avoidance and Risk Transference
Avoidance means that you stop doing the activity that is risk-bearing.\
Transference (or sharing) means assigning risk to a third party, such as an insurance company or a contract with a supplier that defines liabilities.

## Risk Acceptance 
Risk acceptance (or tolerance) means that no countermeasures are put in place either because the level of risk does not justify the cost or because there will be unavoidable delay before the countermeasures are deployed. 

## Residual Risk and Risk Appetite
Where inherent risk is the risk before mitigation, residual risk is the likelihood and impact after specific mitigation, transference, or acceptance measures have been applied. Risk appetite is a strategic assessment of what level of residual risk is tolerable. Risk appetite is broad in scope. Where risk acceptance has the scope of a single system, risk appetite has a project- or institution-wide scope. Risk appetite is constrained by regulation and compliance.

## Control Risk
Control risk is a measure of how much less effective a security control has become over time. For example, antivirus became quite capable of detecting malware on the basis of signatures, but then less effective as threat actors started to obfuscate code. Control risk can also refer to a security control that was never effective in mitigating inherent risk.

## Risk Awareness
A risk register is a document showing the results of risk assessments in a comprehensible format. The register may resemble the heat map risk matrix shown earlier with columns for impact and likelihood ratings, date of identification, description, countermeasures, owner/route for escalation, and status. 

## Business Impact Analysis
It is the process of assessing what losses might occur for a range of threat scenarios. 

Business impact analysis informs risk assessment by documenting the workflows that run the organization and the critical assets and systems that support them.

## Mission Essential Functions(MEF)
Functions that cannot be deferred. Should be restored first in case of disturbance.
- Maximum Tolerable Downtime(MTD) - longest period that a business function outage can occur without irrecoverable business failure.
- Recovery Time objective(RTO) - period of time a system may remain offline.
- Work Recovery Time(WRT) - time to integrate systems, test and ensure its working.
- Recovery Point Objective(RPO) -  is the amount of data loss that a system can sustain, measured in time. That is, if a database is destroyed by a virus, an RPO of 24 hours means that the data can be recovered (from a backup copy) to a point not more than 24 hours before the database was infected.

## Identification of Critical Systems
To support the resiliency of mission essential and primary business functions, it is crucial to perform an identification of critical systems. This means compiling an inventory of business processes and the assets that support them. Asset types include:
- People
- Tangible assets
- Intagible assets(ideas)
- Procedures(supply chains)

Dependencies are identified by performing a business process analysis (BPA) for each function. The BPA should identify the following factors
- Inputs
- Hardware
- Staff
- Outputs
- Process flow

## Single Point of Failure
Mitigated by provisioning redundant components.\
Key Performance Indicators(KPIs)
- Mean Time Between Failures(MTBF) - Expected Lifetime of a product. Total operation time/ number of failures
- Mean Time to Failure(MTTF) - for non repeairable components. operational time/number of devices
- MTTF/MTBF can be used to determine the amount of asset redundancy a system should have.
- Mean Time to Repair(MTTR) - time taken to correct a fault back to operational

## Disasters
An event that could threaten mission essential functions.
- Internal vs External
- Person made 
- Environmental
- Site Risk Assesment

## Disaster Recovery Plan
