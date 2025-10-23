# JMS Cluster Implementation Plan (with DNS-based Cluster Address)

## Objective

Safely introduce a DNS-based Cluster Address for the WebLogic JMS
cluster, ensuring all JMS servers recognize one another and clients can
connect via the new DNS round-robin name.

## Pre-Change Preparation (T-24h → T-1h)

### 1️⃣ Validate prerequisites

\- DNS A record oms-jms.myco.com exists with multiple IPs (one per JMS
node).\
- TTL temporarily set to 30--60 seconds for testing.\
- Confirm all JMS servers and stores are healthy in the Admin Console.\
- Verify no stuck threads, pending XA transactions, or store errors.

### 2️⃣ Communication & change control

\- Notify stakeholders and application owners.\
- Pause deployments and automated scaling actions.\
- Confirm rollback readiness (see section at bottom).

## Implementation Steps

### Step 1 --- Drain the JMS queues

Goal: Stop message production (apps) while allowing agents (consumers)
to finish processing all queued messages.\
\
1. In the WebLogic Console:\
- Go to Environment → Servers → App Servers.\
- Gracefully shut down all application servers (OMS or other message
producers) using \'Shutdown → When work completes.\'\
2. Keep agent servers running so they continue to consume all existing
messages.\
3. Monitor queue depth via Services → Messaging → JMS Modules →
Destinations → Monitoring until MessagesCurrentCount = 0.

### Step 2 --- Shut down agent servers

Once queues are drained, stop agent servers (the JMS consumers) via
Environment → Servers → \[Agent Servers\] → Control → Shutdown → When
work completes.

### Step 3 --- Shut down JMS managed servers

In the Console: Environment → Servers → \[JMS Servers\] → Control →
Shutdown → Force if idle. Verify each JMS server stops cleanly and its
persistent store closes without errors.

### Step 4 --- Update cluster properties

1\. Go to Environment → Clusters → \[Your Cluster\] → Configuration →
General.\
2. In Cluster Address, enter your new DNS name and port, e.g.,
oms-jms.myco.com:8001.\
3. Set Number of Servers (Members) to the number of JMS nodes.\
4. Click Save.

### Step 5 --- Activate the changes

Change Center → Activate Changes. Verify \'All changes have been
activated successfully.\' Expect a restart required notice for the
cluster.

### Step 6 --- Start JMS managed servers

Start all JMS managed servers via Control → Start. Check logs for
successful store mount, no port conflicts, and correct cluster
membership.

### Step 7 --- Validate network and DNS resolution

Run from an admin or jump host:\
dig +short oms-jms.myco.com\
nmap -p8001 oms-jms.myco.com\
\
Expected: both IPs show port 8001 open.

### Step 8 --- Validate intra-cluster visibility

In the Console: Environment → Clusters → Monitoring → Summary (all
members RUNNING). JMS Modules → Destinations → Monitoring (all members
Active).

### Step 9 --- Start the OMS app servers

Start all application servers via Environment → Servers → \[App
Servers\] → Start. Verify connectivity and successful initialization.

### Step 10 --- Start the agent servers

Start agent servers (consumers). Confirm new JMS connections appear on
both managed servers. Observe even consumer distribution.

## Post-Change Verification

\- nmap -p8001 oms-jms.myco.com shows open ports for all JMS nodes.\
- JMS servers running with no store or thread errors.\
- Cluster Address visible in Console.\
- JMS destinations active across all members.\
- Application-to-Agent flow works end-to-end.

## Rollback Plan

1\. Stop app and agent servers.\
2. Stop JMS servers.\
3. Console → Cluster → Configuration → General: revert Cluster Address.\
4. Activate changes.\
5. Restart JMS servers, then apps and agents.\
6. Verify message flow.

## Success Criteria

\- nmap -p8001 shows open ports for all JMS nodes.\
- Each JMS node sees all cluster members.\
- Agents consume messages from both nodes.\
- Apps enqueue messages normally.\
- No message loss, duplication, or stuck threads.
