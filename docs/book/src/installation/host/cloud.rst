============================
Deploying CAPE in the Cloud
============================

The following documentation will detail how to install CAPE using cloud resources.

Azure
=====
To use Azure as a machinery for CAPE, significant work must be done to deploy and secure 
the network architecture required.

Networking
----------
The description below details how a REST client could send files to CAPE in an isolated network.
1. You will need two virtual networks
    a. The first virtual network (VNET1) will be where the client resides. The virtual network
     requires a subnet (VNET1_SUB1) that has the following network security group (VNET1_NSG1) rules applied:
        i. Allow inbound/outbound traffic over HTTP, going to or coming from the port where CAPE's REST API 
        is listening at the IP for VNET2_SUB1_NIC. The default port is 8000.
        ii. Allow inbound/outbound traffic over SSH (port 22) to the IP of VNET2_SUB1_NIC. This is so that
         we can connect to the Host from a safe virtual network (VNET1).
    b. The second virtual network (VNET2) will be where the CAPE host and the guests will reside. A 
    virtual network peering resource is required to connect VNET1 and VNET2. VNET2 will consist of 
    two subnets, one that will allow access to CAPE's REST API (VNET2_SUB1) and another that will 
    provide a detonation space for the guests (VNET2_SUB2). Apply a network security group to these
    two subnets (VNET2_NSG1). The main ALLOW rules that we need in VNET2_NSG1 are as follows:
        i. Allow inbound traffic on port 8000 from VNET1_SUB1 -> VNET2_SUB1
        ii. Allow ALL inbound traffic from VNET2_SUB2 -> VNET2_SUB2
        iii. Allow ALL inbound traffic from VNET2_SUB2 -> 0.0.0.0/0
        iv. Allow ALL outbound traffic from port 8000 from VNET2_SUB1 -> VNET1_SUB1
        v. Allow ALL outbound traffic from VNET2_SUB2 -> VNET2_SUB2
        vi. Allow ALL outbound traffic from VNET2_SUB2 -> 0.0.0.0/0
        vii. Allow SOME inbound traffic from the Internet -> VNET2_SUB1 to allow the Azure machinery to 
        comunicate with Azure.
        viii. Allow SOME outbound traffic from VNET2_SUB1 -> Internet to allow the Azure machinery to 
        communicate with Azure.
        ix. If you want to debug or watch the detonation in the guest from a machine in the same subnet as 
        your REST client, you will need to open up ports 3389 (RDP for Windows guests) and 5900 (VNC for Linux guests) 
        in both VNET1_NSG1 and VNET2_NSG1.

2. You will need a host machine that has two network interface cards, one on VNET2_SUB1 (VNET2_SUB1_NIC) and another on 
VNET2_SUB2 (VNET2_SUB2_NIC).
    a. Set the private IPs of these network interface cards to static.

3. A route table resource has to be created and applied to direct all traffic from guests through the host (VNET2_RT1). 
Apply this route table to VNET2_SUB2, and create a new rule that directs all traffic (0.0.0.0/0) to a virtual appliance, 
aka the IP of VNET2_SUB2_NIC.

4. Install CAPE on the host machine as usual.

These are the main networking resources required to deploy CAPE in Azure. See :doc:`../guest/saving` for instructions on 
how to create a shared gallery image definition version, the equivalent of a snapshot for virtual machine scale sets.

