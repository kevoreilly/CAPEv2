============================
Deploying CAPE in the Cloud
============================

The following documentation will detail how to install CAPE using cloud resources.

Azure
=====
To use Azure as a machinery for CAPE, significant work must be done to deploy and secure 
the resource groups, network architecture, credential management, etc required.

Resource groups
---------------
The description below details how to create the resource groups that are required for isolating resources that should be controlled by the Azure machinery, which is running on a virtual machine and will have raw malware on it.

1. You will need three resource groups:
    a. The first resource group (RG1) will be where VNET1 (see below) will reside. This resource group is for client machines that will send files to CAPE.
    b. The second resource group (RG2) will be where VNET2 (see below) will reside, as well as the virtual machine that is running CAPE.
    c. The third resource group (RG3) will be where the sandbox resources will live.

Networking
----------
The description below details how a REST client could send files to CAPE, which would then detonate the 
submitted files in an isolated network.

1. You will need two virtual networks:
    a. The first virtual network (VNET1) will be where the client resides and goes in resource group RG1. The virtual network requires a subnet (VNET1_SUB1) that has the following network security group (VNET1_NSG1) rules applied:
        i. Allow inbound/outbound traffic over HTTP, going to or coming from the port where CAPE's REST API 
        is listening at the IP for VNET2_SUB1_NIC. The default port is 8000.
        ii. Allow inbound/outbound traffic over SSH (port 22) to the IP of VNET2_SUB1_NIC. This is so that we can connect to the Host from a safe virtual network (VNET1).
    b. The second virtual network (VNET2) will be where the CAPE host and the guests will reside and goes in resource group RG2. A virtual network peering resource is required to connect VNET1 and VNET2. VNET2 will consist of two subnets, one that will allow access to CAPE's REST API (VNET2_SUB1) and another that will provide a detonation space for the guests (VNET2_SUB2). Apply a network security group to these two subnets (VNET2_NSG1). The main ALLOW rules that we need in VNET2_NSG1 are as follows:
        i. Allow inbound traffic on port 8000 from VNET1_SUB1 -> VNET2_SUB1
        ii. Allow ALL inbound traffic from VNET2_SUB2 -> VNET2_SUB2
        iii. Allow ALL inbound traffic from VNET2_SUB2 -> 0.0.0.0/0
        iv. Allow ALL outbound traffic from port 8000 from VNET2_SUB1 -> VNET1_SUB1
        v. Allow ALL outbound traffic from VNET2_SUB2 -> VNET2_SUB2
        vi. Allow ALL outbound traffic from VNET2_SUB2 -> 0.0.0.0/0
        vii. Allow SOME inbound traffic from the Internet -> VNET2_SUB1 to allow the Azure machinery to communicate with Azure.
        viii. Allow SOME outbound traffic from VNET2_SUB1 -> Internet to allow the Azure machinery to communicate with Azure.
        ix. If you want to debug or watch the detonation in the guest from a machine in the same subnet as your REST client, you will need to open up ports 3389 (RDP for Windows guests) and 5900 (VNC for Linux guests) in both VNET1_NSG1 and VNET2_NSG1.

2. You will need a host machine (for CAPE) that has two network interface cards, one on VNET2_SUB1 (VNET2_SUB1_NIC) and another on VNET2_SUB2 (VNET2_SUB2_NIC).
    a. Put this VM in RG2.
    b. Set the private IPs of these network interface cards to static.

3. A route table resource has to be created in RG2 and applied to direct all traffic from guests through the host (VNET2_RT1). Apply this route table to VNET2_SUB2, and create a new rule that directs all traffic (0.0.0.0/0) to a virtual appliance, aka the IP of VNET2_SUB2_NIC.

These are the main networking resources required to deploy CAPE in Azure. 

Credential Management
---------------------
In the ``az.conf``, there are several crucial details that we will need for accessing/manipulating Azure resources. These details are ``client_id``, ``secret``, and ``tenant``.
To get these details, perform the following:

1. Create an Azure application:
    a. In the Azure portal, head to "App registrations"
    b. Click "New registration"
    c. Give the app a name and determine what the supported account types are
    d. Create the app
    e. Head to the app resource in the portal
    f. Select "API permissions" in the sidebar
    g. Click "Add a permission"
    h. Give the app "User.Read" to the Microsoft Graph API
    i. On the sidebar, click "Certificates & secrets"
    j. Select "+ New client secret"
    k. Create a secret
    l. Copy the secret details and paste it into the ``az.conf``
    m. Select "Overview" on the sidebar
    n. You can find the ``client_id`` and ``tenant_id`` details here. Copy and paste them into the ``az.conf``

2. Now that you've gathered the required credentials for the ``az.conf``, you need to set the following roles for this app on the resources:
    a. Give the app "Contributor " access to RG3.
    b. Give the app "Reader" to VNET2.


See :doc:`../guest/saving` for instructions on how to create a shared gallery image definition version, the equivalent of a snapshot for virtual machine scale sets.

