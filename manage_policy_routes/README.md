# manage_policy_routes

This directory contains a script for managing a specific policy_route in Fortigate firewalls.
Let's say that you have a specific policy_route in your Fortigate that grants internet access to VMs. So, if you add a new IP in the source section of this policy_route, the VM with that IP has internet access. In scenarios like this, you can use this script.

### Prerequisites
1. Create a Fortigate user (REST API Admin) with write access to the network/router.
2. Create the policy route that you want to manage.

