# Add VIP to Fortigate

This repository includes a script designed to simplify the process of configuring Virtual IP (VIP) settings on your Fortigate firewall. With this script, you can effortlessly create VIPs, organize them into VIP groups, and add a corresponding firewall policy.

The script does the following tasks:

1. VIP Creation: Generate Virtual IPs that enable traffic redirection to specific local IP addresses.
2. VIP Group Formation: Group VIPs together for efficient management and rule application.
3. Firewall Policy Setup: Generate a firewall policy with the following attributes:
   - Source: All sources.
   - Destination: VIP Group (The VIP group script was created)
   - Source Interface: WAN interface (automatically detected by the script, no manual input required).
   - Destination Interface: Outgoing interface leading to the local IP (automatically detected by the script, no manual input required).
   - Services: TCP and UDP ports, as specified in your input.


## Prerequisites
1. Create a Fortigate user (REST API Admin) with write access to the firewall section and read access to the network section.

## Usage

```bash
python3 add_vip.py
```
The script will prompt you for the following inputs:
1. fortigate_url: Enter the URL of your Fortigate device.
2. fortigate_vdom: Specify the Virtual Domain (VDOM) on your Fortigate.
3. fortigate_token: Provide the API token for Fortigate authentication.
4. name: Input the name of the object for which you want to create VIPs.
5. local_ip: Enter the local IP of your object.
6. publish_ip: Specify the publish IP for your object.
7. portforward: Choose whether to enable or disable port forwarding (options: enable/disable).
8. number_of_tcp_ports: Indicate the number of TCP ports for this local IP.
9. tcp_ports: Enter the TCP ports.
10. number_of_udp_ports: Specify the number of UDP ports for this local IP.
11. udp_ports: Enter the UDP ports.
    

