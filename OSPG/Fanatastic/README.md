
![Fanatastic1](https://github.com/zmiddle/CTF-Writeups/blob/main/OSPG/Fanatastic/images/Fanatastic%201.png)

This is the result of a network scan performed using Nmap. It shows open ports on the target system, such as HTTP (80), SSH (22), and others. Open ports can be potential entry points for an attacker, and the services running on these ports (e.g., OpenSSH, httpd) can be examined for known vulnerabilities.


![Fanatastic2](https://github.com/zmiddle/CTF-Writeups/blob/main/OSPG/Fanatastic/images/Fanatastic%202.png)

The Grafana dashboard interface, accessed through a web browser. It's typically used for monitoring and visualization, but in a penetration testing scenario, if improperly configured, it could be a vector for information leakage or an attack if it allows unauthorized access to sensitive data.

![Fanatastic3](https://github.com/zmiddle/CTF-Writeups/blob/main/OSPG/Fanatastic/images/Fanatastic%203.png)

This screen indicates that Grafana is protected by a login, which is a security measure. However, default or weak credentials can be a vulnerability. The login screen confirms the presence of Grafana, allowing the tester to attempt credential stuffing or brute-force attacks to gain access.

![Fanatastic4](https://github.com/zmiddle/CTF-Writeups/blob/main/OSPG/Fanatastic/images/Fanatastic%204.png)

Shows a failed login attempt to Grafana, which suggests that the service has some form of account lockout or is actively rejecting incorrect credentials. This is useful to know as it means the system has some security measures in place to prevent easy unauthorized access.

![Fanatastic5](https://github.com/zmiddle/CTF-Writeups/blob/main/OSPG/Fanatastic/images/Fanatastic%205.png)

 This is a part of Grafana's administrative interface, which could reveal details about the configuration of data sources and collection methods. Such information may be useful in identifying misconfigurations or in understanding the network infrastructure for more targeted attacks.
 
![Fanatastic5](https://github.com/zmiddle/CTF-Writeups/blob/main/OSPG/Fanatastic/images/Fanatastic%205.png)

 This page provides specific information about the running Prometheus instance, including version numbers and build dates. Such details are invaluable when searching for exploits or vulnerabilities associated with particular versions.

![Fanatastic6](https://github.com/zmiddle/CTF-Writeups/blob/main/OSPG/Fanatastic/images/Fanatastic%206.png)

An entry from the Exploit Database details a specific vulnerability in Prometheus. Knowing that a service is vulnerable can guide a penetration tester to exploit it or use it as a pivot point to gain deeper access to a network.

![Fanatastic7](https://github.com/zmiddle/CTF-Writeups/blob/main/OSPG/Fanatastic/images/Fanatastic%207.png)

This shows a vulnerability for Grafana. Similar to the Prometheus entry, this informs the tester about potential weaknesses in the version of Grafana running on the target, which can be exploited to gain unauthorized access or escalate privileges.
