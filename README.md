# Overview

On occasion, I have needed to spin up an OpenVPN link between two networks. There have been various reasons for this, including a C2 channel during a targeted attack.

There are a number of very good guides and scripts to take some of the complexity away from the PKI, such as easy_rsa (included with OpenVPN), and this project is not designed to replace these. If you are building a multi-user OpenVPN solution, it is worth building a PKI properly. 

For a site-to-site or single-use VPN instance, there is some overhead in this, especially if there is a desire to generate a completely non-attributable OpenVPN server; as an alternative, I have repurposed my certerator (https://github.com/stufus/certerator) code to generate a server CA, client CA and certificates for each.
