#!/bin/bash

# Logan Nielsen IP-tables congifuration for CS3600 Intro to Comp Security

#####################################
#### STEP 0: CLEAR ALL OLD RULES ####
#####################################

# flush all chains
sudo iptables -F

# flush the mangle table
sudo iptables -F -t mangle

# flush the nat table
sudo iptables -F -t nat

# delete all non-defualt chains
sudo iptables -X

# delete all user-defined chains in mangle table
sudo iptables -X -t mangle

# delete all user-defined chains rules in nat table
sudo iptables -X -t nat

#############################################
#### STEP 1: SET POLICIES FOR EACH CHAIN ####
#############################################

# drops input traffic if it does not match any chain rules
sudo iptables -P INPUT DROP

# accepts forwarded traffic if it does not match any chain rules
sudo iptables -P FORWARD DROP

# drops outbound traffic if it does not match any chain rules
sudo iptables -P OUTPUT DROP


##########################################
#### STEP 2: ADD RULES TO INPUT CHAIN ####
##########################################

# Allow Related and Established Incoming Connections
sudo iptables -A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT

# Allow local traffic / Loopback Connections
sudo iptables -A INPUT -i lo -j ACCEPT

# allow stateful inbound remote ssh access from a specific IP address
sudo iptables -A INPUT -i eth0 -p tcp -s 15.15.15.0/24 --dport 22 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT

# allows inbound www http traffic
sudo iptables -A INPUT -p tcp --dport 80 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
sudo iptables -A OUTPUT -p tcp --sport 80 -m conntrack --ctstate ESTABLISHED -j ACCEPT

# allows inbound www https traffic
sudo iptables -A INPUT -p tcp --dport 443 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
sudo iptables -A OUTPUT -p tcp --sport 443 -m conntrack --ctstate ESTABLISHED -j ACCEPT

# allows inbound tcp webcache http-alt traffic
sudo iptables -A INPUT -p tcp --dport 8080 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
sudo iptables -A OUTPUT -p tcp --sport 8080 -m conntrack --ctstate ESTABLISHED -j ACCEPT

# allows inbound udp webcache http-alt traffic
sudo iptables -A INPUT -p udp --dport 8080 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
sudo iptables -A OUTPUT -p udp --sport 8080 -m conntrack --ctstate ESTABLISHED -j ACCEPT

# Default catch-all in case you did not have a secure default policy
sudo iptables -A INPUT -j REJECT

###########################################
#### STEP 3: ADD RULES TO OUTPUT CHAIN ####
###########################################

# Allow Established Outgoing Connections
sudo iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED -j ACCEPT

# Allow local / Loopback Connections
sudo iptables -A OUTPUT -o lo -j ACCEPT

# allows outbound www http traffic
sudo iptables -A OUTPUT -p tcp --dport 80 -j ACCEPT

# allows outbound www https traffic
sudo iptables -A OUTPUT -p tcp --dport 443 -j ACCEPT

# allows outbound webcache http-alt traffic
sudo iptables -A OUTPUT -p tcp --dport 8080 -j ACCEPT
sudo iptables -A OUTPUT -p udp --dport 8080 -j ACCEPT

# DNS allowed out on 53 -- NOTHING WORKED UNTIL I PUT THIS STUPID THING HERE
sudo iptables -A OUTPUT -p udp --dport domain -j ACCEPT

# allow stateful outbound ssh traffic to return to specified IP address in the above command (15.15.15.0/24)
sudo iptables -A OUTPUT -o eth0 -p tcp --sport 22 -m conntrack --ctstate ESTABLISHED -j ACCEPT

# Default catch-all in case you did not have a secure default policy
sudo iptables -A OUTPUT -j REJECT

############################################
#### STEP 4: ADD RULES TO FORWARD CHAIN ####
############################################


# NOT NEEDED, ONLY ONE NETWORK IN USE -- eth0


#######################################
#### STEP 5: SAVE THE CONFIGURATON ####
#######################################

# iptables command to save the current (above) configuration
{
   sudo iptables-save > /etc/iptables_rules
   echo "/sbin/iptables-restore < /etc/iptables_rules" >> /etc/rc.local
} &> /dev/null
