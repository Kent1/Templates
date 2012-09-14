#!/bin/sh

### BEGIN INIT INFO
# Provides: iptables rules
# Required-Start: $network
# Required-Stop:
# Default-Start: 2 3 4 5
# Default-Stop: 0 1 6
# Short-Description: iptables rules
# Description: Règles standards iptables
### END INIT INFO

#################
# Configuration #
#################

# Port SSH
PSH=22

# Ports supplémentaires à ouvrir en tant que serveur
SPRT=""

# Ports supplémentaires à ouvrir en tant que client
CPRT=""

# Fichier contenant les ip à bannir
IPBAN="/root/ipban"

############
# Firewall #
############

IPT=`which iptables`

color="\\033[0;34m"
end="\\033[0m"

print () {
    printf "[$color*$end] $* \n"
}

modprobe nf_conntrack
modprobe ip_conntrack
modprobe ipt_LOG

case "$1" in
start)

    ######################
    # Les règles de base #
    ######################

    # on fait pointer par défaut sur ACCEPT
    $IPT -P INPUT ACCEPT
    $IPT -P OUTPUT ACCEPT
    $IPT -P FORWARD ACCEPT

    # on nettoie
    $IPT -F
    $IPT -X
    print "Clearing previous entries."

    # on fait pointer par défaut sur DROP
    $IPT -P INPUT DROP
    $IPT -P OUTPUT DROP
    $IPT -P FORWARD DROP
    print "Drop ALL by default."

    # La machine locale est sure
    $IPT -A INPUT -i lo -j ACCEPT
    $IPT -A OUTPUT -o lo -j ACCEPT
    print "local machine is safe."

    # On autorise les connexions existantes ou relayés
    $IPT -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
    $IPT -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

    # On se protège des scan de port
    $IPT -A INPUT -p tcp --tcp-flags SYN,ACK,FIN,RST RST -m limit --limit 1/s -j ACCEPT
    print "Scan ports protection."

    # Protection SYN flood
    $IPT -A INPUT -p tcp --syn -m limit --limit 5/s -j ACCEPT
    $IPT -A INPUT -p udp -m limit --limit 10/s -j ACCEPT
    $IPT -A INPUT -p tcp --syn -j DROP
    $IPT -A INPUT -p udp -j DROP
    # Syn cookies
    echo 1 > /proc/sys/net/ipv4/tcp_syncookies
    print "Syn flood protection."

    # Protection ping flood
    $IPT -A INPUT -p icmp --icmp-type echo-request -m limit --limit 4/s -j ACCEPT
    $IPT -A INPUT -p icmp --icmp-type echo-reply -m limit --limit 4/s -j ACCEPT
    $IPT -A INPUT -p icmp --icmp-type echo-request -j DROP
    $IPT -A INPUT -p icmp --icmp-type echo-reply -j DROP

    # On autorise de pinger d'autres machines.
    $IPT -A OUTPUT -p icmp --icmp-type echo-request -j ACCEPT
    $IPT -A OUTPUT -p icmp --icmp-type echo-reply -j ACCEPT

    #Accepter le protocole ICMP
    $IPT -A INPUT -p icmp --icmp-type destination-unreachable -j ACCEPT
    $IPT -A INPUT -p icmp --icmp-type time-exceeded -j ACCEPT

    # Ignore ping
    #echo 1 > /proc/sys/net/ipv4/icmp_echo_ignore_all
    #echo 1 > /proc/sys/net/ipv4/icmp_echo_ignore_broadcasts

    # Ignorer les ICMP erronées
    echo 1 > /proc/sys/net/ipv4/icmp_ignore_bogus_error_responses

    # Ne pas accepter les redirections ICMP (empêche les attaques man in the middle)
    echo 0 > /proc/sys/net/ipv4/conf/all/accept_redirects
    echo 0 > /proc/sys/net/ipv4/conf/all/send_redirects

    print "Ping flood & ICMP protection."

    # Ne pas faire suivre les paquets IP
    echo 0 > /proc/sys/net/ipv4/conf/all/forwarding
    # Désactivation des paquets source routés.
    echo 0 > /proc/sys/net/ipv4/conf/all/accept_source_route

    ##########################################
    # Les règles pour les services standards #
    ##########################################

    # Serveur SSH
    $IPT -A INPUT -p tcp --dport $PSH -m state --state NEW,RELATED,ESTABLISHED -j ACCEPT
    $IPT -A OUTPUT -p tcp --sport $PSH -m state --state RELATED,ESTABLISHED -j ACCEPT
    print "Open SSH Server."

    # Serveur SMTP
    $IPT -A OUTPUT -p tcp --dport 25 -m state --state NEW,RELATED,ESTABLISHED -j ACCEPT
    $IPT -A INPUT -p tcp --sport 25 -m state --state RELATED,ESTABLISHED -j ACCEPT
    #print "Open SMTP."

    # Client DNS
    $IPT -A OUTPUT -p tcp --dport 53 -m state --state NEW,RELATED,ESTABLISHED -j ACCEPT
    $IPT -A INPUT -p tcp --sport 53 -m state --state RELATED,ESTABLISHED -j ACCEPT
    $IPT -A OUTPUT -p udp --dport 53 -m state --state NEW,RELATED,ESTABLISHED -j ACCEPT
    $IPT -A INPUT -p udp --sport 53 -m state --state RELATED,ESTABLISHED -j ACCEPT
    print "Open DNS Client."

    # Client NTP
    $IPT -A OUTPUT -p tcp --dport 123 -m state --state NEW,RELATED,ESTABLISHED -j ACCEPT
    $IPT -A INPUT -p tcp --sport 123 -m state --state RELATED,ESTABLISHED -j ACCEPT
    print "Open NTP."

    # Client requêtes WHOIS
    $IPT -A OUTPUT -p tcp --dport 43 -m state --state NEW,RELATED,ESTABLISHED -j ACCEPT
    $IPT -A INPUT -p tcp --sport 43 -m state --state RELATED,ESTABLISHED -j ACCEPT
    print "Open Whois."

    # Serveur Web (http et https)
    $IPT -A INPUT -p tcp --dport 80 -m state --state NEW,RELATED,ESTABLISHED -j ACCEPT
    $IPT -A OUTPUT -p tcp --sport 80 -m state --state RELATED,ESTABLISHED -j ACCEPT
    #$IPT -A INPUT -p tcp --dport 443 -m state --state NEW,RELATED,ESTABLISHED -j ACCEPT
    #$IPT -A OUTPUT -p tcp --sport 443 -m state --state RELATED,ESTABLISHED -j ACCEPT
    #print "Open Web Server."

    # Client Web (pour apt-get par exemple)
    $IPT -A INPUT -p tcp --sport 80 -m state --state RELATED,ESTABLISHED -j ACCEPT
    $IPT -A OUTPUT -p tcp --dport 80 -m state --state NEW,RELATED,ESTABLISHED -j ACCEPT
    $IPT -A INPUT -p tcp --sport 443 -m state --state RELATED,ESTABLISHED -j ACCEPT
    $IPT -A OUTPUT -p tcp --dport 443 -m state --state NEW,RELATED,ESTABLISHED -j ACCEPT
    print "Open Web Client."

    # Serveur FTP (ftp et ftp-data)
    #$IPT -A INPUT -p tcp --dport 20 -m state --state NEW,RELATED,ESTABLISHED -j ACCEPT
    #$IPT -A OUTPUT -p tcp --sport 20 -m state --state RELATED,ESTABLISHED -j ACCEPT
    #$IPT -A INPUT -p tcp --dport 21 -m state --state NEW,RELATED,ESTABLISHED -j ACCEPT
    #$IPT -A OUTPUT -p tcp --sport 21 -m state --state RELATED,ESTABLISHED -j ACCEPT
    #print "Open FTP Server."

    # Client FTP (apt-get par exemple)
    $IPT -A INPUT -p tcp --sport 20 -m state --state RELATED,ESTABLISHED -j ACCEPT
    $IPT -A OUTPUT -p tcp --dport 20 -m state --state NEW,RELATED,ESTABLISHED -j ACCEPT
    $IPT -A INPUT -p tcp --sport 21 -m state --state RELATED,ESTABLISHED -j ACCEPT
    $IPT -A OUTPUT -p tcp --dport 21 -m state --state NEW,RELATED,ESTABLISHED -j ACCEPT

    $IPT -A INPUT -p tcp --dport 1024:65535 --sport 1024:65535 -m state --state RELATED,ESTABLISHED -j ACCEPT
    $IPT -A OUTPUT -p tcp --dport 1024:65535 --sport 1024:65535 -m state --state RELATED,ESTABLISHED -j ACCEPT
    print "Open FTP Client."

    # Client IRC
    $IPT -A OUTPUT -p tcp --dport 6667 -m state --state NEW,RELATED,ESTABLISHED -j ACCEPT
    #$IPT -A INPUT -p udp --sport 133 -j ACCEPT # identification port
    #$IPT -A OUTPUT -p udp --dport 133 -j ACCEPT # identification port
    print "Open IRC Client."

    # rTorrent
    $IPT -A INPUT -p tcp --dport 6890:6999 -m state --state NEW,RELATED,ESTABLISHED -j ACCEPT
    $IPT -A INPUT -p udp --dport 6881 -j ACCEPT
    $IPT -A INPUT -p tcp --dport 1024:65535 --sport 1024:65535 -m state --state NEW,RELATED,ESTABLISHED -j ACCEPT
    $IPT -A OUTPUT -p tcp --dport 1024:65535 --sport 1024:65535 -m state --state NEW,RELATED,ESTABLISHED -j ACCEPT

    #########################
    # Ports supplémentaires #
    #########################

    # Serveur
    if [ -n "$SPRT" ]; then
      for PRT in $SPRT; do
        $IPT -A INPUT -p tcp --dport $PRT -m state --state NEW,RELATED,ESTABLISHED -j ACCEPT
        $IPT -A OUTPUT -p tcp --sport $PRT -m state --state RELATED,ESTABLISHED -j ACCEPT
        print "Open port $PRT for Server."
      done
    fi

    # Client
    if [ -n "$CPRT" ]; then
      for PRT in $CPRT; do
        $IPT -A OUTPUT -p tcp --dport $PRT -m state --state NEW,RELATED,ESTABLISHED -j ACCEPT
        $IPT -A INPUT -p tcp --sport $PRT -m state --state RELATED,ESTABLISHED -j ACCEPT
        print "Open port $PRT for Server."
      done
    fi

    ##############################
    # IP bannies supplémentaires #
    ##############################

    if [ -f $IPBAN ]; then
      nbln=`cat $IPBAN | wc -l`
      if [ $nbln -gt 0 ]
      then
        while read line
        do
          $IPT -I INPUT -s $line -j DROP
          $IPT -I OUTPUT -d $line -j DROP
        done < $IPBAN
        print "Ban IPs in $IPBAN."
      fi
    fi

    ########
    # logs #
    ########

    $IPT -N LOG_DROP
    $IPT -A LOG_DROP -j LOG --log-prefix '[IPTABLES - DROP] : ' --log-level debug
    $IPT -A LOG_DROP -j DROP
    $IPT -t filter -A INPUT -j LOG_DROP
    $IPT -t filter -A OUTPUT -j LOG_DROP
    $IPT -t filter -A FORWARD -j LOG_DROP

    $IPT -N FLOOD
    $IPT -A FLOOD -m limit --limit 1/s --limit-burst 20 -j RETURN
    $IPT -A FLOOD -j LOG --log-prefix "[IPTABLES - SYN flood] : "
    $IPT -A FLOOD -j DROP
    print "Initialize Logs"
    print "Firewall started"
;;

stop)

    $IPT -F
    $IPT -X
    $IPT -P INPUT ACCEPT
    $IPT -P OUTPUT ACCEPT
    $IPT -P FORWARD ACCEPT
    print "Firewall stopped"
;;

restart)
    $0 stop
    $0 start
;;

*)
    echo "Utilisation: firewall {start|stop|restart}"
    exit 1
;;

esac
exit 0
