#!/bin/bash
############################################################################
# Shellscript:	"setips.sh" Generates randoms ips within the user
#	user provided network range. This script automatically assigns
#	each ip to a new sub-interface starting with the sub-int number
#	provided. It does not set gateway nor dns nameservers.
#
# Author : spatiald
############################################################################
#uncomment to debug
#set -x

# Setup some path variables
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# Variables - change them if you want to
version=BETA2
currentDateTime=`date +"%Y%b%d-%H%M"`
defaultMTU=1300 # Normal is 1500
currentgw=`route -n|grep eth0| head -n 1|cut -d"." -f4-7|cut -d" " -f10`
setipsFolder="/root/setips-files"
ipsSaved="$setipsFolder/ips-saved.txt" # Save file for restoring IPs
ipsArchive="$setipsFolder/ips-archive.txt" # IP archive listed by date/time for reference during exercises
cobaltstrikeDir="/redteam/toolkit/cobaltstrike"
c2profilesDir="$HOME/c2profiles"
veilDir="/redteam/avevasion/Veil"
powersploitDir="$HOME/powersploit"
iptablesBackup="$setipsFolder/iptables"
iptablesBackupfile="iptables-$currentDateTime"
subintsBackup="$setipsFolder/subints"
redteamShare="http://share.com/remote.php/webdav" # NO trailing slash
redteamShareUser="psswrd"
redteamWiki="http://wiki.rt/current-wiki"
redteamWikiUser="redteam"
redteamPathToUpdateSetips="linux/setips.sh"
redteamPathToUpdateSetipsBeta="linux/setips-beta.sh"
redteamPathToPullSnortRules="scripts/snort.rules"
snortRulesFile="snort.rules"
snortRulesDirectory="/root/snort-rules"
snortRulesFileDownloadLocation="$snortRulesDirectory/$snortRulesFile"
setipsUpdateFileDownloadLocation="/root/setips.sh"

# Fix backspace
stty sane

# Do not change this - sets counter to 0
counter=0
inundator=`which inundator`
ifconfig=`which ifconfig`
fping=`which fping`
ping=`which ping`
iptables=`which iptables`

#in case you wish to kill it
trap 'exit 3' 1 2 3 15

# Setup backup folder for saving setips scripts/backup files
if [[ ! -d "$setipsFolder" ]]; then
	mkdir -p $iptablesBackup
	echo; echo "[+] Created $iptablesBackup; all setips files are stored there."
fi

if [[ -f "/root/ips-saved.txt" ]]; then
	if [[ -f "$ipsSaved" ]]; then
		rm -f /root/ips-saved.txt /root/ips-archive.txt > /dev/null 2>&1
		rm -f /ips-saved.txt /ips-archive.txt 2>&1
	else
		mv /root/ips-saved.txt /root/ips-archive.txt $setipsFolder > /dev/null 2>&1
		mv /ips-saved.txt /ips-archive.txt $setipsFolder > /dev/null 2>&1
	fi
fi

# Find the IP addresses in use
function listIPs {
	echo; echo "[-] Ethernet interfaces that have assigned addresses:"
	$ifconfig |grep -B1 "inet addr" |awk '{ if ( $1 == "inet" ) { print $2 } else if ( $2 == "Link" ) { printf "%s:" ,$1 } }' | sed 's/[addr]//g' |awk -F:: '{ print $1 " " $NF }' | sed "/lo/d"
}

# Find the core IP address in use
function listCoreIP {
	echo; echo "[-] Core IP address on this system:"
	$ifconfig | head -n2 | awk '{ if ( $1 == "inet" ) { print $2, $4 } else if ( $2 == "Link" ) { printf "%s " ,$1 } }'
}

# List the interfaces without addresses assigned
function listInts {
	echo; echo "[-] Ethernet interfaces:"
	$ifconfig |grep "eth" | awk '{ print $1 " " }' | sed "/lo/d" | sed "/:/d"
}

# Ask which ethernet port you want to create subinterfaces for
function whatInterface {
while :; do
	echo; echo "[?] What ethernet interface do you want to work with (choose a root interface, ie eth0 or eth1)?"; read ethInt
	if [[ "$ethInt" =~ ^[A-Za-z]{3}+[0-9]{1}$ ]]; then
		break
	else
		echo; echo "[!] Please enter the root ethernet interface (for example, enter eth0 not eth0:1)"
	fi
done
}

# List IPs, single line, comma-seperated
function listIPs-oneline {
	# List IPs for use in Armitage/Cobalt Strike "Teamserver"
	$ifconfig | grep -B1 "inet addr" |awk '{ if ( $1 == "inet" ) { print $2 } else if ( $2 == "Link" ) { printf "%s:" ,$1 } }' | sed 's/[addr]//g'| awk -F:: '{ print $NF }' | head -n -1 | awk '{printf "%s,",$0} END {print ""}' | sed 's/.$//'
}

# Tests IP for connectivity
function pingTest {
	if [ `which fping` ]
	then
		$fping -c 1 $unusedip || echo $unusedip/$subnet >> /tmp/ips.txt
	else
		$ping -c 1 -w 0.5 $unusedip || echo "Available IP: "$unusedip; echo $unusedip/$subnet mtu $mtu >> /tmp/ips.txt
	fi
}

# What MTU
function whatMTU {
	# MTU
	echo; echo "[?] What is your desired MTU setting (current default is $defaultMTU)?"; read mtu || return
	if [ -z ${mtu:+x} ]; then
		echo "[+] Setting mtu of $defaultMTU."
		mtu=$defaultMTU
	else
		echo "[+] Setting your desired mtu of $mtu"
	fi
	# Add MTU to backup file
	echo $mtu > $setipsFolder/mtu.current
}

# Remove all subinterfaces
function removeSubInts {
	$ifconfig | grep $ethInt |cut -d" " -f1 |tail -n +2 >> /tmp/sub.txt
	while IFS= read sub; do
	$ifconfig $sub down > /dev/null 2>&1
	done < "/tmp/sub.txt"

	if [ -s /tmp/sub.txt ]; then
		echo; echo "[-]Removed subinterface(s):"
		cat /tmp/sub.txt
		rm /tmp/sub.txt > /dev/null 2>&1
		rm /tmp/ips.txt > /dev/null 2>&1
	fi
}

# Add subinterfaces
function addSubInts {
	{ rm /tmp/ips.txt; touch /tmp/ips.txt; } > /dev/null 2>&1
	# MTU
	whatMTU

	# SUBNET
	echo; echo "[?] What subnet class are you creating IPs for?"
	select class in "A" "B" "C"; do
		case $class in
		A)
		# Find out the range that we are setting
		echo; echo "[?] What is the IP's first octet (number)?"; read octet1
		echo "[?] What is the IP's second octet (range; ie 1-255)?"; read octet2
		echo "[?] What is the IP's third octet (range; ie 1-255)?"; read octet3
		echo "[?] What is the IP's fourth octet (range; ie 1-255)?"; read octet4
		echo; echo "[?] What subnet (ie 8 for a 255.0.0.0)?"; read subnet

		#Ask how many subinterface ips the user would like
		echo; echo "[?] How many virtual ips (subinterfaces) would you like?"; read numberips

		until [[ $numberips = $(wc -l < /tmp/ips.txt) ]]; do
			unusedip=$octet1"."$(shuf -i $octet2 -n 1)"."$(shuf -i $octet3 -n 1)"."$(shuf -i $octet4 -n 1)
			pingTest
		sort -u /tmp/ips.txt > /tmp/ips2.txt; mv /tmp/ips2.txt /tmp/ips.txt
		done

		echo; echo "[+] Identified $numberips available IPs; setting subinterface IPs!"
		break
		;;

		B)
		# Find out the range that we are setting
		echo; echo "[?] What is the IP's first octet (number)?"; read octet1
		echo "[?] What is the IP's second octet (number)?"; read octet2
		echo "[?] What is the IP's third octet (range; ie 1-255)?"; read octet3
		echo "[?] What is the IP's fourth octet (range; ie 1-255)?"; read octet4
		echo; echo "[?] What subnet (ie 16 for a 255.255.0.0)?"; read subnet

		#Ask how many subinterface ips the user would like
		echo; echo "[?] How many virtual ips (subinterfaces) would you like?"; read numberips

		until [[ $numberips = $(wc -l < /tmp/ips.txt) ]]; do
			unusedip=$octet1"."$octet2"."$(shuf -i $octet3 -n 1)"."$(shuf -i $octet4 -n 1)
			pingTest
		sort -u /tmp/ips.txt > /tmp/ips2.txt; mv /tmp/ips2.txt /tmp/ips.txt
		done
		echo; echo "[+] Identified $numberips available IPs; setting subinterface IPs!"
		break
		;;

		C)
		# Find out the range that we are setting
		echo; echo "[?] What is the IP's first octet (number)?"; read octet1
		echo "[?] What is the IP's second octet (number)?"; read octet2
		echo "[?] What is the IP's third octet (number)?"; read octet3
		echo "[?] What is the IP's fourth octet (range; ie 1-255)?"; read octet4
		echo; echo "[?] What subnet (ie 24 for a 255.255.255.0)?"; read subnet

		#Ask how many subinterface ips the user would like
		echo; echo "[?] How many virtual ips (subinterfaces) would you like?"; read numberips

		until [[ $numberips = $(wc -l < /tmp/ips.txt) ]]; do
			unusedip=$octet1"."$octet2"."$octet3"."$(shuf -i $octet4 -n 1)
			pingTest
		sort -u /tmp/ips.txt > /tmp/ips2.txt; mv /tmp/ips2.txt /tmp/ips.txt
		done
		echo; echo "[+] Identified $numberips available IPs; setting subinterface IPs!"
		break
		;;
		esac
	done

	# Add subnet to backup file
	echo $subnet > $setipsFolder/subnet.current

	echo; echo "[?] What subinterface number would you like to start assigning ips to?"; read num; num=$((num-1))
	while IFS= read ip; do
		num=$((num+1))
		$ifconfig $ethInt:$num $ip mtu $mtu
	done < "/tmp/ips.txt"
	echo "[+] Done."; echo
	cp -f /tmp/ips.txt $ipsSaved

	# Save ips set for future restore by this script
	$ifconfig |grep -B1 "inet addr" |awk '{ if ( $1 == "inet" ) { print $2 } else if ( $2 == "Link" ) { printf "%s:" ,$1 } }' | sed 's/[addr]//g' | awk -F:: '{ print $1 " " $NF }' | sed -e "s/$/\/$subnet mtu $mtu/" | sed "/lo/d" > $ipsSaved

	# Append ips to running log
	echo $(date) >> $ipsArchive
	listIPs-oneline >> $ipsArchive

	echo "[+] Your IP settings were saved to three files:";
	echo "   - $ipsSaved -> restore them with this program";
	echo "   - $ipsArchive -> running log of all IPs used during an exercise/event";
	rm -rf /tmp/ips*.txt /tmp/sub.txt > /dev/null 2>&1
}

# Check for subinterfaces
function checkForSubinterfaces {
	$ifconfig | grep $ethInt |cut -d" " -f1 |tail -n +2 >> /tmp/sub.txt
	if [ ! -s /tmp/sub.txt ]; then
		echo; read -p "[?] No subinterfaces exist...would you like to create some? (y/n) " -n 1 -r
		if [[ $REPLY =~ ^[Yy]$ ]]; then
			addSubInts
		fi
	else
		echo; read -p "[?] Do you want to change your current subinterface IPs? (y/n) " -n 1 -r
		if [[ $REPLY =~ ^[Yy]$ ]]; then
			removeSubInts
			addSubInts
		fi
	fi
}

# Restore subinterface IPs from file
function restoreSubIntsFile {
	# Identify the subinterfaces save file
	echo; echo "[?] What is the full path to the setips save file (default is $ipsSaved)?"; read savefile || return
	if [ -z ${savefile:+x} ]; then
		echo "[+] Restoring from $ipsSaved.";
		savefile=$ipsSaved
	else
		echo "[+] Restoring from $savefile";
	fi
	echo; echo "[?] What is the IP of the gateway?"; read gatewayip || return
	# Add subinterfaces
	while IFS= read intip; do
		$ifconfig $intip
	done < "$savefile"
	# Add new gw
	route add default gw $gatewayip
}

# Set the IP
function initialSetup {
	listInts
	whatInterface
	whatMTU
	echo; echo "[?] What IP do you want to set?"; read ip
	echo; echo "[?] What subnet (ie 8 for a 255.0.0.0)?"; read subnet
	$ifconfig $ethInt $ip/$subnet mtu $mtu
	# Add subnet to backup file
	echo $subnet > $setipsFolder/subnet.current
	echo; echo "[+] Your $ethInt IP is setup:"
	echo; ifconfig $ethInt
	setGateway
	setDNS
	sed -i '/iface eth0 inet dhcp/d' /etc/network/interfaces
	echo "address $ip" >> /etc/network/interfaces
	if ! which ipcalc > /dev/null; then
		echo; echo "[!] The program ipcalc is not installed...what is the actual netmask (ie 255.255.0.0)?"; read netmask
		echo "netmask $netmask" >> /etc/network/interfaces
	else
		netmask=`ipcalc -c 13 | grep Address | awk '{ print $2 }'`
		echo "netmask $netmask" >> /etc/network/interfaces
        fi
	gatewayip=`route -n|grep $ethInt|grep 0.0.0.0|grep G|head -n 1|cut -d"." -f4-7|cut -d" " -f10`
	echo "gateway $gatewayip" >> /etc/network/interfaces
	dns=`cat /etc/resolv.conf | grep nameserver | awk '{ print $2}' | awk '{printf "%s ",$0} END {print ""}'`
	echo "dns-nameservers $dns" >> /etc/network/interfaces
	# Startup Cobaltstrike requirements
	echo; echo "[+] Setting up initial services for Cobalt Strike support."
	arch=`uname -m`
	if [[ $hosttype = *"x86_64"* ]]; then
		update-java-alternatives --jre -s java-1.7.0-openjdk-amd64 # For x64
	else
		update-java-alternatives --jre -s java-1.7.0-openjdk-i386 # For x86
	fi
	service postgresql start
	service metasploit start
	service metasploit stop
	echo; echo "[+] Setup complete."
#	echo; echo "[+] Starting Cobalt Strike client."
#	cd cobaltstrike; ./cobaltstrike
}

# Set default gateway
function setGateway {
	currentgw=`route -n|grep $ethInt|grep 0.0.0.0|grep G|head -n 1|cut -d"." -f4-7|cut -d" " -f10`
	gatewayip=$currentgw
	if [ -z ${currentgw:+x} ]; then
		echo; echo "[!] You do not have a default gateway set.";
	else
		echo; echo "[-] Your current gateway is:  $gatewayip";
	fi
	echo; read -p "[?] Do you want to change your gateway? (y/n)" -n 1 -r
	if [[ $REPLY =~ ^[Yy]$ ]]; then
		echo; echo "[?] What is the IP of the gateway?"; read gatewayip || return
		# Remove current gw
		route del default gw $currentgw
		# Add new gw
		route add default gw $gatewayip
		newgw=`route -n|grep $ethInt|grep 0.0.0.0|grep G|head -n 1|cut -d"." -f4-7|cut -d" " -f10`

#		newgw=`route -n|grep eth0| head -n 1|cut -d"." -f4-7|cut -d" " -f10`
		if [ -z ${newgw:+x} ]; then
			echo; echo "[!] Something went wrong...check your desired gateway.";
		else
			echo; echo "[+] Your gateway was updated to:  $newgw"; echo
			# Print current routing table
			route -n; echo
			echo; echo "[+] Your gateway was set.";
		fi
	else
		echo; echo "[!] Gateway not changed.";
	fi
}

# Set DNS
function setDNS {
	echo; echo "[-] Your current DNS settings:";
	cat /etc/resolv.conf
	echo; read -p "[?] Do you want to change your DNS servers? (y/n)" -n 1 -r
	if [[ $REPLY =~ ^[Yy]$ ]]; then
		echo; echo "[?] What are the DNS server IPs (space separated)?"; read dnsips || return
		rm /etc/resolv.conf
		IFS=' '; set -f
		eval "array=(\$dnsips)"
		for x in "${array[@]}"; do echo "nameserver $x" >> /etc/resolv.conf; echo; done
		echo; echo "[+] Your DNS settings were updated as follows:"
		cat /etc/resolv.conf; echo;
	else
		echo; echo "[!] DNS not changed.";
	fi
}

# Auto set subinterface IPs on system start/reboot
function autoSetIPsOnStart {
	rm /root/setips-atstart.sh > /dev/null 2>&1 # check for old version
	subnet=`cat $setipsFolder/subnet.current`
	$ifconfig |grep -B1 "inet addr" |awk '{ if ( $1 == "inet" ) { print $2 } else if ( $2 == "Link" ) { printf "%s:" ,$1 } }' | sed 's/[addr]//g' | awk -F:: '{ print $1 " " $NF }' | sed -e "s/$/\/$subnet/" | sed "/lo/d" > $ipsSaved
	removeSetIPsOnStart
	setGateway
	sed "s,%SETIPSFOLDER%,$setipsFolder,g;s,%GATEWAYIP%,$gatewayip,g" >$setipsFolder/setips-atboot.sh << 'EOF'
#!/bin/bash
#Auto-generated script - DO NOT REMOVE
#
#This is a setips.sh created script that
#restores ip saved by the setips script
#
ifconfig=`which ifconfig`
while IFS= read intip; do
	$ifconfig $intip
done < %SETIPSFOLDER%/ips-saved.txt
route add default gw %GATEWAYIP%
EOF
	chmod +x $setipsFolder/setips-atboot.sh
	sed -i '$e echo "#setips - Auto-set IPs on startup using setips-atboot.sh script"' /etc/rc.local
	sed -i '$e echo "'$setipsFolder'/setips-atboot.sh&"' /etc/rc.local
	awk 'BEGIN{OFS=FS="/"} $1~/$setipsFolder/ {$1="'$setipsFolder'";}1' /etc/rc.local > /tmp/rclocal.tmp; mv /tmp/rclocal.tmp /etc/rc.local
	echo; echo "[+] Added script to setup subinterface IPs on system startup."
	echo "[!] The setips save file must be located at $setipsFolder/ips-saved.txt"
}

# Remove setips script from /etc/rc.local
function removeSetIPsOnStart {
	sed -i '/setips-atboot/d' /etc/rc.local
	rm -f /root/setips-atboot.sh
}

# Change /etc/ssh/sshd_config conifguration for root to only login "without-password" to "yes"
function fixSSHConfigRoot {
	awk 'BEGIN{OFS=FS=" "} $1~/PermitRootLogin/ {$2="yes";}1' /etc/ssh/sshd_config > /tmp/sshd_config.tmp; mv /tmp/sshd_config.tmp /etc/ssh/sshd_config
	service ssh restart
	echo; echo "[+] Modified /etc/ssh/sshd_config file to allow root to login with a password, restarted ssh."
}

# Add ssh socks proxy to /etc/rc.local
function autoStartSOCKSProxy {
	sed -i '/screen/d' /etc/rc.local
	sed -i '$e echo "#SOCKS - Auto-start SOCKS proxy on startup using screen"' /etc/rc.local
	sed -i '$e cat /tmp/ssh.tmp' /etc/rc.local
	rm -f /tmp/ssh.tmp
	echo; echo; echo "[+] Added SOCKS proxy auto-start script to /etc/rc.local"
}

# Setup SOCKS proxy
function setupSOCKS {
	# Check for dependencies
	if ! which socat > /dev/null; then
		echo; echo "[!] The program socat is not installed...downloading now."
		apt-get -y install socat libreadline5
	fi
	echo "[-] Killing previous setips SSH SOCKS proxies."
	screen -X -S ssh kill > /dev/null
	echo; echo "[+] Starting up SOCKS proxy..."
	echo "[-] The startup process will take ~5 secs."
	echo "    You will be returned to the setips menu when setup is complete."
	echo; echo "[?] What port do you want to use for your proxy?"; read proxyport
	echo
	while :; do
		if netstat -antp |grep 0.0.0.0:$proxyport
		then
			echo; echo "[!] Something is already listening on that port, please try a different port."
			echo; echo "[?] What port do you want to use for your proxy?"; read proxyport
		else
			break
		fi
	done
	echo "[?] What is root's password?"; read -s password
	echo; echo "[-] Checking if the SSH server is running..."
	if ps aux | grep -v grep | grep /usr/sbin/sshd > /dev/null; then
		echo "[+] SSH server *is* running; let's rock."
	else
		echo "[!] SSH server *is not* running; starting it up."
		service ssh start
		echo; echo "[-] Checking if the SSH server is running after we attempted to start it up..."
		if ps aux | grep -v grep | grep /usr/sbin/sshd > /dev/null; then
			echo "[+] SSH server *is* running; let's rock."
		else
			echo "[!] SSH server *is not* running. #sadpanda"
			break
		fi
	fi

	if cat /etc/ssh/sshd_config | grep "without-password" | grep -v '"PermitRootLogin without-password"' > /dev/null; then
		echo; echo "[!] I have to fix your sshd_config file to allow login with password."
		fixSSHConfigRoot
	fi

	echo; echo "[+] Setting up the SSH SOCKS proxy...please wait..."
	sshPort=`netstat -antp | grep "sshd" | head -n 1 | cut -d":" -f2| cut -d" " -f1`
	while :; do
		(sleep 2; echo $password; sleep 2; echo ""; sleep 1) | socat - EXEC:"screen -S ssh ssh -o StrictHostKeyChecking=no -gD$proxyport -p $sshPort -l root localhost",pty,setsid,ctty > /dev/null
		echo "(sleep 2; echo $password; sleep 2; echo ""; sleep 1) | socat - EXEC:'screen -S ssh ssh -o StrictHostKeyChecking=no -p $sshPort -gD"$proxyport" -l root localhost',pty,setsid,ctty" > /tmp/ssh.tmp
		if netstat -antp | grep -v grep | grep $proxyport > /dev/null; then
			echo; echo "[+] SUCCESS...SOCKS proxy started on Port $proxyport."
			netstat -antp | grep $proxyport
			break
		else
			echo; echo "[!] FAIL...looks like the SOCKS proxy didn't start correctly; try these possible fixes:"
			echo '- Check your password and try running the script again.'
			echo '- Type "screen -r" from the command line to see if the screened session has any errors.  Once in screen, type "Ctrl-D" to get back to original command line.'
			echo
			exit 1
		fi
	done
	echo; echo "To use, copy the following to the end of your local /etc/proxychains.conf file (replace any other proxies in the file):"
	$ifconfig | grep -B1 "inet addr" |awk '{ if ( $1 == "inet" ) { print $2 } else if ( $2 == "Link" ) { printf "%s:" ,$1 } }' | sed 's/[addr]//g' | awk -F:: '{ print "socks4 " $NF }' | awk '{ print $0 "'" $proxyport"'"}' | head -n -1

	# Ask if you want to start the SOCKS proxy automatically on boot (careful, this will put your root password in the /etc/rc.local file)
        echo; read -p "[?] Would you like the SOCKS proxy to start on reboot? (y/n)" -n 1 -r
        if [[ $REPLY =~ ^[Yy]$ ]]; then
		autoStartSOCKSProxy
	else
		rm -rf /tmp/ssh.tmp;
	fi
	echo
}

# Stop SOCKS proxy
function stopSOCKS {
	screen -ls |grep ssh|cut -d"." -f1|cut -b2- > /tmp/socks.tmp
	while read p; do screen -X -S $p.ssh kill; done < /tmp/socks.tmp
	rm -f /tmp/socks.tmp
	sed -i '/screen/d' /etc/rc.local
}

# Flush all current IPTable rules
function flushIPTables {
	# Flushing all rules
	$iptables -F
	$iptables -X
	$iptables -F -t nat
	$iptables -X -t nat

	# Setting default filter policy
	$iptables -P INPUT ACCEPT
	$iptables -P OUTPUT ACCEPT
	$iptables -P FORWARD ACCEPT
}

# Add iptables script to /etc/rc.local
function autoStartIPTables {
		sed -i '/iptable*/d' /etc/rc.local
		sed -i '$e echo "#IPTables - Restore iptable rules on reboot"' /etc/rc.local
		sed -i '$e echo "iptables-restore < PATHTO"' /etc/rc.local
		awk 'BEGIN{OFS=FS=" "} $1~/iptables-restore/ {$3="'$setipsFolder'/iptables.current";}1' /etc/rc.local > /tmp/iptables.tmp; mv /tmp/iptables.tmp /etc/rc.local
}

# Remove iptables reinstall script from /etc/rc.local
function removeStartIPTables {
	sed -i '/iptable/d' /etc/rc.local
}

# Display the current IPTables list
function displayIPTables {
	if [[ -z `iptables-save` ]]; then
		echo; echo "[!] There are no IPTable rules."
	else
		echo; echo "[+] Displaying your current IPTables rules:"
		echo; iptables-save
	fi
}

# Setup IPTables SRC NAT Pivot
function setupIPTablesPivot {
	# Ask if you want to start the SOCKS proxy automatically on boot (careful, this will put your root password in the /etc/rc.local file)
	echo; read -p "[?] Would you like to flush the current iptable rules? (y/n)" -n 1 -r
	if [[ $REPLY =~ ^[Yy]$ ]]; then
		echo; read -p "[?] ARE YOU SURE? (y/n)" -n 1 -r
		if [[ $REPLY =~ ^[Yy]$ ]]; then
			flushIPTables
		fi
	fi
	echo; echo "[+] Let's set up some IPTables..."
	listIPs
	echo; echo '[?] Is the traffic "tcp" or "udp"?'; read prot
	echo; echo "[?] What subinterface IP should the pivot listen on?"; read subintip
	echo; echo "[?] What port should the pivot subinterface listen on?"; read incomingport
	echo; echo "[?] What is the redteam *IP* the pivot redirects incoming traffic to?"; read redteamip
	echo; echo "[?] What is the redteam *PORT* the pivot redirects incoming traffic to?"; read redteamport
	$iptables -t nat -A PREROUTING -p $prot -j DNAT -d $subintip --dport $incomingport --to $redteamip:$redteamport
	$iptables -t filter -I FORWARD 1 -j ACCEPT
	# Ask if you want to reapply the iptables rules automatically on boot (/etc/rc.local file)
	echo; read -e -p "[?] Would you like to apply these rules automatically on reboot? (y/n) " -r
	if [[ $REPLY =~ ^[Yy]$ ]]; then
		autoStartIPTables
	fi
	echo
}

# Setup Socat Pivot
function setupSocatPivot {
	# Check for dependencies
	if ! which socat > /dev/null; then
		echo; echo "[!] The program socat is not installed...downloading now."
		apt-get -y install socat
	fi
	echo; echo "[?] What port do you want to pivot (i.e. listen for)?"; read socatport
	echo; echo "[?] What is the redteam *IP* the pivot redirects incoming traffic to?"; read redteamip
	echo; echo "[?] What is the redteam *PORT* the pivot redirects incoming traffic to?"; read redteamport
	socat TCP-LISTEN:$socatport,reuseaddr,fork,su=nobody TCP:$redteamip:$redteamport&
	echo; echo "[+] Socat pivot setup."
	netstat -antp | grep $socatport
}

# Setup Cobaltstrike Teamserver
function setupTeamserver {
	# Check for dependencies
#	if ! which unzip > /dev/null; then
#		echo; echo "[!] The program unzip is not installed...downloading now."
#		apt-get -y install unzip
#	fi

	echo "[+] setips.sh needs to download some files from the Redteam network share."
	echo "[?] What is the password to the network share?"; read -s redteamSharePassword

	# Download Cobalt Strike
	if [ ! -d "$cobaltstrikeDir" ]; then
#		echo; echo "[!] Cobaltstrike folder does not exist...download/unzip to /root/cobaltstrike and try again."
		echo; echo "[!] Cobaltstrike folder does not exist; downloading..."
		wget -q --http-user=$redteamShareUser --http-password=$redteamSharePassword http://share.com/remote.php/webdav/scripts/cobaltstrike.tgz
		mkdir -p /redteam/toolkit/cobaltstrike > /dev/null
		tar xzf cobaltstrike.tgz -C /redteam/toolkit/; rm -f cobaltstrike.tgz
		echo "[+] Success!"
	else
		echo; echo "[+] Cobalstrike folder exists, moving on."
	fi
	cd /root
	# Download Cobalt Strike C2 Profiles
	if [ ! -d "$c2profilesDir" ]; then
		echo; echo "[?] Cobaltstrike c2profiles folder does not exist; downloading..."
		wget -q --http-user=$redteamShareUser --http-password=$redteamSharePassword http://share.com/remote.php/webdav/scripts/c2profiles.tgz
		tar xzf c2profiles.tgz -C /root/; rm -f c2profiles.tgz
		echo "[+] Success!"
#		echo; read -p "[?] Cobaltstrike c2profiles folder does not exist; download now? (y/n)" -n 1 -r
#		if [[ $REPLY =~ ^[Yy]$ ]]; then
#			echo; wget https://github.com/rsmudge/Malleable-C2-Profiles/archive/master.zip -O c2.zip; unzip c2.zip; mv Malleable-C2-Profiles-master c2profiles; rm -rf c2.zip
#		fi
	else
		echo; echo "[+] Cobalstrike c2profiles folder exists, moving on."
	fi
	# Ask if you will use a c2profile with the teamserver
	echo; read -e -p "[?] Would you like to use a c2profile (if you don't know what that is, type 'n')? (y/n) " -r
	if [[ $REPLY =~ ^[Yy]$ ]]; then
		c2profile=""
		cd /root/c2profiles; ls -R *; cd
		echo; echo "[!] What c2profile would you like to use? (enter just the name)"; read c2profile
		c2profile=`find /root/c2profiles/ -name $c2profile`
	fi
	# Download Veil
	if [ ! -d "$veilDir" ]; then
		echo; echo "[-] Veil is unavailable."
#		echo; read -p "[?] Veil folder does not exist; download now? (y/n)" -n 1 -r
#		if [[ $REPLY =~ ^[Yy]$ ]]; then
#			echo; wget https://github.com/Veil-Framework/Veil/archive/master.zip -O veil.zip; unzip veil.zip; mv Veil-master veil; rm -rf veil.zip; /root/veil/Install.sh -c
#		fi
	else
		echo; echo "[+] Veil folder exists, moving on."
	fi
	# Download PowerSploit
	if [ ! -d "$powersploitDir" ]; then
		echo; echo "[!] PowerSploit folder does not exist...downloading."
		cd /root/
		wget -q --http-user=$redteamShareUser --http-password=$redteamSharePassword http://share.com/remote.php/webdav/scripts/powersploit.tgz
		tar xzf powersploit.tgz; rm -f powersploit.tgz
		echo "[+] Success!"
#		echo; read -p "[?] PowerSploit folder does not exist; download now? (y/n)" -n 1 -r
#		if [[ $REPLY =~ ^[Yy]$ ]]; then
#		echo; wget https://github.com/mattifestation/PowerSploit/archive/master.zip -O powersploit.zip; unzip powersploit.zip; mv PowerSploit-master powersploit; rm -rf powersploit.zip
#		fi
	else
		echo; echo "[+] PowerSploit folder exists, moving on."
	fi
	# Startup teamserver
	coreip=`$ifconfig $ethInt |grep -B1 "inet addr" |awk '{ if ( $1 == "inet" ) { print $2 } else if ( $2 == "Link" ) { printf "%s:" ,$1 } }' | sed 's/[addr]//g' | awk -F:: '{ print $2 }' | head -n 1`
	echo; echo "[!] What teamserver password would you like to use?"; read teampass
	# Populate tables in background
	msfrpcdpid=`ps aux|grep msfrpcd|head -n 1|awk '{ print $2 }'`
	kill -9 $msfrpcdpid
	service postgresql start
	service metasploit start
	service metasploit stop
	echo "[-] If the teamserver fails to start, correct the issues and then type this command from the cobaltstrike folder:"
	echo "    ./teamserver $coreip $teampass $c2profile"
	cd $cobaltstrikeDir; ./teamserver $coreip $teampass $c2profile
}

# Loop function to redisplay menu
function whatToDo {
	echo; echo "[?] What would you like to do next?"
	echo "1)Setup  2)Subinterfaces  3)Utilities  4)Export  5)Quit"
}

# Clean old crap from iptables
function cleanIPTables {
	tmp=`mktemp`
	tmp2=`mktemp`
	tmpDNAT=`mktemp`
	# Clean duplicate items that are next to each other; remove old MASQUERADE method of "proxying"
	echo 1 > /proc/sys/net/ipv4/ip_forward
	iptables-save | uniq > $tmp; sed -i "/MASQUERADE/d" $tmp
	# Clean duplicate items NOT next to each other; save off DNAT list to tmp.snat then remove all DNAT entries for tmp iptables file
	cat $tmp | grep "DNAT" | sort -u > $tmpDNAT; sed -i "/DNAT/d" $tmp
	# Have to add "--packet 0" back into before restoring on certain version of iptables
	if [[ ! `grep "packet" $tmp` ]]; then 
		awk 'BEGIN{OFS=FS=" "} $4~/statistic/ {$9="--packet 0 -j";}1' $tmp > $tmp2; mv $tmp2 $tmp
	fi
	# Restore the cleaned rules
	iptables-restore < $tmp
	# Add back in the cleaned DNAT rules; order doesn't matter
	while read p; do $iptables -t nat $p; done < $tmpDNAT
	rm $tmp $tmpDNAT
	$iptables -t nat -A POSTROUTING -p tcp -j MASQUERADE
	$iptables -t nat -A POSTROUTING -p udp -j MASQUERADE
}

# Save IPTables for historical purposes
function saveIPTables {
	currentDateTime=`date +"%Y%b%d-%H%M"`
	iptablesBackupfile="iptables-$currentDateTime"
	iptables-save > $iptablesBackup/$iptablesBackupfile
	cp $iptablesBackup/$iptablesBackupfile $setipsFolder/iptables.current
	echo; echo "[+] Backup of iptables rules saved to $iptablesBackup/$iptablesBackupfile"
}

# Create IPTables to randomize source port when pivoting
function randomizePivotIP {
	tmp=/tmp/iptables.tmp
	iplist="./ips.list"
	# List subinterface ips randomly and put into file called "intips"
	ifconfig | grep -B1 "inet addr" |awk '{ if ( $1 == "inet" ) { print $2 } else if ( $2 == "Link" ) { printf "%s:" ,$1 } }' | sed 's/[addr]//g'| awk -F:: '{ print $NF }' | head -n -1 | awk '{printf "%s\n",$0} END {print ""}' | sed '/^$/d' | shuf > $iplist
	# Save off current iptables, delete all SNAT rules with the word "statistic", and restore the table
	iptables-save > $tmp; sed -i "/SNAT/d" $tmp; iptables-restore < $tmp; rm $tmp
	# Identify the number of assigned subinterfaces
	ipcount=`wc -l $iplist | cut -f 1 -d " "`
	while read p; do
		iptables -t nat -A POSTROUTING -m statistic --mode nth --every $ipcount --packet 0 -j SNAT --to-source $p
		ipcount=$(($ipcount-1))
	done <$iplist
	rm $iplist
	# Setup forward rule, if there isn't one
	$iptables -t filter -I FORWARD 1 -j ACCEPT
}

# Start fully interactive mode (default when no options given or by adding "-i")
function interactiveMode {
echo; echo "[!] Remember to remove your $ipsArchive file if you are starting a new exercise."; echo
select ar in "Setup" "Subinterfaces" "Utilities" "Export" "Quit"; do
	case $ar in
		Setup )
		echo
		select au in "SSH-SOCKS-Proxy" "IPTables-SRC-NAT-Pivot" "Socat-Pivot" "Teamserver" "Main-Menu"; do
			case $au in
				SSH-SOCKS-Proxy )
				listInts
				whatInterface
				listCoreIP
				checkForSubinterfaces
				autoSetIPsOnStart
				randomizePivotIP
				cleanIPTables
				saveIPTables
				setupSOCKS
				break
				;;

				IPTables-SRC-NAT-Pivot )
				listInts
				whatInterface
				checkForSubinterfaces
				autoSetIPsOnStart
				displayIPTables
				setupIPTablesPivot
				randomizePivotIP
				cleanIPTables
				saveIPTables
				break
				;;

				Socat-Pivot )
				setupSocatPivot
				break
				;;

				Teamserver )
				listInts
				whatInterface
				removeSubInts
				setupTeamserver
				break
				;;

				Main-Menu )
				break
				;;
			esac
		done
		whatToDo
		;;

		Subinterfaces )
		echo
		select su in "Add-Subinterfaces" "Remove-All-Subinterfaces" "Restore-Subinterfaces" "Main-Menu"; do
			case $su in
				Add-Subinterfaces )
				listInts
				whatInterface
				listCoreIP
				addSubInts
				randomizePivotIP
				autoSetIPsOnStart
				break
				;;

				Remove-All-Subinterfaces )
				listIPs
				whatInterface
				removeSubInts
				removeSetIPsOnStart
				break
				;;

				Restore-Subinterfaces )
				restoreSubIntsFile
				autoSetIPsOnStart
				echo "[+] Here are your current settings:";
				listIPs
				echo "[+] Your settings where restored.";
				break
				;;

				Main-Menu )
				break
				;;
			esac
		done
		whatToDo
		;;

		Utilities )
		echo
		select ut in "Initial-Setup" "Set-Gateway" "Set-DNS" "Fix-SSH-Without-Password" "Display-IPTables" "Flush-IPTables" "Auto-set-IPTables-on-startup" "Remove-auto-set-IPTables-on-startup" "Auto-set-IPs-on-startup" "Remove-auto-set-IPs-on-startup" "Startup-SOCKS-Proxy" "Stop-SOCKS-Proxy" "Main-Menu"; do
			case $ut in
				Initial-Setup )
				initialSetup
				break
				;;

				Set-Gateway )
				listIPs
				setGateway
				break
				;;

				Set-DNS )
				setDNS
				break
				;;

				Fix-SSH-Without-Password )
				fixSSHConfigRoot
				break
				;;

				Display-IPTables )
				displayIPTables
				break
				;;

				Flush-IPTables )
				flushIPTables
				echo; echo "[+] IPTables successfully flushed."
				break
				;;

				Auto-set-IPTables-on-startup )
				autoStartIPTables
  				echo; echo "[+] Added iptables restore script to /etc/rc.local."
				break
				;;

				Remove-auto-set-IPTables-on-startup )
				removeStartIPTables
  				echo; echo "[+] Removed iptables auto-set script."
				echo; read -p "[?] Would you like to flush the current iptable rules? (y/n)" -n 1 -r
				if [[ $REPLY =~ ^[Yy]$ ]]; then
					echo; read -p "[?] ARE YOU SURE? (y/n)" -n 1 -r
					if [[ $REPLY =~ ^[Yy]$ ]]; then
						flushIPTables
					fi
				fi
				break
				;;

				Auto-set-IPs-on-startup )
				setGateway
				autoSetIPsOnStart
  				echo; echo "[+] Added setips auto-set script to /etc/rc.local."
				break
				;;

				Remove-auto-set-IPs-on-startup )
				removeSetIPsOnStart
  				echo; echo "[+] Removed setips auto-set script."
				break
				;;

				Startup-SOCKS-Proxy )
				setupSOCKS
  				echo; echo "[+] SSH SOCKS Proxy started."
				break
				;;

				Stop-SOCKS-Proxy )
				stopSOCKS
  				echo; echo "[+] SSH SOCKS Proxy stopped."
				break
				;;

				Main-Menu )
				break
				;;
			esac
		done
		whatToDo
		;;

		Export )
		echo; echo "[?] What format do you want to export?"; echo
		select ex in "Cobaltstrike-Teamserver" "Proxychains" "List-IPs" "Main-Menu"; do
 			case $ex in
 				Cobaltstrike-Teamserver )
 				listIPs-oneline
				break
 				;;

				Proxychains )
				echo; echo "[?] What port do you want to use for your proxy?"; read proxyport
				echo; echo "Copy the following to the end of /etc/proxychains.conf"
				$ifconfig | grep -B1 "inet addr" |awk '{ if ( $1 == "inet" ) { print $2 } else if ( $2 == "Link" ) { printf "%s:" ,$1 } }' | sed 's/[addr]//g' | awk -F:: '{ print "socks4 " $NF }' | awk '{ print $0 "'" $proxyport"'"}' | head -n -1
				break
				;;

				List-IPs )
				listIPs
				break
				;;

				Main-Menu )
				break
				;;
			esac
		done
		whatToDo
		;;

		Quit )
		echo; echo "[+] Exiting, nothing to do."; echo
		exit 1
		;;
	esac
done
}

function printHelp {
	echo "Usage: [-h] [-i] [-l] [-r] [-s <protocol> <subintip> <subintport> <tgtIP> <tgtPort>]"
	echo "       [-f <fileName>] [-d <protocol> <subintip> <subintport> <tgtIP> <tgtPort>]"
	echo "       [-u] [-x <victim IP> <# of threads>] [-z]"
	echo; echo "Examples:"
	echo "./setips.sh -h"
	echo "Displays this help menu."
	echo; echo "./setips.sh -i"
	echo "Interactive mode."
	echo; echo "./setips.sh -l"
	echo "List current IPTables rules."
	echo; echo "./setips.sh -r"
	echo "Repair current IPTables ruleset by removing duplicates, removing rules that conflict with SNAT source IP manipulation, and saving a backup."
	echo; echo "./setips.sh -s <tcp or udp> <pivot-subinterface-IP> <pivot-subinterface-listen-port> <target-IP> <target-port>"
	echo "Add single IPTables rule - by default, it will append to the iptables file."
	echo; echo "./setips.sh -d <tcp or udp> <pivot-subinterface-IP> <pivot-subinterface-listen-port> <target-IP> <target-port>"
	echo "Delete single IPTables rule matching the input."
	echo; echo "./setips.sh -f <file of SRC-NAT entries>"
	echo "Add list of IPTables rules from file - Reads file and appends SRC-NAT rules to the iptables file."
	echo "File Format, one entry per line:  <tcp or udp> <pivot-subinterface-IP> <pivot-subinterface-listen-port> <target-IP> <target-port>"
	echo; echo "./setips -u"
	echo "Update setips.sh scripts with RELEASE version from the Redteam wiki."
	echo; echo "./setips -z"
	echo "Update setips.sh scripts with BETA version from the Redteam wiki."
	echo; echo "./setips.sh -x <target-IP> <#-of-threads>"
	echo "Inundator - Setup subinterfaces (if necessary), run inudator to blind snort sensors but send all the default snort rules across their sensors."
	echo
}

# MAIN MENU
echo; echo "Setips Script - Version $version"
# Check /etc/rc.local for the execute bit
chmod +x /etc/rc.local

if [[ $1 = "" || $1 = "--help" ]]; then
	printHelp >&2
	exit 1
else
	IAM=${0##*/} # Short basename
	while getopts ":d:f:hilrs:ux:z" opt
	do sc=0 #no option or 1 option arguments
		case $opt in
		(d) # DELETE - Quick delete iptables rule
			if [ $# -lt $((OPTIND + 1)) ]; then
				echo "$IAM: Option -d argument(s) missing...needs five!" >&2
				echo; printHelp >&2
				exit 2
			fi
			OPTINDplus1=$((OPTIND + 1))
			OPTINDplus2=$((OPTIND + 2))
			OPTINDplus3=$((OPTIND + 3))
			protocol=$OPTARG
			eval subintip=\$$OPTIND
			eval subintport=\$$OPTINDplus1
			eval tgtip=\$$OPTINDplus2
			eval tgtport=\$$OPTINDplus3
			$iptables -t nat -D PREROUTING -p $protocol -d $subintip --dport $subintport -j DNAT --to-destination $tgtip:$tgtport
			echo; echo "[+] Deleted rule specified."
			saveIPTables >&2
			echo
			sc=4 #5 args
			;;
		(f) # IMPORT - Import list of src nat entries from file
			#File format, one entry per line:  <tcp or udp> <pivot-subinterface-IP> <pivot-subinterface-listen-port> <target-IP> <target-port> 
			srcnatfile=$OPTARG
			sed -i '/^\x*$/d' $srcnatfile > /tmp/srcnatfile #Remove blank lines
			read -e -p "[?] Do you want to delete your current 1-to-1 NAT rules (y/n)? " -r
			while :; do
				if [[ $REPLY =~ ^[Yy]$ ]]; then
					iptables-save > iptables.tmp
					sed -i '/DNAT/d' iptables.tmp
					iptables-restore < iptables.tmp
					rm iptables.tmp
					break
				elif [[ $REPLY =~ ^[Nn]$ ]]; then
					break
				fi
			done
			while IFS=" " read protocol subintip subintport tgtip tgtport; do
				echo "$iptables -t nat -A PREROUTING -p $protocol -j DNAT -d $subintip --dport $subintport --to $tgtip:$tgtport"
				$iptables -t nat -A PREROUTING -p $protocol -j DNAT -d $subintip --dport $subintport --to $tgtip:$tgtport
			done <$srcnatfile
			echo; echo "[+] Imported rules from file:  $srcnatfile"
			cleanIPTables >&2
			saveIPTables >&2
			echo
			;;
		(h) # Print help/usage statement
			printHelp >&2
			exit 1
			;;
		(i) # Fully interactive mode
			interactiveMode >&2
			;;
		(l) # List current IPTables rules
			displayIPTables >&2
			;;
		(r) # REPAIR - quick repair; doesn't hurt if run multiple times.
			echo "[+] Cleaning up/repair the current IPTables ruleset."
			echo "[+] Saving backup of your IPTables before repair attempt to $iptablesBackup/$iptablesBackupfile"
			sed -i '/#setips - Auto-set IPs on startup/d' /etc/rc.local
			whatMTU
			echo; echo "[?] What is the CIDR of the subnet you are on (ie 16 for 255.255.0.0)? "; read subnet
			echo $subnet > $setipsFolder/subnet.current
			iptables-save > $iptablesBackup/$iptablesBackupfile
			cleanIPTables >&2
			autoStartIPTables >&2
			autoSetIPsOnStart >&2
			saveIPTables >&2
			echo "[+] Repair complete, saving IPTables backup...run './setips.sh -l' to view current IPTables."
			;;
		(s) # IMPORT - Quick entry to iptables src nat
			if [ $# -lt $((OPTIND + 1)) ]; then
				ec!ho "$IAM: Option -s argument(s) missing...needs five!" >&2
				echo; printHelp >&2
				exit 2
			fi
			OPTINDplus1=$((OPTIND + 1))
			OPTINDplus2=$((OPTIND + 2))
			OPTINDplus3=$((OPTIND + 3))
			protocol=$OPTARG
			eval subintip=\$$OPTIND
			eval subintport=\$$OPTINDplus1
			eval tgtip=\$$OPTINDplus2
			eval tgtport=\$$OPTINDplus3
			#Clean old masquerade way of doing SRC NAT
			$iptables -t nat -A PREROUTING -p $protocol -j DNAT -d $subintip --dport $subintport --to $tgtip:$tgtport
			$iptables -t filter -I FORWARD 1 -j ACCEPT
			randomizePivotIP >&2
			echo "[+] Imported rule specified."
			cleanIPTables >&2
			saveIPTables >&2
			echo
			sc=4 #5 args
			;;
		(u) # UPDATE - Update setips.sh to the latest release build.
			echo; echo "[?] To download the latest version, I need to know the password to the Redteam wiki?"; read -s redteamWikiPassword
			setipsDownloadLink="wget --http-user=$redteamWikiUser --http-password=$redteamWikiPassword $redteamWiki/$redteamPathToUpdateSetips -O $setipsUpdateFileDownloadLocation.tmp"
			$setipsDownloadLink >&2
			if [[ -s $setipsUpdateFileDownloadLocation.tmp ]]; then
				mv $setipsUpdateFileDownloadLocation $setipsFolder/setips.sh.last
				mv $setipsUpdateFileDownloadLocation.tmp $setipsUpdateFileDownloadLocation
				chmod +x $setipsUpdateFileDownloadLocation
				echo "[+] Success! Downloaded update to /root/setips.sh"
			else
				echo "[-] Fail! Check the password you entered in the following command, fix if necessary, confirm your download and run this script again:"
				echo "$setipsDownloadLink"
				echo
				exit 1
			fi
			;;
		(z) # UPDATE - Update setips.sh to the latest beta build.
			echo; echo "[?] To download the latest version, I need to know the password to the Redteam wiki?"; read -s redteamWikiPassword
			setipsDownloadLink="wget --http-user=$redteamWikiUser --http-password=$redteamWikiPassword $redteamWiki/$redteamPathToUpdateSetipsBeta -O $setipsUpdateFileDownloadLocation.tmp"
			$setipsDownloadLink >&2
			if [[ -s $setipsUpdateFileDownloadLocation.tmp ]]; then
				mv $setipsUpdateFileDownloadLocation $setipsFolder/setips.sh.last
				mv $setipsUpdateFileDownloadLocation.tmp $setipsUpdateFileDownloadLocation
				chmod +x $setipsUpdateFileDownloadLocation
				echo "[+] Success! Downloaded update to /root/setips.sh"
			else
				echo "[-] Fail! Check the password you entered in the following command, fix if necessary, confirm your download and run this script again:"
				echo "$setipsDownloadLink"
				echo
				exit 1
			fi
			;;
		(x) # INUNDATOR - Setup subinterfaces (if necessary), run inudator to replay snort rules that "inundates" snort sensors by sending all the default snort rules across their sensors
			# inundator 76.161.37.18 --verbose --thread 10 --proxy 37.75.5.41:1080 --rules /root/snort-rules/
			if [ $# -lt $((OPTIND)) ]; then
				echo "$IAM: Option -x argument(s) missing...needs 2!" >&2
				echo; printHelp >&2
				exit 2
			fi
			OPTINDplus1=$((OPTIND + 1))
			tgtIP=$OPTARG
			eval threads=\$$OPTIND
			# Start setup
			echo; echo "[!] You will need snort rules to run this script. If you want to download a copy, select 'n' to get them from the Redteam share"
			while :; do
				read -e -p "[?] Do you already have them downloaded already (y/n)? " -r
				if [[ $REPLY =~ ^[Nn]$ ]]; then
					echo; echo "[?] What is the password to the network share?"; read -s redteamSharePassword
					mkdir -p $snortRulesDirectory
					# Downloading snort rulesets
					snortRulesDownloadLink="wget --http-user=$redteamShareUser --http-password=$redteamSharePassword $redteamShare/$redteamPathToPullSnortRules -O $snortRulesFileDownloadLocation"
					$snortRulesDownloadLink >&2
					if [[ -s $snortRulesFileDownloadLocation ]]; then
						echo; echo "[+] Success! Downloaded rules to $snortRulesFileDownloadLocation"
					else
						echo; echo "[-] Fail! Check the password you entered in the following command, fix if necessary, confirm your download and run this script again:"
						echo "$snortRulesDownloadLink"
						exit 1
					fi
					break
				elif [[ $REPLY =~ ^[Yy]$ ]]; then
					echo; echo "[?] What is the path to your Snort rules *directory* (no trailing slash)? "; read snortRulesUserProvidedDirectory
					snortRulesDirectory="$snortRulesUserProvidedDirectory"
					break
				fi
			done
			echo; echo "[!] You need to use a proxy to increase your effects. Select 'n' to use a different server redirector IP:port"
			read -e -p "[?] Do you want to setup a proxy on your local box (y/n)? " -r
			while :; do
				if [[ $REPLY =~ ^[Yy]$ ]]; then
					listInts >&2
					whatInterface >&2
					checkForSubinterfaces >&2
					autoSetIPsOnStart >&2
					cleanIPTables >&2
					saveIPTables >&2
					while :; do
						echo; read -e -p "[?] Enter 9050 when asked for your port...enter 'y' to confirm that you understand (y/n) " -r
						if [[ $REPLY =~ ^[Yy]$ ]]; then
							echo
							setupSOCKS
							break
						elif [[ $REPLY =~ ^[Nn]$ ]]; then
							exit 1
						fi
						proxy="localhost:9050"
					done
					break
				elif [[ $REPLY =~ ^[Nn]$ ]]; then
					echo; echo "[?] What is the IP:Port of the external proxy (format as IP:Port)? "; read proxy
					break
				fi
			done
			echo; echo "[+] Command built, this is what I will execute:"
			echo "$inundator --thread $threads --proxy $proxy --rules $snortRulesDirectory --verbose $tgtIP"
			echo; echo "[-] If you receive errors, check your commands for the accuracy."
			echo; read -e -p "[?] Are you ready to execute? (y/n) " -r
			while :; do
				if [[ $REPLY =~ ^[Yy]$ ]]; then
					echo; read -e -p "[?] ARE YOU SURE? (y/n) " -r
					if [[ $REPLY =~ ^[Yy]$ ]]; then
						echo; $inundator --thread $threads --proxy $proxy --rules $snortRulesDirectory --verbose $tgtIP
					elif [[ $REPLY =~ ^[Nn]$ ]]; then
						exit 1
					fi
				elif [[ $REPLY =~ ^[Nn]$ ]]; then
					exit 1
				fi
			done
			exit 1		
			sc=1 #2 args
			;;
		(\?) #Invalid options
			echo "$IAM: Invalid option: -$OPTARG" >&2
			printHelp >&2
			exit 1
			;;
		(:) #Missing arguments
			echo "$IAM: Option -$OPTARG argument(s) missing." >&2
			printHelp >&2
			exit 1
			;;
		esac
		if [ $OPTIND != 1 ]; then #This test fails only if multiple options are stacked after a single "-"
			shift $((OPTIND - 1 + sc))
			OPTIND=1
		fi
	done
fi