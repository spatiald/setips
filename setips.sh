#!/bin/bash
#set -x
############################################################################
# Shellscript:  "setips.sh" Generates randoms ips for secondary interfaces
#  and automates the creation of proxy servers, pivots, web/ftp servers, and
#  other useful red team capabilities.
#
# Author : spatiald
############################################################################

scriptVersion=3.3a

# Check that we're root
if [[ $UID -ne 0 ]]; then
	echo "Superuser (i.e. root) privileges are required to run this script."
	exit 1
fi

# Print version only, if requested
if [[ $1 == "--version" ]]; then
	echo $scriptVersion
	exit 0
fi

# Setup setips folder (for saving setips scripts/backup files)
setipsFolder="$HOME/setips-files" # Main setips data folder
if [[ ! -d "$setipsFolder" ]]; then
	mkdir -p $setipsFolder > /dev/null 2>&1
fi

# Logging
exec &> >(tee "$setipsFolder/setips.log")

createConfig(){
	cat > $setipsConfig << 'EOF'
# Setips config file
# Add custom variables here and they will supercede the default ones

## NETWORK INFO
IP="" # Secondary addresses are listed in comma-separated format "192.168.1.1/24,192.168.1.2/24"
GATEWAY=""
MTU="1500" # Normal is 1500
NAMESERVERS="" # Comma-separated format "1.1.1.1,9.9.9.9"
networkManager="networkd"
ethInt=""

## OTHER
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
netplanConfig="/etc/netplan/setips-network.yaml"
defaultMTU="1500" # The default MTU (change only when needed)
setipsFolder="$HOME/setips-files" # Main setips data folder
setipsGitFolder="$HOME/setips" # Cloned Git repo for setips
internet="" # "0"=Offline, "1"=Online, ""=(ie Blank) Force ask
redteamGogs="" # Redteam wiki full web address
EOF
}

### Setup config file
setipsConfig="$setipsFolder/setips.conf"
if [[ ! -f $setipsConfig ]]; then
	createConfig
fi

if [[ ! `grep -v "#Setips config file" $setipsConfig` ]]; then
	createConfig
fi

### Import config file
setipsConfigClean="/tmp/setips.tmp"
# check if the file contains something we don't want
if egrep -q -v '^#|^[^ ]*=[^;]*' "$setipsConfig"; then
  echo "Config file is unclean, cleaning it..." >&2
  # filter the original to a new file
  egrep '^#|^[^ ]*=[^;&]*'  "$setipsConfig" > "$setipsConfigClean"
  mv $setipsConfigClean $setipsConfig
fi
# now source it, either the original or the filtered variant
source $setipsConfig

#stty sane # Fix backspace
trap cleanup EXIT # Cleanup if script exits for any reason

### DO NOT CHANGE the following
os="$(awk -F '=' '/^ID=/ {print $2}' /etc/os-release 2>&-)"
osIssue="$(cat /etc/issue|awk -F '\' '{ print $1 }')"
osVersion=$(awk -F '=' '/VERSION_ID=/ {print $2}' /etc/os-release 2>&-)
osFullVersion=$(awk -F '=' '/VERSION=/ {print $2}' /etc/os-release 2>&-)
currentDateTime=$(date +"%Y%b%d-%H%M")
# currentgw=$(route -n|grep eth0| head -n 1|cut -d"." -f4-7|cut -d" " -f10)
# ipsSaved="$setipsFolder/ips-saved.txt" # Save file for restoring IPs
ipsCurrent="$setipsFolder/ips.current"
ipsArchive="$setipsFolder/ips-archive.txt" # IP archive listed by date/time for reference during exercises
pivotRulesBackup="$setipsFolder/pivotRules"
iptablesBackup="$setipsFolder/iptables"
iptablesBackupFile="iptables-$currentDateTime"
subintsBackup="$setipsFolder/subints"
downloadError="0"
counter=0
fping=$(which fping)
ping=$(which ping)
iptables=$(which iptables)
socatDownload="apt -y install socat"

printGood(){
	echo -e "\x1B[01;32m[+]\x1B[0m $1"
}

printError(){
	echo -e "\x1B[01;31m[-]\x1B[0m $1"
}

printStatus(){
	echo -e "\x1B[01;35m[*]\x1B[0m $1"
}

printQuestion(){
	echo -e "\x1B[01;33m[?]\x1B[0m $1"
}

# Test function
testingScript(){
	$2
	exit 1
}

cleanup(){
	# Remove clear screen commands from log file <-- created by the Veil scripts
	sed -i '/=======/d' $setipsFolder/setips.log
	# kill $! # Kills the last run background process
	# trap 'kill $1' SIGTERM

	# stty sane
	# echo; exit $?
}

osCheck(){
	if [[ -z "$os" ]] || [[ -z "$osVersion" ]] || [[ -z "$osIssue" ]]; then
	  printError "Internal issue. Couldn't detect OS information."
	elif [[ "$os" == "kali" ]]; then
	  printGood "Kali Linux ${osVersion} $(uname -m) detected"
	elif [[ "$os" == "ubuntu" ]]; then
	  osVersion=$(awk -F '["=]' '/^VERSION_ID=/ {print $3}' /etc/os-release 2>&- | cut -d'.' -f1)
	  printGood "Ubuntu ${osFullVersion} $(uname -m) detected"
	elif [[ "$os" == "debian" ]]; then
	  printGood "Debian ${osVersion} $(uname -m) detected"
	else
	  printGood "$(echo $osIssue)"
	fi
}

opMode(){
	opModeOnline(){
		printGood "Script set for 'ONLINE' mode."
		internet="1"
		setOnline
		checkInternet
	}
	opModeOffline(){
		printGood "Script set for 'OFFLINE' mode."
		internet="0"
		setOffline
	}
	if [[ -z $internet ]]; then
#		printGood "Script set for 'ASK EVERY TIME' mode."
		echo; printQuestion "Do you want to run in ONLINE or OFFLINE mode?"
		select MODE in "ONLINE" "OFFLINE"; do
			case $MODE in
				ONLINE)
				opModeOnline
				break
				;;
				OFFLINE)
				opModeOffline
				break
				;;
			esac
			printGood "Done."
			break
		done
	elif [[ $internet == "0" ]]; then
		opModeOffline
	elif [[ $internet == "1" ]]; then
		opModeOnline
	fi
}

# Check internet connectivity
checkInternet(){
	echo; printStatus "Checking internet connectivity..."
	if [[ $internet == "1" || -z $internet ]]; then
		# Check internet connecivity
		WGET=`which wget`
		$WGET -q --tries=5 --timeout=5 --spider -U "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; AS; rv:11.0) like Gecko" http://ipchicken.com
		if [[ $? -eq 0 ]]; then
			printGood "Internet connection confirmed...continuing."
			internet=1
		else
			echo; printError "No internet connectivity; entering 'OFFLINE' mode."
			internet=0
		fi
	fi
}

# Capture a users Ctrl-C
ctrlC(){
	#stty sane
	echo; printError "Cancelled by user."
	echo; exit $?
}

# Check if command executed successfully...or not
commandStatus(){
	export EXITCODE="$?"
	if [[ $EXITCODE != 0 ]]; then
	printError "Command failed.  Exit code: $EXITCODE"
	export downloadError="1"
	else
	printGood "Command successful."
	fi
}

firstTime(){
	echo; printStatus "Running initial setup \"firstTime\" script"
	runningFirstTime=1
	# Set a root password, if needed
	echo; echo "[---------  ROOT PASSWORD  ---------]"
	echo; printStatus "We need to set a password on the root user. If you already have one set, please select 'N'"
	printQuestion "Do you want to set/change root's password? (Y/n)"; read REPLY
	if [[ $REPLY =~ ^[Nn]$ ]]; then
		printGood "We will NOT change the root password."
	else 
		passwd
	fi

	# Update netplan config to setips naming
	if [[ ! -f $netplanConfig ]]; then
		echo; echo "[---------  NETPLAN  ---------]"
		mkdir -p $setipsFolder/netplan.backups
		cd /etc/netplan
		for file in *.yaml*; do
			printStatus "Backing up all current network yaml scripts to $setipsFolder/netplan.backups folder."
			mv -nv -- "$file" "$setipsFolder/netplan.backups/$file.$(date +"%Y-%m-%d_%H-%M-%S")" > /dev/null 2>&1
		done
	fi

	# Change hostname [optional]
	setHostname

	# Identify ethernet interface
	echo; echo "[---------  ETHERNET INTERFACE  ---------]"
	whatInterface
	# ethInt="$(ip l show | grep ^2: | cut -f2 -d':' | sed 's/^ *//g')"

	# Disable/stop DNS stub resolver
	disableStubResolver

	# Setup static IP
	setupStaticIP

	echo; printGood "Initial setup \"firstTime\" script complete."
}

# Pull core interface info into variables
getInternetInfo(){
    local internetInfo=$( ip r | grep default )
    printf "%s" "$( echo $internetInfo | cut -f$1 -d' ' )"
}

# List IPs with interface assignments, one per line
listIPs(){
	echo; printStatus "Ethernet interfaces that have assigned addresses:"
	ip address show | grep "inet" | grep -v "inet6" | awk '{ print $2, $7, $8 }' | sed '/127.0/d'
}

# List only subinterface assignments, one per line
listSubIntIPs(){
	ip address show $ethInt | grep "inet" | grep -v "inet6" | awk '{ print $2, $7, $8 }' | sed '/127.0/d' | tail -n +2
}

# List IPs, one per line
listIPsOnly(){
	ip address show $ethInt | grep "inet" | grep -v "inet6" | awk '{ print $2 }' | cut -d/ -f1 | sed '/127.0/d'
}

# List IPs, single line, comma-seperated for use in Armitage/Cobalt Strike "Teamserver"
listIPs-oneline(){
	listIPsOnly | awk '{printf "%s,",$0} END {print ""}' | sed 's/.$//'
}

# List subinterface IPs, one per line
listSubIntIPsOnly(){
	ip address show $ethInt | grep "inet" | grep -v "inet6" | awk '{ print $2 }' | sed '/127.0/d' | tail -n +2 | cut -d/ -f1 | awk '{printf "%s\n",$0} END {print ""}' | sed '/^$/d'
}

# List interfaces available
listInts(){
	ip address show | grep "mtu" | awk '{ print $2 }' | sed "s/://g" | sed "/lo/d"
}

# List subints, one per line
listSubInts(){
	ip address show | grep secondary | awk '{ print $2 }'
}

# Find the core IP address in use
listCoreInterfaces(){
	echo; printStatus "Core IP addresses on this system:"
	ip address show | grep "inet" | grep -v "inet6" | grep -v "secondary" | awk '{ print $2, $7 }' | sed '/127.0/d'
}

listCoreIP(){
	ip address show | grep "inet" | grep -v "inet6" | awk '{ print $2 }' | sed '/127.0/d' | head -n 1
}

# Ask which ethernet port you want to create subinterfaces for
whatInterface(){
	#stty sane
#	ints=$(ip address show | grep "inet" | grep -v "inet6" | grep -v "secondary" | awk '{ print $2, $7 }' | grep -v "127.0.0.1/8" | awk '{ print $2 }')
	listCoreInterfaces
	ints=$(ip address show | grep state | grep -v LOOPBACK | awk '{ print $2 }' | cut -d: -f1)
	echo; printQuestion "What ethernet interface?"
	select int in $ints; do
		export ethInt=$int
		sed -i "/^ethInt=/c\ethInt=\"$int\"" $setipsConfig
		break
	done
	exec &> >(tee -a "$setipsFolder/setips.log")
}

# List IPs, single line, comma-seperated
listIPs-oneline(){
	# List IPs for use in Armitage/Cobalt Strike "Teamserver"
	ip address show $ethInt |grep "inet" |grep -v "inet6"|awk '{ print $2 }'|cut -d/ -f1| awk '{printf "%s,",$0} END {print ""}' | sed 's/.$//'
}

# Tests IP for connectivity
pingTest(){
	# Check for ping response (test 1)
	if [[ `which fping` ]]; then
		$fping -qc1 $unusedIP && (echo $unusedIP >> $tmpUsedIPs; return 1) || availIP=$unusedIP
	else
		$ping -qc1 $unusedIP && (echo $unusedIP >> $tmpUsedIPs; return 1) || availIP=$unusedIP
	fi
	# Check if in the running used IP list (test 2)
	if [[ $(cat $tmpUsedIPs | grep $availIP) ]]; then
		return 1
	else
		echo $availIP >> $tmpUsedIPs
		echo $availIP >> $tmpIPs
	fi
}

# Calculate # of IPs within the range requested
howManyIPs(){
	if [[ $class="A" ]]; then
		numOct2=$(echo $(( $(echo $octet2 | cut -d- -f2) - $(echo $octet2 | cut -d- -f1) + 1 )))
		numOct3=$(echo $(( $(echo $octet3 | cut -d- -f2) - $(echo $octet3 | cut -d- -f1) + 1 )))
		numOct4=$(echo $(( $(echo $octet4 | cut -d- -f2) - $(echo $octet4 | cut -d- -f1) + 1 )))
		numPossIPs=$(($numOct2 * $numOct3 * $numOct4))
	elif [[ $class="B" ]]; then
		numOct3=$(echo $(( $(echo $octet3 | cut -d- -f2) - $(echo $octet3 | cut -d- -f1) + 1 )))
		numOct4=$(echo $(( $(echo $octet4 | cut -d- -f2) - $(echo $octet4 | cut -d- -f1) + 1 )))
		numPossIPs=$(($numOct3 * $numOct4))
	elif [[ $class="C" ]]; then
		numOct4=$(echo $(( $(echo $octet4 | cut -d- -f2) - $(echo $octet4 | cut -d- -f1) + 1 )))
		numPossIPs=$numOct4
	fi
}

# Remove all secondary addresses
removeSubInts(){
	tmp=`mktemp`
	rm -f $tmp
	sed -i -e "0,/\[\([^]]*\)\]/s|\[\([^]]*\)\]|[$(listCoreIP)]|" $netplanConfig
	netplan generate; netplan apply
	echo; printStatus "Removed all secondary addresses."
}

octet1NumCheck(){
	while true; do
		if [[ ! $octet1 =~ ^([01]?[0-9]?[0-9]|2[0-4][0-9]|25[0-5])$ ]]; then
			printError "You didn't specify a valid number."
			echo; printQuestion "What is the IP's first octet (number; ie 1-255)?"; read octet1
		else
			break
		fi
	done
}
octet2NumCheck(){
	while true; do
		if [[ ! $octet2 =~ ^([01]?[0-9]?[0-9]|2[0-4][0-9]|25[0-5])$ ]]; then
			printError "You didn't specify a valid number."
			echo; printQuestion "What is the IP's second octet (number; ie 1-255)?"; read octet2
		else
			break
		fi
	done
}
octet3NumCheck(){
	while true; do
		if [[ ! $octet3 =~ ^([01]?[0-9]?[0-9]|2[0-4][0-9]|25[0-5])$ ]]; then
			printError "You didn't specify a valid number."
			echo; printQuestion "What is the IP's third octet (number; ie 1-255)?"; read octet3
		else
			break
		fi
	done
}
octet2RangeCheck(){
	while true; do
		if [[ ! $octet2 =~ ^([01]?[0-9]?[0-9]|2[0-4][0-9]|25[0-5])\-([01]?[0-9]?[0-9]|2[0-4][0-9]|25[0-5])$ ]] || [[ ! $(echo $octet2 | cut -d"-" -f1) -le $(echo $octet2 | cut -d"-" -f2) ]]; then
			printError "You didn't specify a valid range."
			echo; printQuestion "What is the IP's second octet (range; ie 1-255)?"; read octet2
		else
			break
		fi
	done
}
octet3RangeCheck(){
	while true; do
		if [[ ! $octet3 =~ ^([01]?[0-9]?[0-9]|2[0-4][0-9]|25[0-5])\-([01]?[0-9]?[0-9]|2[0-4][0-9]|25[0-5])$ ]] || [[ ! $(echo $octet3 | cut -d"-" -f1) -le $(echo $octet3 | cut -d"-" -f2) ]]; then
			printError "You didn't specify a valid range."
			echo; printQuestion "What is the IP's third octet (range; ie 1-255)?"; read octet3
		else
			break
		fi
	done
}
octet4RangeCheck(){
	while true; do
		if [[ ! $octet4 =~ ^([01]?[0-9]?[0-9]|2[0-4][0-9]|25[0-5])\-([01]?[0-9]?[0-9]|2[0-4][0-9]|25[0-5])$ ]] || [[ ! $(echo $octet4 | cut -d"-" -f1) -le $(echo $octet4 | cut -d"-" -f2) ]]; then
			printError "You didn't specify a valid range."
			echo; printQuestion "What is the IP's fourth octet (range; ie 1-255)?"; read octet4
		else
			break
		fi
	done
}
# Add subinterfaces
addSubInts(){
	tmpIPs=`mktemp`
	tmp2IPs=`mktemp`
	tmpUsedIPs=`mktemp`

	# SUBNET
	echo; printQuestion "What subnet class are you creating IPs for?"
	select class in "A" "B" "C"; do
		case $class in
		A)
		class="A"
		# Find out the range that we are setting
		echo; printQuestion "What is the IP's first octet (number)?"; read octet1
		octet1NumCheck
		printQuestion "What is the IP's second octet (range; ie 1-255)?"; read octet2
		octet2RangeCheck
		printQuestion "What is the IP's third octet (range; ie 1-255)?"; read octet3
		octet3RangeCheck
		printQuestion "What is the IP's fourth octet (range; ie 1-255)?"; read octet4
		octet4RangeCheck

		# Calculate # of IPs within the range requested
		howManyIPs

		# Ask how many subinterface ips the user would like
		echo; printQuestion "How many virtual ips (subinterfaces) would you like?"; read numberIPs
		until [[ $numberIPs = $(wc -l < $tmpIPs) ]]; do
			if [[ $(wc -l < $tmpUsedIPs) == $numPossIPs ]]; then echo; printError "Maximum number of possible IPs reached; you need to expand your IP pool."; return 1; fi
			unusedIP=$octet1"."$(shuf -i $octet2 -n 1)"."$(shuf -i $octet3 -n 1)"."$(shuf -i $octet4 -n 1)
			if [[ ! $(cat $tmpUsedIPs | grep $unusedIP) ]]; then pingTest; fi
		done
		sort -u $tmpIPs > $tmp2IPs; mv $tmp2IPs $tmpIPs
		echo; printGood "Identified $numberIPs available IPs; setting subinterface IPs!"
		break
		;;

		B)
		class="B"
		# Find out the range that we are setting
		echo; printQuestion "What is the IP's first octet (number)?"; read octet1
		octet1NumCheck
		printQuestion "What is the IP's second octet (number)?"; read octet2
		octet2NumCheck
		printQuestion "What is the IP's third octet (range; ie 1-255)?"; read octet3
		octet3RangeCheck
		printQuestion "What is the IP's fourth octet (range; ie 1-255)?"; read octet4
		octet4RangeCheck

		# Calculate # of IPs within the range requested
		howManyIPs

		#Ask how many subinterface ips the user would like
		echo; printQuestion "How many virtual ips (subinterfaces) would you like?"; read numberIPs
		until [[ $numberIPs == $(wc -l < $tmpIPs) ]]; do
			if [[ $(wc -l < $tmpUsedIPs) == $numPossIPs ]]; then echo; printError "Maximum number of possible IPs reached; you need to expand your IP pool."; return 1; fi
			unusedIP=$octet1"."$octet2"."$(shuf -i $octet3 -n 1)"."$(shuf -i $octet4 -n 1)
			if [[ ! $(cat $tmpUsedIPs | grep $unusedIP) ]]; then pingTest; fi
		done
		sort -u $tmpIPs > $tmp2IPs; mv $tmp2IPs $tmpIPs
		echo; printGood "Identified $numberIPs available IPs; setting subinterface IPs!"
		break
		;;

		C)
		class="C"
		# Find out the range that we are setting
		echo; printQuestion "What is the IP's first octet (number)?"; read octet1
		octet1NumCheck
		printQuestion "What is the IP's second octet (number)?"; read octet2
		octet2NumCheck
		printQuestion "What is the IP's third octet (number)?"; read octet3
		octet3NumCheck
		printQuestion "What is the IP's fourth octet (range; ie 1-255)?"; read octet4
		octet4RangeCheck

		# Calculate # of IPs within the range requested
		howManyIPs

		#Ask how many subinterface ips the user would like
		echo; printQuestion "How many virtual ips (subinterfaces) would you like?"; read numberIPs
		until [[ $numberIPs == $(wc -l < $tmpIPs) ]]; do
			if [[ $(wc -l < $tmpUsedIPs) == $numPossIPs ]]; then echo; printError "Maximum number of possible IPs reached; you need to expand your IP pool."; return 1; fi
			unusedIP=$octet1"."$octet2"."$octet3"."$(shuf -i $octet4 -n 1)
			if [[ ! $(cat $tmpUsedIPs | grep $unusedIP) ]]; then pingTest; fi
		done
		sort -u $tmpIPs > $tmp2IPs; mv $tmp2IPs $tmpIPs
		echo; printGood "Identified $numberIPs available IPs; setting subinterface IPs!"
		break
		;;
		esac
	done

	# Pull current ips, replace ',' with new line
	cat $netplanConfig | grep "/" | cut -d "[" -f2 | cut -d "]" -f1 | sed "s/\,/\n/g" > $tmpUsedIPs

	# Identify the CIDR and append to each of the new IPs
	CIDR=$(listCoreIP | sed -n 's/.*\///p')
	for ip in $(cat $tmpIPs); do echo $ip/$CIDR >> $tmpUsedIPs; done

	# Append new ips to current ips, unique w/out sorting, and then replace new lines with ','
	cat $tmpUsedIPs | awk '!x[$0]++' | sed ':a; N; $!ba; s/\n/,/g' > $tmpIPs

	# Add clean addresses to netplan
	sed -i '0,/addresses/s|addresses:.*|addresses: ['$(cat $tmpIPs)']|' $netplanConfig

	netplan generate; netplan apply
	printGood "Done."; echo

	# Append ips to running log
	echo -e "\n$(date)" >> $ipsArchive
	cat $tmpIPs >> $ipsArchive
	cat $tmpIPs > $ipsCurrent

	printGood "Your IP settings were saved to two files:";
	echo "   - $ipsCurrent -> current IPs assigned to server and listed in $netplanConfig";
	echo "   - $ipsArchive -> running log of all IPs used during an exercise/event";
}

# Check for subinterfaces
checkForSubinterfaces(){
	tmp=`mktemp`
	listSubInts >> $tmp
	if [[ ! -s $tmp ]]; then
		echo; printQuestion "No subinterfaces exist...would you like to create some? (y/N) "; read REPLY
		if [[ $REPLY =~ ^[Yy]$ ]]; then
			addSubInts
		fi
	else
		echo; printStatus "Current subinterfaces:"
		listSubIntIPs
		echo; printQuestion "Do you want to change your current subinterface IPs? (y/N) "; read REPLY
		if [[ $REPLY =~ ^[Yy]$ ]]; then
			removeSubInts
			addSubInts
		fi
	fi
}

# Restore subinterface IPs from file
restoreSubIntsFile(){
	# Identify the subinterfaces save file
	echo; printStatus "The subinterface file should be a one-line, comma-seperated list of IP/CIDR; for example, '192.168.1.1/24,192.168.1.55/24'"
	echo; printQuestion "What is the full path to the setips save file (default is $ipsCurrent)?"; read savefile || return
	if [[ -z ${savefile:+x} ]]; then
		printGood "Restoring from $ipsCurrent"
		savefile=$ipsCurrent
	else
		printGood "Restoring from $savefile"
	fi

	# Add clean addresses to netplan
	sed -i '0,/addresses/s|addresses:.*|addresses: ['$(cat $savefile)']|' $netplanConfig
}

# Change hostname [optional]
setHostname(){
	echo; echo "[---------  HOSTNAME  ---------]"
	echo; hostnamectl
	echo; printQuestion "Do you want to change the hostname of this server? (Y/n)"; read REPLY
	if [[ $REPLY =~ ^[Nn]$ ]]; then
		printGood "Hostname NOT changed."
	else 
		printQuestion "What name would you like to set for this server?"; read REPLY
		hostnamectl set-hostname $REPLY
		sed -i '0,/127\.0\.1\.1/s|127\.0\.1\.1.*|127\.0\.1\.1 '$(echo $REPLY)'|' /etc/hosts
		printGood "Hostname changed to \"$REPLY\" - reboot to see changes."
	fi
}

# Set IP
setIP(){
	echo; echo "[---------  IP  ---------]"
	echo; REGEX='(((25[0-5]|2[0-4][0-9]|1?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|1?[0-9][0-9]?))(\/([8-9]|[1-2][0-9]|3[0-2]))([^0-9.]|$)'
	IP=$(ip a | grep inet | grep $ethInt | grep -v inet6 | grep -v 127.0.0.1 | grep -v secondary | cut -f6 -d' ')
	staticIPLoop(){
		until [[ $valid_ip == 1 ]]
		do
			valid_ip=0
			printQuestion "What would you like to set as your primary static IP/CIDR (i.e. 192.168.1.1/24)? "; read IP
			if [[ "$IP" =~ $REGEX ]]; then
			        printGood "Valid IP: $IP"
			        valid_ip=1
			else
			        printError "You didn't provide a valid IP: $IP"
			        echo "Please provide your IP/CIDR in this format example - 192.168.1.1/24"
			fi
		done
	}
	printStatus "Configuring a static IP on the server."
	if [[ -z $IP ]]; then
		staticIPLoop
	else
		echo "The current IP on this server is:  $IP"
		printQuestion "Would you like to set the current IP as the primary static IP on the server? (Y/n)"; read REPLY
		if [[ $REPLY =~ ^[Nn]$ ]]; then
			staticIPLoop
		fi
	fi
	sed -i "/^IP=/c\IP=\"$IP\"" $setipsConfig
	sed -i "0,/addresses:/{s|addresses:.*|addresses: [$IP]|;}" $netplanConfig
}

# Set default gateway
setGateway(){
	echo; echo "[---------  GATEWAY  ---------]"
	echo; printStatus "Current route table:"
	ip route; echo
	currentgw="$( getInternetInfo 3 )"
	if [[ -z ${currentgw:+x} ]]; then
		printError "You do not have a default gateway set."
	else
		echo "Your primary gateway is:  $currentgw"
	fi
	printQuestion "Do you want to update your gateway? (y/N) "; read REPLY
	if [[ $REPLY =~ ^[Yy]$ ]]; then
		printQuestion "What is the IP of the gateway?"; read currentgw
		printGood "Your gateway was updated to:  $currentgw"
	else
		printError "Gateway not changed."
	fi
	sed -i "/^GATEWAY=/c\GATEWAY=\"$currentgw\"" $setipsConfig
	sed -i "s|via:.*|via: $currentgw|;" $netplanConfig
}

# Set DNS
setDNS(){
	echo; echo "[---------  DNS  ---------]"
	# if [[ $(systemctl status systemd-resolved.service | grep dead ) ]]; then printStatus "Enabling DNS stub resolver temporarily."; systemctl enable systemd-resolved.service > /dev/null; fi
	# dnsips=$(systemd-resolve --status | sed -n '/DNS Servers/,/^$/p' | grep -oE "\b([0-9]{1,3}\.){3}[0-9]{1,3}\b" | sort -u | sed ':a; N; $!ba; s/\n/,/g')
	echo; dnsips=$(cat /etc/resolv.conf | grep nameserver | cut -d " " -f2 | awk '{printf "%s,",$0} END {print ""}' | sed 's/.$//')
	printStatus "Your current DNS server(s):  $dnsips"
	printQuestion "Do you want to change your DNS servers? (y/N) "; read REPLY
	if [[ $REPLY =~ ^[Yy]$ ]]; then
		printQuestion "What are the DNS server IPs (comma separated)?"; read dnsips
		printGood "Your DNS settings were updated."
	else
		printError "DNS not changed."
	fi
	echo "# This file was automagically created by the setips script." > /etc/resolv.conf
	for i in ${dnsips//,/ }
	do
		echo "nameserver $i" >> /etc/resolv.conf
	done
	sed -i "/^NAMESERVERS=/c\NAMESERVERS=\"$dnsips\"" $setipsConfig
	sed -i '/.*nameservers:/!b;n;c\                addresses: ['$dnsips']' $netplanConfig
}

# Set MTU
setMTU(){
	echo; echo "[---------  MTU  ---------]"
	echo; if [[ ! $ethInt ]]; then
		whatInterface
	elif [[ -z $runningFirstTime ]]; then
		echo; printQuestion "Do you change the interface? (y/N)"; read REPLY
		if [[ $REPLY =~ ^[Yy]$ ]]; then
			echo; printStatus "Changing the interface."
			whatInterface
		fi
	else
		printStatus "Interface:  $ethInt"
	fi

	currentMTU="$( ip a | grep $ethInt | grep mtu | grep -v lo | awk '{for(i=1;i<=NF;i++)if($i=="mtu")print $(i+1)}' )"
	printStatus "Current MTU:  $currentMTU"
	printQuestion "Do you want to change your MTU (normally 1500)? (y/N)"; read REPLY
	if [[ $REPLY =~ ^[Yy]$ ]]; then
		printQuestion "What is your desired MTU setting (default is normally 1500)?"; read MTU
		if [[ -z ${MTU:+x} ]]; then MTU=1500; fi
		printGood "Setting MTU of $MTU."
	else
		MTU=$currentMTU
		printError "MTU not changed."
	fi
	sed -i -e "/^MTU=/c\MTU=$MTU" $setipsConfig
	sed -i -r -e 's/(mtu:)\s+\w+/\1 '$MTU'/i' $netplanConfig
}

# Disable/stop DNS stub resolver
disableStubResolver(){
	echo; echo "[---------  CONFIGURE DNS STUB RESOLVER  ---------]"
	echo; printStatus "Disabling the local DNS stub resolver"
	systemctl disable systemd-resolved.service
	systemctl stop systemd-resolved
 	rm /etc/resolv.conf
}

# Change /etc/ssh/sshd_config conifguration for root to only login "without-password" to "yes"
checkSSH(){
	if cat /etc/ssh/sshd_config | grep '#PermitRootLogin' >/dev/null; then
		echo; printError "I have to fix your sshd_config file to allow login with password."
		sed -i 's/.*\#PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config
		echo; printStatus "Checking SSH service is enabled and accepts passwords."
		systemctl restart ssh
		systemctl enable ssh
		printGood "Root login permitted."
	fi
}

# Create systemd unit file for starting SOCKS proxy
autoStartSOCKSProxy(){
	# rc.local delete
	# sed -i '/screen/d' /etc/rc.local
	# sed -i '$e echo "#SOCKS - Auto-start SOCKS proxy on startup using screen"' /etc/rc.local
	# sed -i '$e cat /tmp/ssh.tmp' /etc/rc.local
	# rm -f /tmp/ssh.tmp
	cat > /etc/systemd/system/autostart_socks.service << EOF
[Unit]
Description="Auto-start SOCKS proxy on startup using screen"
After=network.target

[Service]
ExecStart=$autostartSOCKS

[Install]
WantedBy=multi-user.target
EOF
	systemctl enable autostart_socks.service
	echo; printGood "Created systemd unit file for starting SOCKS proxy."
}

createStaticYAML() {
    defaultYAML() {
		local YAML="---\n"
		YAML+="network:\n"
		YAML+="    version: 2\n"
		YAML+="    renderer: $networkManager\n"
		YAML+="    ethernets:\n"
		YAML+="        $ethInt:\n"
		YAML+="            dhcp4: false\n"
		YAML+="            addresses: [$IP]\n"
		YAML+="            routes:\n"
        YAML+="                - to: default\n"
        YAML+="                  via: $GATEWAY\n"
		YAML+="            mtu: $MTU\n"
		YAML+="            nameservers:\n"
		YAML+="                addresses: [$NAMESERVERS]"
		printf "%s" "$YAML"
	}
	# Clear configs
	[ -f $netplanConfig ] && sudo rm $netplanConfig
	# Create default YAML
	sudo echo -e "$(defaultYAML)" > $netplanConfig
	# Ensure YAML is not viewable by others
	chmod 600 $netplanConfig
}

setupStaticIP(){
	createStaticYAML
	setIP
	setGateway
	setDNS
	setMTU
	netplan generate; netplan apply
	echo; printStatus "NOTE: You can ignore warnings about the ovsdb-server.service not running."
}

# Display SOCKS proxies
displayProxies(){
	ip address show $ethInt |grep "inet" |grep -v "inet6"|awk '{ print $2 }'|cut -d/ -f1 |  grep -v "127.0.0.1" | tail -n +2 | awk '{printf "%s\n",$0} END {print ""}' | sed '/^$/d' | awk -F:: '{ print "socks4 " $NF }' | awk '{ print $0 "'" $proxyport"'"}'
}

# Setup SOCKS proxy
setupSOCKS(){
	# Check for dependencies
	if ! which socat > /dev/null; then
		echo; printError "The SOCKS proxy requires 'socat' it and will not be setup, exiting."
		echo; printStatus "If online, you can install using the Install Redirector Tools option in the Utilities menu."
		break
	fi
	if ss -ltpn | grep -v grep | grep 0.0.0.0 | grep -v sshd | grep ssh > /dev/null; then
		echo; printStatus "You currently have proxies running on the following ports:"
		ss -ltpn | grep -v grep | grep 0.0.0.0 | grep -v sshd | grep ssh
		echo; printQuestion "Do you want to remove them? (y/N)"; read REPLY
		if [[ $REPLY =~ ^[Yy]$ ]]; then
			echo; printStatus "Killing previous setips SSH SOCKS proxies."
			stopSOCKS
		else
			printStatus "Keeping existing proxies and continuing."
		fi
	fi
	echo; printGood "Starting up SOCKS proxy..."
	printStatus "The startup process will take ~5 secs."
	echo "	You will be returned to the setips menu when setup is complete."
	echo; printQuestion "What *PORT* do you want to use for your proxy?"; read proxyport
	while :; do
		if ss -ltpn | grep "0.0.0.0:$proxyport "; then
			echo; printError "Something is already listening on that port, please try a different port."
			echo; ss -ltpn | grep ":$proxyport "
			echo; printQuestion "What *PORT* do you want to use for your proxy?"; read proxyport
		else
			break
		fi
	done
	echo; printQuestion "What is root's key passphrase (or password if keys are not used)?"; read -s password
	echo; printStatus "Checking if the SSH server is running..."
	if ps aux | grep -v grep | grep /usr/sbin/sshd > /dev/null; then
		printGood "SSH server *is* running; let's rock."
	else
		printError "SSH server *is not* running; starting it up."
		service ssh start
		sleep 2
		echo; printStatus "Checking if the SSH server is running after we attempted to start it up..."
		if ps aux | grep -v grep | grep /usr/sbin/sshd > /dev/null; then
			printGood "SSH server *is* running; let's rock."
		else
			printError "SSH server *is not* running. #sadpanda"
			break
		fi
	fi

	checkSSH

	echo; printStatus "Setting up the SSH SOCKS proxy...please wait..."
	sshPort=`ss -ltpn | grep "sshd" | head -n 1 | cut -d":" -f2| cut -d" " -f1`
	while :; do
		(sleep 2; echo $password; sleep 2; echo ""; sleep 1) | socat - EXEC:"screen -S ssh ssh -o StrictHostKeyChecking=no -gD$proxyport -p $sshPort -l root localhost",pty,setsid,ctty > /dev/null
		export autostartSOCKS="(sleep 2; echo $password; sleep 2; echo \"\"; sleep 1) | socat - EXEC:'screen -S ssh ssh -o StrictHostKeyChecking=no -p $sshPort -gD\"$proxyport\" -l root localhost',pty,setsid,ctty"
		if ss -ltpn | grep -v grep | grep $proxyport > /dev/null; then
			echo; printGood "SUCCESS...SOCKS proxy started on Port $proxyport."
			echo $proxyport >> $setipsFolder/proxies.current
			ss -ltpn | grep $proxyport
			break
		else
			echo; printError "FAIL...looks like the SOCKS proxy didn't start correctly; try these possible fixes:"
			echo '- Check your password and try running the script again.'
			echo '- Type "screen -r" from the command line to see if the screened session has any errors.  Once in screen, type "Ctrl-D" to get back to original command line.'
			echo
			exit 1
		fi
	done
	echo; echo "To use, copy the following to the end of your local /etc/proxychains.conf file (replace any other proxies in the file):"
	displayProxies

	# Ask if you want to start the SOCKS proxy automatically on boot (careful, this will put your root password in a systemd unit file)
	echo; printQuestion "Would you like the SOCKS proxy to start on reboot? (y/N)"; read REPLY
	if [[ $REPLY =~ ^[Yy]$ ]]; then
		autoStartSOCKSProxy
	fi
}

# Stop SOCKS proxy
stopSOCKS(){
	screen -ls |grep ssh|cut -d"." -f1|cut -b2- > /tmp/socks.tmp
	while read p; do screen -X -S $p.ssh kill; done < /tmp/socks.tmp
	rm -f /tmp/socks.tmp
	systemctl disable autostart_socks.service
	rm -f $setipsFolder/proxies.current
}

# Flush all current IPTable rules
flushIPTables(){
	tmp=`mktemp`
	# Flushing all rules
	$iptables -F
	$iptables -X
	$iptables -F -t nat
	$iptables -X -t nat

	# Setting default filter policy
	$iptables -P INPUT ACCEPT
	$iptables -P OUTPUT ACCEPT
	$iptables -P FORWARD ACCEPT

	# Remove MASQUERADE rules
	iptables-save > $tmp; sed -i '/-o '$ethInt' -j MASQUERADE/ {d;}' $tmp; iptables-restore < $tmp; rm $tmp
}

cleanIPPivots(){
	tmp=`mktemp`
	iptables-save | uniq > $tmp; sed -i '/--to-destination/ {d;}' $tmp; sed -i '/--to-source/ {d;}' $tmp
	iptables-restore < $tmp; rm $tmp
}

iptablesToggleRandomSource(){
	tmp=`mktemp`
	# Check if current iptables is set to random source address
	if [[ $2 == "OFF" || $(iptables-save | grep "SNAT") ]]; then 
		# Save off current iptables, delete all SNAT rules with the word "statistic", and restore the table
		iptables-save > $tmp; sed -i "/SNAT/d" $tmp; iptables-restore < $tmp; rm $tmp
		echo; printGood "Turned ** OFF ** outgoing source IP randomization."
	else
		# Randomize source IPs on all outgoing packets
		randomizePivotIP	
		# Save off current iptables, delete all masquerade rules, and restore the table
		iptables-save > $tmp; sed -i '/-o '$ethInt' -j MASQUERADE/ {d;}' $tmp; iptables-restore < $tmp; rm $tmp	
		echo; printGood "Turned ** ON ** outgoing source IP randomization."
	fi
}

# Create systemd unit file to restore iptable rules on reboot
autoStartIPTables(){
	cat > /etc/systemd/system/restore_iptables.service << EOF
[Unit]
Description="Restore iptable rules on reboot"
After=network.target

[Service]
ExecStart=iptables-restore < $setipsFolder/iptables.current

[Install]
WantedBy=multi-user.target
EOF
	systemctl enable restore_iptables.service
}

# Remove systemd unit file to restore iptable rules on reboot
removeStartIPTables(){
	systemctl disable restore_iptables.service
}

# Display the current IPTables list
displayIPTables(){
	if [[ -z `iptables-save` ]]; then
		echo; printError "There are no iptable rules."
		iptablesCount=0
	else
		echo; printGood "Displaying your current iptables rules:"
		echo; iptables-save
	fi
}

# Flush current IPTables rules
flushIPTablesPivotRules(){
	# Ask if you want to start the SOCKS proxy automatically on boot (careful, this will put your root password in a systemd unit file)
	if [[ $iptablesCount == 1 ]]; then
		echo
		printQuestion "Do you want to delete your current 1-to-1 NAT rules (y/n)? "; read REPLY
		while :; do
			if [[ $REPLY =~ ^[Yy]$ ]]; then
				iptables-save > iptables.tmp
				sed -i '/DNAT/d' -i '/-o '$ethInt' -j MASQUERADE/ {d;}' iptables.tmp
				iptables-restore < iptables.tmp
				rm iptables.tmp
				break
			elif [[ $REPLY =~ ^[Nn]$ ]]; then
				break
			else
				printQuestion "You didn't answer correctly; do you want to delete your current 1-to-1 NAT rules (y/n)? "; read REPLY
			fi
		done
	fi
}

# Setup IPTables SRC NAT Pivot
setupIPTablesPivot(){
	# Flush the current pivot rules?
	flushIPTablesPivotRules
	# Add IPTables pivot rules
	echo; printGood "Let's set up some IPTables..."
	listIPs
	echo; echo 'Is the traffic "tcp" or "udp"?'; read prot
	echo; printQuestion "What redirector subinterface *IP* should the redirector listen on?"; read subintip
	while true; do
		if [[ ! $subintip =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
			echo; printError "That doesn't appear to be a valid IP."
			printQuestion "What subinterface *IP* should the pivot listen on?"; read subintip
		else
			break
		fi
	done
	echo; printQuestion "What redirector subinterface *PORT* should the redirector listen on?"; read incomingport
	echo; printQuestion "What is the redteam *IP* the redirector sends incoming traffic to?"; read redteamip
	echo; printQuestion "What is the redteam *PORT* the redirector sends incoming traffic to?"; read redteamport
	# TESTING
	# $iptables -t nat -A PREROUTING -m state --state NEW -p $prot -d $subintip --dport $incomingport -j MARK --set-mark 0x400
	# $iptables -t nat -A PREROUTING -m mark --mark 0x400 -p $prot -j DNAT -d $subintip --dport $incomingport --to $redteamip:$redteamport
	# original	
	$iptables -t nat -A PREROUTING -p $prot -j DNAT -d $subintip --dport $incomingport --to $redteamip:$redteamport
	$iptables -t filter -I FORWARD 1 -j ACCEPT
	# Set IPs to auto-start on reboot
	autoStartIPTables
	echo
}

# Add additional iptables rule IP netblocks
setupIPTablesRedirectorIPs(){
	echo; printStatus "This function will setup the number of IPs you request and redirect them all"
	echo "to the destination you specify (example, request 5 IPs listening on port 80 to redirect"
	echo "to your teamserver at 1.2.3.4 on port 80)."
	flushIPTablesPivotRules
	listIPs
	addSubInts
	echo; echo 'Is the redirected traffic "tcp" or "udp"?'; read prot
	echo; printQuestion "What *PORT* should the pivot subinterface listen on?"; read incomingport
	echo; printQuestion "What is the redteam *IP* the pivot redirects incoming traffic to?"; read redteamip
	echo; printQuestion "What is the redteam *PORT* the pivot redirects incoming traffic to?"; read redteamport
	awk -F/ '{print $1}' $tmpIPs > $tmp2IPs; mv $tmp2IPs $tmpIPs
	while IFS= read subintip; do
		$iptables -t nat -A PREROUTING -p $prot -j DNAT -d $subintip --dport $incomingport --to $redteamip:$redteamport
		$iptables -t filter -I FORWARD 1 -j ACCEPT
	done < "$tmpIPs"
	# Set IPs to auto-start on reboot
	autoStartIPTables
	# Display current rules
	displayIPTables
}

setupAnotherRedirector(){
	exec &>/dev/tty
	REPLY="y"
	while :; do
		if [[ $REPLY =~ ^[Yy]$ ]]; then
			if [[ ! -f /root/.ssh/id_rsa ]] || [[ ! -f /root/.ssh/id_rsa.pub ]]; then
				echo; printStatus "No ssh keys found on the local system; I need to setup some for you."
				printStatus "Just hit enter if prompted for information."
				ssh-keygen
			fi
			echo; printQuestion "What is the IP of the redirector that you want to setup? "; read redirIP
			echo; printStatus "Pinging target for viability..."
			$ping -c 1 $redirIP > /dev/null
			if [[ $? == 0 ]]; then
				printGood "Target is alive."
				sshBytes=$(sudo cat /root/.ssh/id_rsa.pub | cut -d" " -f2| tail -c 6)
				echo; printStatus "Here are the last 5 characters of your public key:  $sshBytes"
				echo; printStatus "Checking for your SSH key on the target system."
				echo; printQuestion "What username do you want to log in with?"; read username
				ssh $username@$redirIP "sudo rm -f /root/setips.sh > /dev/null; sudo sed -i '/UseDNS/d' /etc/ssh/sshd_config; echo \"UseDNS no\" | sudo tee -a /etc/ssh/sshd_config; sudo service ssh restart; sudo grep $sshBytes /root/.ssh/authorized_keys"
				if [[ $? -gt 0 ]]; then
					echo; printStatus "SSH Key not found on target system; uploading..."
					publicKey=$(cat /root/.ssh/id_rsa.pub) 
					ssh $username@$redirIP "sudo echo "$publicKey" >> authorized_keys; sudo mv authorized_keys /root/.ssh/; sudo chown root:root /root/.ssh/authorized_keys; sudo chmod 600 /root/.ssh/authorized_keys"
				else
					echo; printGood "SSH key found."
				fi
				echo; printStatus "Uploading current setips.sh"
				scp /root/setips.sh root@$redirIP:/root/setips.sh
				ssh root@$redirIP "chmod +x /root/setips.sh; /root/setips.sh -n"
			else
				echo; printError "That IP did not respond to ping, try again."
			fi
			echo; printQuestion "Would you like to setup another redirector? (y/n)"; read REPLY
		elif [[ $REPLY =~ ^[Nn]$ ]]; then
			break
		else
			echo; printError "You didn't answer correctly; do you want to setup another redirector (y/n)? "; read REPLY
		fi
	done
}

# Save Pivot Rules to $setipsFolder/pivot.rules
savePivotRules(){
	tmp=`mktemp`
	date +"%Y%b%d-%H%M" > $tmp
	pivotRulesBackupFile="pivotRules-$(cat $tmp)"
	iptables-save |grep DNAT | awk -F" " '{print $6 " " $4 " " $10 " " $14}'| sed 's/:/ /g' | sed 's/\/32//g' > $pivotRulesBackup/$pivotRulesBackupFile
	cp $pivotRulesBackup/$pivotRulesBackupFile $setipsFolder/pivotRules.current
	echo; printGood "Backup of pivot rules saved to $pivotRulesBackup/$pivotRulesBackupFile"
}

# Setup Socat Pivot
setupSocatPivot(){
	# Check for dependencies
	if ! which socat > /dev/null; then
		echo; printError "The program socat is not installed...downloading now."
		$socatDownload
		commandStatus
		if [[ $internet == "0" ]]; then
			tar xvzf socat.tar.gz; cd socat*; ./configure; make; make install
			cd ..; rm -f socat.tar.gz
		fi
	fi
	echo; printQuestion "What port do you want to pivot (i.e. listen on)?"; read socatport
	while true; do
		if [[ $(ss -ltpn | grep "0.0.0.0:$socatport ") || $(ss -ltpn | grep "127.0.0.1:$socatport ") ]]; then
			echo; printError "Something is already listening on that port, please try a different port."
			echo; ss -ltpn | grep ":$socatport "
			echo; printQuestion "What port do you want to pivot (i.e. the one socat will listen for)?"; read socatport
		else
			break
		fi
	done
	echo; printQuestion "What is the redteam *IP* the pivot redirects incoming traffic to?"; read redteamip
	echo; printQuestion "What is the redteam *PORT* the pivot redirects incoming traffic to?"; read redteamport
	socat -d -d -d -lf $setipsFolder/socat.log TCP-LISTEN:$socatport,reuseaddr,fork,su=nobody TCP:$redteamip:$redteamport&
	disown
	if [[ $(ss -ltpn | grep -v grep | grep socat | grep $socatport | wc -l) -ge "1" ]]; then
		echo; printGood "SUCCESS! Socat pivot setup; logging to $setipsFolder/socat.log"
		ss -ltpn | grep socat
	else
		echo; printError "FAIL...looks like the socat pivot didn't setup correctly, check $setipsFolder/socat.log for errors."
	fi
}

# Stop SOCKS proxy
stopSocatPivot(){
	tmp=`mktemp`
	ss -ltpn | grep socat | awk '{ print $6 }' | cut -d= -f2 | cut -d, -f1 | sort -u > $tmp
	while read p; do kill -9 $p; done < $tmp
	rm -f $tmp
}

# Install redirector tools
installRedirTools(){
	downloadError=0
	echo; printStatus "Updating package repository."
	apt-get update
	apt-get -y autoremove
	echo; printStatus "Attempting to install:  wireguard unzip fping ipcalc socat readline-common screen traceroute nmap proxychains vsftpd apache2 php"
	apt-get -y install wireguard unzip fping ipcalc socat readline-common screen traceroute nmap proxychains vsftpd apache2 php libapache2-mod-php
	commandStatus
	systemctl stop apache2
	systemctl stop vsftpd
	update-rc.d apache2 disable
	update-rc.d vsftpd disable
	# Add vsftpd config files
	mkdir -p /var/ftp/upload
	chown ftp:ftp /var/ftp/upload
	mkdir -p /etc/vsftpd
	cat > /etc/vsftpd/vsftpd-anon.conf << 'EOF'
# Anon config file
listen=YES
local_enable=NO
anonymous_enable=YES
write_enable=YES
anon_root=/var/ftp
secure_chroot_dir=/var/ftp/upload
#
# optional
#
chown_upload_mode=0666
anon_umask=022
allow_writeable_chroot=YES
banner_file=/etc/vsftpd/banner_file
anon_mkdir_write_enable=YES
anon_other_write_enable=YES
anon_upload_enable=YES
no_anon_password=YES
xferlog_enable=YES
listen_port=21
#anon_max_rate=2048000
#listen_address=x.x.x.x
EOF
	# Add banner file
	cat > /etc/vsftpd/banner_file << 'EOF'
  _   _                  ____              _        _____ _____ ____
 | | | | ___   ___  _ __/ ___| _ __   __ _| | _____|  ___|_   _|  _ \
 | |_| |/ _ \ / _ \|  _ \___ \|  _ \ / _  | |/ / _ \ |_    | | | |_) |
 |  _  | (_) | (_) | |_) |__) | | | | (_| |   <  __/  _|   | | |  __/
 |_| |_|\___/ \___/| .__/____/|_| |_|\__,_|_|\_\___|_|     |_| |_|
                   |_|
 Your escape from the down-under...Copyright 1970
 - - - - -
 LOGIN with "anonymous"
 DO NOT FORGET to change directory to "upload" to upload/download stuff
EOF
	# Add vsftpd start file
	cat > /root/vsftpd.start << 'EOF'
#!/bin/bash
vsftpd /etc/vsftpd/vsftpd-anon.conf&
EOF
	chmod +x /root/vsftpd.start
	# Add vsftpd stop file
	cat > /root/vsftpd.stop << 'EOF'
#!/bin/bash
killall vsftpd
EOF
	chmod +x /root/vsftpd.stop
	# Install Java for Cobalt Strike
	echo; printQuestion "Would you like to install Java (required for Cobalt Strike? (y/N)"; read REPLY
	if [[ $REPLY =~ ^[Yy]$ ]]; then
		sudo apt -y install openjdk-11-jdk
		sudo update-java-alternatives -s java-1.11.0-openjdk-amd64
	fi
	if [[ $downloadError == 1 ]]; then
		echo; printError "Something went wrong...one or more downloads didn't complete successfully."
	else
		echo; printGood "Done."
	fi
}

# Clean old crap from iptables
cleanIPTables(){
	tmp=`mktemp`
	tmp2=`mktemp`
	tmp3=`mktemp`
	tmpSNAT=`mktemp`
	tmpDNAT=`mktemp`
	# Clean duplicate items that are next to each other; enable ipv4/ipv6 forwarding; remove old MASQUERADE method of "proxying"
	# older forwarding technique
	# echo 1 > /proc/sys/net/ipv4/ip_forward
	# sysctl net.ipv4.ip_forward=1
	iptables -I FORWARD -j ACCEPT
	iptables -P FORWARD ACCEPT
	# newer forwarding technique
	sed -i '/net.ipv4.ip_forward=1/s/^#//g' /etc/sysctl.conf
	sed -i '/net.ipv6.conf.all.forwarding=1/s/^#//g' /etc/sysctl.conf
	sysctl -p > /dev/null 2>&1
	sysctl --system > /dev/null 2>&1
	iptables-save | uniq > $tmp; sed -i '/-o '$ethInt' -j MASQUERADE/ {d;}' $tmp
	# DNAT - Clean duplicate items NOT next to each other; save off DNAT list to tmp.nat then remove all DNAT entries for tmp iptables file
	cat $tmp | grep "DNAT" | sort -u > $tmpDNAT; sed -i "/DNAT/d" $tmp
	# SNAT - Clean duplicate items NOT next to each other; save off SNAT list to tmp.nat then remove all DNAT entries for tmp iptables file
	cat $tmp | grep "SNAT" | sort -u > $tmpSNAT; sed -i "/SNAT/d" $tmp
	# Have to add "--packet 0" back into before restoring on certain version of iptables
	if [[ ! `grep "packet" $tmp` ]]; then
		awk 'BEGIN{OFS=FS=" "} $4~/statistic/ {$9="--packet 0 -j";}1' $tmp > $tmp2; mv $tmp2 $tmp
	fi
	# Restore the cleaned rules
	iptables-restore < $tmp
	# Add back in the cleaned DNAT rules; order doesn't matter
	while read p; do $iptables -t nat $p; done < $tmpSNAT
	while read p; do $iptables -t nat $p; done < $tmpDNAT
	rm $tmp $tmpDNAT $tmpSNAT
	# Clean masquerade rules (if applicable)
	if [[ $(iptables-save | grep -E 'statistic') ]]; then
		iptables-save > $tmp3; sed -i '/-o '$ethInt' -j MASQUERADE/ {d;}' $tmp3; iptables-restore < $tmp3; rm $tmp3
		iptables-save > $tmp3; sed -i '/-o '$ethInt' -j MASQUERADE/ {d;}' $tmp3; iptables-restore < $tmp3; rm $tmp3
	else
		$iptables -t nat -A POSTROUTING -o $ethInt -j MASQUERADE
		# $iptables -t nat -A POSTROUTING -m mark --mark 0x400 -j MASQUERADE
	fi
}

# Save IPTables for historical purposes
saveIPTables(){
	tmp=`mktemp`
	date +"%Y%b%d-%H%M" > $tmp
	iptablesBackupFile="iptables-$(cat $tmp)"
	iptables-save > $iptablesBackup/$iptablesBackupFile
	cp $iptablesBackup/$iptablesBackupFile $setipsFolder/iptables.current
	echo; printGood "Backup of iptables rules saved to $iptablesBackup/$iptablesBackupFile"
}

# Create IPTables to randomize source port when pivoting
randomizePivotIP(){
	tmp=/tmp/iptables.tmp
	iplist="./ips.list"
	# List subinterface ips randomly and put into file called "intips"
	listSubIntIPsOnly | shuf > $iplist
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
	iptables-save > $tmp; sed -i "/-A FORWARD -j ACCEPT/d" $tmp; iptables-restore < $tmp; rm $tmp	
	$iptables -t filter -I FORWARD 1 -j ACCEPT
}

setOnline(){
	sed -i '/^internet=/d' $setipsConfig
	echo 'internet="1"' >> $setipsConfig
	internet="1"
}

setOffline(){
	sed -i '/^internet=/d' $setipsConfig
	echo 'internet="0"' >> $setipsConfig
	internet="0"
}

setAskEachTime(){
	sed -i '/^internet=/d' $setipsConfig
	echo 'internet=""' >> $setipsConfig
	internet=""
}

# Loop function to redisplay menu
whatToDo(){
	echo; printQuestion "What would you like to do next?"
	echo "1)Setup  2)Subinterfaces  3)Utilities  4)View-Info  5)Quit"
}

# Start fully interactive mode (default when no options given or by adding "-i")
interactiveMode(){
echo; printError "Remember to remove your $ipsArchive file if you are starting a new exercise."; echo
select ar in "Setup" "Subinterfaces" "Utilities" "View-Info" "Quit"; do
	case $ar in
		Setup )
		echo
		echo "Setup Menu"
		echo "----------"
		echo "[Initial-Redirector] persistent static IP"
		echo "[SSH-SOCKS-Proxy] sets up SOCKS proxy on a port"
		echo "[IPTables-Pivot-IPs] redirects redirector IP/Port to target IP/Port"
		echo "[Socat-Pivot] sets up socat listener that redirects to target IP/Port"
		echo "[SublimeText] installs SublimeText"
		echo "[Cobaltstrike...] installs the programs listed"
		echo "[Static-IP] persistent static IP"
		echo
		select au in "Initial-Redirector" "Remote-Redirector" "Addtl-Redir-Pivot-IPs" "SSH-SOCKS-Proxy" "IPTables-Pivot-IPs" "Socat-Pivot" "Static-IP" "Main-Menu"; do
			case $au in
				Initial-Redirector )
				if [[ $internet = 1 ]]; then echo; installRedirTools; else printError "Need to be online to download/install required redirector tools."; fi
				echo; printGood "Redirector setup completed."
				break
				;;

				Remote-Redirector )
				setupAnotherRedirector
				break
				;;

				Addtl-Redir-Pivot-IPs )
				whatInterface
				echo; displayIPTables
				setupIPTablesRedirectorIPs
				cleanIPTables
				savePivotRules
				saveIPTables
				break
				;;

				SSH-SOCKS-Proxy )
				whatInterface
				checkForSubinterfaces
				cleanIPTables
				saveIPTables
				setupSOCKS
				iptablesToggleRandomSource ON
				break
				;;

				IPTables-Pivot-IPs )
				whatInterface
				checkForSubinterfaces
				echo; displayIPTables
				setupIPTablesPivot
				cleanIPTables
				saveIPTables
				break
				;;

				Socat-Pivot )
				setupSocatPivot
				break
				;;

				Static-IP )
				whatInterface
				setupStaticIP
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
				whatInterface
				addSubInts
				autoStartIPTables
				break
				;;

				Remove-All-Subinterfaces )
				listIPs
				removeSubInts
				break
				;;

				Restore-Subinterfaces )
				whatInterface
				removeSubInts
				restoreSubIntsFile
				setDNS
				setGateway
				netplan generate; netplan apply
				listIPs
				printGood "Your settings where restored.";
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
		select ut in "Install-Redirector-Tools" "Reset-Setips-Config" "Change-Internet-OpMode" "Set-Git-Server" "Set-Hostname" "Set-Gateway" "Set-DNS" "Set-MTU" "Disable-DNS-Stub-Resolver" "IPTables-flush" "IPTables-clean-pivots" "IPTables-toggle-random-source-IPs" "IPTables-restore-on-startup" "IPTables-REMOVE-restore-on-startup" "SOCAT-Pivots-REMOVE-ALL" "SOCKS-Proxy-REMOVE-ALL" "Main-Menu"; do
			case $ut in
				Install-Redirector-Tools )
				if [[ $internet = 1 ]]; then echo; installRedirTools; else printError "Need to be online to download/install required redirector tools." ; fi
				break
				;;

				Reset-Setips-Config )
				rm -f $setipsConfig
				createConfig
				echo; printGood "Setips config file created/recreated."
				break
				;;

				Change-Internet-OpMode )
				echo; printStatus "Change Internet OpMode"
				echo "----------------------"
				echo "Persistently changes this script's operational mode (can be changed at any time)."
				# Default the internet opmode
				internet=""
				opMode
				break
				;;

				Set-Git-Server )
				printQuestion "What is the IP or domain for the Git Server? "; read REPLY
				sed -i "/^redteamGogs=/c\redteamGogs=\"$REPLY\"" $setipsConfig
				break
				;;

				Set-Hostname )
				setHostname
				break
				;;

				Set-Gateway )
				listIPs
				setGateway
				netplan generate; netplan apply
				break
				;;

				Set-DNS )
				setDNS
				netplan generate; netplan apply
				break
				;;

				Set-MTU )
				setMTU
				netplan generate; netplan apply
				break
				;;

				Disable-DNS-Stub-Resolver )
				disableStubResolver
				setDNS
				break
				;;

				IPTables-flush )
				flushIPTables
				echo; printGood "IPTables successfully flushed."
				break
				;;

				IPTables-clean-pivots )
				cleanIPPivots
				echo; printGood "IPTables successfully cleaned of all pivots."
				break
				;;

				IPTables-toggle-random-source-IPs )
				iptablesToggleRandomSource
				cleanIPTables
				saveIPTables
				autoStartIPTables
				break
				;;

				IPTables-restore-on-startup )
				autoStartIPTables
				echo; printGood "Created systemd unit file to restore iptable rules on reboot."
				break
				;;

				IPTables-REMOVE-restore-on-startup )
				removeStartIPTables
				echo; printGood "Removed systemd unit file to restore iptable rules on reboot."
				break
				;;

				SOCAT-Pivots-REMOVE-ALL )
				stopSocatPivot
				echo; printGood "All SOCAT pivoting stopped."
				break
				;;

				SOCKS-Proxy-REMOVE-ALL )
				stopSOCKS
				iptablesToggleRandomSource OFF
				cleanIPTables
				saveIPTables
				autoStartIPTables
				echo; printGood "SSH SOCKS Proxies stopped."
				break
				;;

				Main-Menu )
				break
				;;
			esac
		done
		whatToDo
		;;

		View-Info )
		echo; printQuestion "What IP format do you want to view?"; echo
		select ex in "Proxychains" "Show-Current-IPs" "Show-Previously-Used-IPs" "Show-IPTables" "Main-Menu"; do
			case $ex in
				Proxychains )
				echo; printQuestion "What *PORT* do you want to use for your proxy?"; read proxyport
				echo; echo "Copy the following to the end of /etc/proxychains.conf"
				displayProxies
				break
				;;

				Show-Current-IPs )
				echo; printStatus "CHECK IT OUT -> You can find the save file here:  $ipsCurrent"
				listIPs
				break
				;;

				Show-Previously-Used-IPs )
				echo; printStatus "CHECK IT OUT -> You can find the archive file here:  $ipsArchive"
				cat $ipsArchive
				break
				;;

				Show-IPTables )
				displayIPTables
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
		echo; printGood "Exiting, nothing to do."; echo
		break
		;;
	esac
done
}

printHelp(){
	echo "Usage: [-h] [-i] [-l] [-r] [-a <protocol> <subintip> <subintport> <tgtIP> <tgtPort>]"
	echo "	   [-f <fileName>] [-d <protocol> <subintip> <subintport> <tgtIP> <tgtPort>] [-u]"
	echo
}

#### MAIN PROGRAM ####

# Starting core script
echo; echo "Setips Script - Version $scriptVersion"
printGood "Started:  $(date)"
printGood "Configuration and logging directory:  $setipsFolder"

# Check OS version
osCheck

# Ask to run interface setup or, if setup, collect information
if [[ ! -f $setipsFolder/setupComplete ]]; then
	firstTime
	touch $setipsFolder/setupComplete
fi

# Determine the operational mode - ONLINE or OFFLINE
opMode

# Check for iptables backup folder
if [[ ! -d $iptablesBackup ]]; then
	mkdir -p $iptablesBackup
fi

# Check for pivotRules backup folder
if [[ ! -d $pivotRulesBackup ]]; then
	mkdir -p $pivotRulesBackup
fi

# Checking ssh service is turned on and enabled for password login (Added for Don *grin*)
checkSSH

if [[ $1 == "help" || $1 == "--help" ]]; then
	echo; printStatus "setips.sh provides an interactive menu (-i) or arguements (see usage below)"
	echo; printHelp
elif [[ $1 == "" ]]; then
	interactiveMode
else
	IAM=${0##*/} # Short basename
	while getopts ":a:d:f:hilno:rstu" opt
	do sc=0 #no option or 1 option arguments
		case $opt in
		(a) # IMPORT - Quick entry to iptables src nat
			if [[ $# -lt $((OPTIND + 1)) ]]; then
				echo; echo "$IAM: Option -s argument(s) missing...needs five!" >&2
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
			$iptables -t nat -A PREROUTING -i $ethInt -p $protocol -j DNAT -d $subintip --dport $subintport --to $tgtip:$tgtport
			$iptables -t filter -I FORWARD 1 -j ACCEPT
			printGood "Imported rule specified."
			cleanIPTables >&2
			saveIPTables >&2
			echo
			sc=4 #5 args
			;;
		(d) # DELETE - Quick delete iptables rule
			if [[ $# -lt $((OPTIND + 1)) ]]; then
				echo; echo "$IAM: Option -s argument(s) missing...needs five!" >&2
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
			$iptables -t nat -D PREROUTING -i $ethInt -p $protocol -d $subintip --dport $subintport -j DNAT --to-destination $tgtip:$tgtport
			echo; printGood "Deleted rule specified."
			saveIPTables >&2
			echo
			sc=4 #5 args
			;;
		(f) # IMPORT - Import list of src nat entries from file
			#File format, one entry per line:  <tcp or udp> <pivot-subinterface-IP> <pivot-subinterface-listen-port> <target-IP> <target-port>
			srcnatfile=$OPTARG
			sed -i '/^\x*$/d' $srcnatfile > /tmp/srcnatfile #Remove blank lines
			# Delete current rules
			cleanIPPivots
			while IFS=" " read protocol subintip subintport tgtip tgtport; do
				# echo "$iptables -t nat -A PREROUTING -i $ethInt -p $protocol -j DNAT -d $subintip --dport $subintport --to $tgtip:$tgtport"
				echo "Redirecting $subintip:$subintport to $tgtip:$tgtport"
				# TESTING
				# $iptables -t nat -A PREROUTING -m state --state NEW -p $protocol -d $subintip --dport $subintport -j MARK --set-mark 0x400
				# $iptables -t nat -A PREROUTING -m mark --mark 0x400 -p $protocol -j DNAT -d $subintip --dport $subintport --to $tgtip:$tgtport
				# original below
				$iptables -t nat -A PREROUTING -i $ethInt -p $protocol -j DNAT -d $subintip --dport $subintport --to $tgtip:$tgtport
			done <$srcnatfile
			echo; printGood "Imported rules from file:  $srcnatfile"
			cleanIPTables >&2
			saveIPTables >&2
			echo
			;;
		(h) # Print help/usage statement
			echo; printHelp
			echo; echo "Examples:"
			echo "./setips.sh -h"
			echo "Displays this help menu."
			echo; echo "./setips.sh -i"
			echo "Interactive mode."
			echo; echo "./setips.sh -l"
			echo "List current IPTables rules."
			echo; echo "./setips.sh -r"
			echo "Repair current IPTables ruleset by removing duplicates, removing rules that conflict with SNAT source IP manipulation, and saving a backup."
			echo; echo "./setips.sh -a <tcp or udp> <pivot-subinterface-IP> <pivot-subinterface-listen-port> <target-IP> <target-port>"
			echo "Add single IPTables rule - by default, it will append to the iptables file."
			echo; echo "./setips.sh -d <tcp or udp> <pivot-subinterface-IP> <pivot-subinterface-listen-port> <target-IP> <target-port>"
			echo "Delete single IPTables rule matching the input."
			echo; echo "./setips.sh -f <file of SRC-NAT entries>"
			echo "Add list of IPTables rules from file - Reads file and appends SRC-NAT rules to the iptables file."
			echo "File Format, one entry per line:  <tcp or udp> <pivot-subinterface-IP> <pivot-subinterface-listen-port> <target-IP> <target-port>"
			echo; echo "./setips -u"
			echo "Updates the setips.sh script (when configured)."
			echo
			;;
		(i) # Fully interactive mode *historical as this is now the default operation*
			interactiveMode >&2
			;;
		(l) # List current IPTables rules
			displayIPTables >&2
			;;
		(n) # New redirector setup
			echo; printStatus "Setting up this server as a setips redirector."
			# Install redirector tools
			echo; printStatus "*IMPORTANT* For redirectors, there are several tools we need to install."
			if [[ $internet == "0" ]]; then
				echo; printError "You can not setup this redirector unless you can access a repo."
				echo; printQuestion "Would you like the try anyway? (Y/n)"; read REPLY
				if [[ $REPLY =~ ^[Nn]$ ]]; then
					echo; printError "Exiting."
					exit 1
				fi
			fi
			installRedirTools
			echo; printGood "Setup complete."
			# Remove the setupComplete flag to force the firstTime script to run on next start
			rm -f $setipsFolder/setupComplete > /dev/null 2>&1
			echo "" > $setipsFolder/setips.log
			;;
		(o) # IMPORT - Setup 1:1 redirector
			if [[ $# -lt $((OPTIND)) ]]; then
				echo; echo "$IAM: Option -s argument(s) missing...needs two!" >&2
				echo; printHelp >&2
				exit 2
			fi
			subintip=$OPTARG
			eval tgtip=\$$OPTIND
			
			# Adding 1:1 IP redirection
			$iptables -t nat -A PREROUTING -d $subintip -j DNAT --to-destination $tgtip
			$iptables -t nat -A POSTROUTING -s $tgtip -j SNAT --to-source $subintip
			printGood "Imported rule specified."
			cleanIPTables >&2
			saveIPTables >&2
			echo
			sc=1 #2 args
			;;
		(r) # REPAIR - quick repair; doesn't hurt if run multiple times.
			printGood "Cleaning up/repair the current IPTables ruleset."
			printGood "Saving backup of your IPTables before repair attempt to $iptablesBackup/$iptablesBackupFile"
			iptables-save > $iptablesBackup/$iptablesBackupFile
			cleanIPTables >&2
			#iptables-save | grep -v statistic | iptables-restore
			autoStartIPTables >&2
			saveIPTables >&2
			printGood "Repair complete, saving IPTables backup...run './setips.sh -l' to view current IPTables."
			;;
		(s) # Run first time script
			firstTime >&2
			;;
		(t) # Testing script
			testingScript >&2
			;;
		(u) # UPDATE - Update setips.sh to the latest release build.
			if [[ $internet == 1 ]]; then
				mv /root/setips /root/setips.backup
				git clone https://github.com/spatiald/setips.git
				if [[ -d $setipsGitFolder ]]; then
					cd /root/setips
					git checkout master
					commandStatus
					ln -sf $HOME/setips/setips.sh $HOME/setips.sh
					chmod +x /root/setips/setips.sh
					if [[ -f /root/setips.sh ]]; then echo; printGood "setips.sh downloaded to /root/setips.sh"; fi
					rm -rf /root/setips.backup
				else
					printError "The git repo failed to download...restoring original folder."
					mv /root/setips.backup /root/setips
				fi 
			else
				echo; printStatus "You are currently in OFFLINE mode."
				if [[ ! -z $redteamGogs ]]; then
					if [[ ! -d $setipsGitFolder ]]; then
						cd $HOME
						GIT_SSL_NO_VERIFY=true git clone https://$redteamGogs:3000/spatiald/setips.git
						ln -sf $setipsGitFolder/setips.sh $HOME/setips.sh > /dev/null 2>&1
					else
						cd $setipsGitFolder; GIT_SSL_NO_VERIFY=true git pull
						ln -sf $setipsGitFolder/setips.sh $HOME/setips.sh > /dev/null 2>&1
						echo
					fi
				else
					printQuestion "What is the IP or domain for the Git Server? "; read REPLY
					sed -i "/^redteamGogs=/c\redteamGogs=\"$REPLY\"" $setipsConfig
					bash $0 -u
				fi
			fi
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
		if [[ $OPTIND != 1 ]]; then #This test fails only if multiple options are stacked after a single "-"
			shift $((OPTIND - 1 + sc))
			OPTIND=1
		fi
	done
fi
