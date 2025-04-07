#!/bin/bash
#set -x
############################################################################
# Shellscript:  "setips.sh" Generates randoms ips for secondary interfaces
#  and automates the creation of proxy servers, pivots, web/ftp servers, and
#  other useful red team capabilities.
#
# Author : spatiald
############################################################################

scriptVersion=3.4

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
wget=$(which wget)
curl=$(which curl)
iptables=$(which iptables)
socatDownload="apt -y install socat"
userAgent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36 Edg/134.0.3124.72"

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
        # Use multiple methods to verify connectivity
        # 1. Try DNS resolution first (faster than full HTTP requests)
        if host -W 2 1.1.1.1 >/dev/null 2>&1 || host -W 2 google.com >/dev/null 2>&1; then
            # 2. Try ICMP ping to multiple reliable targets
            if $ping -c 1 -W 2 1.1.1.1 >/dev/null 2>&1 || $ping -c 1 -W 2 8.8.8.8 >/dev/null 2>&1; then
                # 3. Finally, try HTTP connectivity to diverse endpoints
                if $wget -q --spider --timeout=3 --tries=2 -U "$userAgent" https://1.1.1.1 >/dev/null 2>&1 || 
                   $wget -q --spider --timeout=3 --tries=2 -U "$userAgent" https://www.cloudflare.com >/dev/null 2>&1 || 
                   $curl -s --connect-timeout 3 -A "$userAgent" https://www.google.com >/dev/null 2>&1; then
                    printGood "Internet connection confirmed...continuing."
                    internet=1
                    return 0
                fi
            fi
        fi
        
        # If we get here, all checks failed
        echo; printError "No internet connectivity; entering 'OFFLINE' mode."
        internet=0
        return 1
    fi
    return 0
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
	echo; printStatus "Ethernet interface $ethInt assigned addresses:"
	#ip address show | grep "inet" | grep -v "inet6" | awk '{ print $2, $7, $8 }' | sed '/127.0/d'
	netplan get ethernets.$ethInt.addresses | cut -d "\"" -f2 | cut -d "\"" -f1
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

# List interfaces available
listInts(){
	ip address show | grep "mtu" | awk '{ print $2 }' | sed "s/://g" | sed "/lo/d"
}

# List subinterface IPs, one per line
listSubIntIPsOnly(){
	ip address show $ethInt | grep "inet" | grep -v "inet6" | awk '{ print $2 }' | sed '/127.0/d' | tail -n +2 | cut -d/ -f1 | awk '{printf "%s\n",$0} END {print ""}' | sed '/^$/d'
}

# List subints with CIDR, one per line
listSubInts(){
	#ip address show | grep secondary | awk '{ print $2 }'
	netplan get ethernets.$ethInt.addresses | tail -n+2 | cut -d "\"" -f2 | cut -d "\"" -f1
}

# Find the core IP address in use
listCoreInterfaces(){
	echo; printStatus "Core IP addresses on this system:"
	ip address show | grep "inet" | grep -v "inet6" | grep -v "secondary" | awk '{ print $2, $NF }' | sed '/127.0/d'
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
#	rm -f $tmp
#	sed -i -e "0,/\[\([^]]*\)\]/s|\[\([^]]*\)\]|[$(listCoreIP)]|" $netplanConfig
	#netplan get ethernets.$ethInt.addresses | head -1 | cut -d "\"" -f2 | cut -d "\"" -f1 > $tmp
	listCoreIP > $tmp	
	netplan set ethernets.$ethInt.addresses=null
	netplan set ethernets.$ethInt.addresses=[$(cat $tmp)]
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

	# Pull current ips - not needed as Netplan v0.105+ set command is additive and doesn't replace
	#cat $netplanConfig | grep "/" | cut -d "[" -f2 | cut -d "]" -f1 | sed "s/\,/\n/g" > $tmpUsedIPs ## old, replace ',' with new line
	netplan get ethernets.$ethInt.addresses | cut -d "\"" -f2 | cut -d "\"" -f1 | sed "s/\,/\n/g" > $tmpUsedIPs
	
	# Identify the CIDR, append to each of the new IPs, and add to list of current IPs
	#CIDR=$(listCoreIP | sed -n 's/.*\///p')
	CIDR=$(netplan get ethernets.$ethInt.addresses | head -1 | cut -d "\"" -f2 | cut -d "\"" -f1 | sed -n 's/.*\///p')
	for ip in $(cat $tmpIPs); do echo $ip/$CIDR >> $tmpUsedIPs; done

	# Unique addrs w/out sorting, and then replace new lines with ','
	cat $tmpUsedIPs | awk '!x[$0]++' | sed ':a; N; $!ba; s/\n/,/g' > $tmpIPs

	# Add clean addresses to netplan
	#sed -i '0,/addresses/s|addresses:.*|addresses: ['$(cat $tmpIPs)']|' test.yaml
	netplan set ethernets.$ethInt.addresses=[$(cat $tmpIPs)]

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
	echo; printStatus "The subinterface save file should be a one-line, comma-seperated list of IP/CIDR; for example, '192.168.1.1/24,192.168.1.55/24'"
	echo; printQuestion "What is the full path to the subinterfaces save file (default is $ipsCurrent)?"; read savefile || return
	if [[ -z ${savefile:+x} ]]; then
		printGood "Restoring from $ipsCurrent"
		savefile=$ipsCurrent
	else
		printGood "Restoring from $savefile"
	fi

	# Add clean addresses to netplan
	#sed -i '0,/addresses/s|addresses:.*|addresses: ['$(cat $savefile)']|' $netplanConfig
	sed -i '/^[[:space:]]*$/d' $savefile # remove newlines and white space
	netplan set ethernets.$ethInt.addresses=null # the current core IP maybe different from the savefile first IP...what is desired?
	netplan set ethernets.$ethInt.addresses=[$(listCoreIP),$(cat $savefile)]
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
    IP=$(listCoreIP)
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
    # Update the config file
    sed -i "/^IP=/c\IP=\"$IP\"" $setipsConfig
    
    # Update netplan with the new IP, replacing only the primary address
    # Get current addresses to preserve secondary ones
    currentAddresses=$(netplan get ethernets.$ethInt.addresses | tail -n+2 | cut -d "\"" -f2 | cut -d "\"" -f1)
    
    # Clear existing addresses first
    netplan set ethernets.$ethInt.addresses=null
    
    # Set the primary IP address
    if [[ -n "$currentAddresses" ]]; then
        # If we had secondary addresses, add them back
        netplan set ethernets.$ethInt.addresses=[$IP,$currentAddresses]
    else
        # Just set the primary IP
        netplan set ethernets.$ethInt.addresses=[$IP]
    fi
    
    printGood "Primary IP updated to $IP in netplan configuration"
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

        # Update the config file
        sed -i "/^GATEWAY=/c\GATEWAY=\"$currentgw\"" $setipsConfig
        
        # Update netplan with the new gateway
        # First remove existing routes
        netplan set ethernets.$ethInt.routes=null
        
        # Then add the new default route
        netplan set "ethernets.$ethInt.routes=[{to: 0.0.0.0/0, via: $currentgw, on-link: true}]"
        
        printGood "Gateway updated to $currentgw in netplan configuration"
    else
        printError "Gateway not changed."
    fi
}

# Set DNS
setDNS(){
    echo; echo "[---------  DNS  ---------]"
    echo
    if [ ! -f /etc/resolv.conf ]; then
        printError "You do not currently have DNS setup."
        dnsips="8.8.8.8,8.8.4.4"
    else
        dnsips=$(cat /etc/resolv.conf | grep nameserver | cut -d " " -f2 | awk '{printf "%s,",$0} END {print ""}' | sed 's/.$//')
        printStatus "Your current DNS server(s):  $dnsips"
    fi     
    printQuestion "Do you want to change your DNS servers? (y/N) "; read REPLY
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        printQuestion "What are the DNS server IPs (comma separated)?"; read dnsips
        printGood "Your DNS settings were updated."

        # Update resolv.conf
        echo "# This file was automagically created by the setips script." > /etc/resolv.conf
        for i in ${dnsips//,/ }
        do
            echo "nameserver $i" >> /etc/resolv.conf
        done
        
        # Update config file
        sed -i "/^NAMESERVERS=/c\NAMESERVERS=\"$dnsips\"" $setipsConfig
        
        # Set the global NAMESERVERS variable for use in createStaticYAML
        NAMESERVERS="$dnsips"

        # Update netplan's nameservers configuration
        netplan set ethernets.$ethInt.nameservers.addresses=[$dnsips]
    else
        printError "DNS not changed."
    fi
}

# Set MTU
setMTU(){
    echo; echo "[---------  MTU  ---------]"
    
    # Check if interface is set
    if [[ ! $ethInt ]]; then
        whatInterface
    elif [[ -z $runningFirstTime ]]; then
        echo; printStatus "Targeted interface:  $ethInt"
        printQuestion "Do you want to adjust the targeted interface? (Y/n)"; read REPLY
        if [[ $REPLY =~ ^[Nn]$ ]]; then
            echo; printStatus "Changing the interface..."
            whatInterface
        fi
    else
        printStatus "Interface:  $ethInt"
    fi

    # Get current MTU
    currentMTU="$( ip a | grep $ethInt | grep mtu | grep -v lo | awk '{for(i=1;i<=NF;i++)if($i=="mtu")print $(i+1)}' )"
    printStatus "Current MTU:  $currentMTU"
    
    # Ask if user wants to change MTU
    printQuestion "Do you want to change your MTU (normally 1500)? (y/N)"; read REPLY
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        printQuestion "What is your desired MTU setting (default is normally 1500)?"; read MTU
        if [[ -z ${MTU:+x} ]]; then MTU=1500; fi
        printGood "Setting MTU of $MTU."
    
        # Update MTU in setipsConfig
        sed -i "/^MTU=/c\MTU=\"$MTU\"" $setipsConfig
        
        # Use netplan set to update the MTU in the netplan configuration
        netplan set ethernets.$ethInt.mtu=$MTU
        
        printGood "MTU updated to $MTU in netplan configuration."
    else
        MTU=$currentMTU
        printError "MTU not changed."
        return 0  # Exit function early if no change requested
    fi
}

# Disable/stop DNS stub resolver
disableStubResolver(){
	echo; echo "[---------  CONFIGURE DNS STUB RESOLVER  ---------]"
	echo; printStatus "Disabling the local DNS stub resolver"
	systemctl disable systemd-resolved.service
	systemctl stop systemd-resolved
 	rm /etc/resolv.conf; echo "nameserver 8.8.8.8" >> /etc/resolv.conf
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

setupSSHKey() {
    # Create .ssh directory if it doesn't exist
    if [[ ! -d /root/.ssh ]]; then
        mkdir -p /root/.ssh
        chmod 700 /root/.ssh
    fi
    
    # Check if the key already exists
    if [[ ! -f /root/.ssh/setips_proxy ]]; then
        echo; printStatus "Creating SSH key for SOCKS proxy and other functions"
        ssh-keygen -t ed25519 -f /root/.ssh/setips_proxy -N "" -C "setips automated key"
        
        # Add the key to authorized_keys for local connections if not already there
        if ! grep -q "$(cat /root/.ssh/setips_proxy.pub)" /root/.ssh/authorized_keys; then
            cat /root/.ssh/setips_proxy.pub >> /root/.ssh/authorized_keys
            chmod 600 /root/.ssh/authorized_keys
            printGood "SSH key added to authorized_keys"
        fi
        
        printGood "SSH key created at /root/.ssh/setips_proxy"
    else
        printStatus "Using existing SSH key at /root/.ssh/setips_proxy"
        
        # Make sure the key is in authorized_keys even if we didn't create it
        if ! grep -q "$(cat /root/.ssh/setips_proxy.pub)" /root/.ssh/authorized_keys; then
            cat /root/.ssh/setips_proxy.pub >> /root/.ssh/authorized_keys
            chmod 600 /root/.ssh/authorized_keys
            printGood "Existing SSH key added to authorized_keys"
        fi
    fi
    
    # Configure SSH client to use this key for localhost
    if [[ ! -f /root/.ssh/config ]] || ! grep -q "Host localhost" /root/.ssh/config; then
        cat >> /root/.ssh/config << EOF
Host localhost
    IdentityFile /root/.ssh/setips_proxy
    StrictHostKeyChecking no
    UserKnownHostsFile=/dev/null
    PasswordAuthentication no
EOF
        chmod 600 /root/.ssh/config
        printGood "SSH config updated to use the key for localhost connections"
    fi
}

# Create systemd unit files for starting multiple SOCKS proxies
autoStartSOCKSProxy() {
    # Make sure SSH key is set up
    setupSSHKey
    
    # Identify running SOCKS proxies using ss
    # Get all listening ports with SSH that aren't the SSH server itself
    proxy_processes=$(ss -ltpn | grep -v grep | grep 0.0.0.0 | grep -v sshd | grep ssh)
    
    if [ -z "$proxy_processes" ]; then
        echo; printError "No active SOCKS proxies found. Please set up at least one proxy first."
        return 1
    fi
    
    # Extract the ports from the proxy processes
    proxy_ports=($(echo "$proxy_processes" | grep -o "0.0.0.0:\([0-9]\+\)" | cut -d':' -f2 | sort -u))
    
    if [ ${#proxy_ports[@]} -eq 0 ]; then
        echo; printError "Failed to identify active SOCKS proxy ports"
        return 1
    fi
    
    echo; printStatus "Found ${#proxy_ports[@]} active SOCKS proxies on ports: ${proxy_ports[*]}"
    
    # First, disable and remove any existing autostart services
    systemctl disable autostart_socks.service >/dev/null 2>&1
    rm -f /etc/systemd/system/autostart_socks.service >/dev/null 2>&1
    
    # Create a service file for each proxy port
    for port in "${proxy_ports[@]}"; do
        cat > /etc/systemd/system/socks_proxy_${port}.service << EOF
[Unit]
Description=SOCKS proxy on port ${port}
After=network.target sshd.service
Wants=sshd.service

[Service]
Type=simple
ExecStart=/usr/bin/ssh -i /root/.ssh/setips_proxy -o StrictHostKeyChecking=no -N -D 0.0.0.0:${port} root@127.0.0.1
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
        # Enable the service
        systemctl enable socks_proxy_${port}.service
        systemctl start socks_proxy_${port}.service
        echo; printGood "Created and enabled SOCKS proxy service for port ${port}"
    done
    
    systemctl daemon-reload
    
    echo; printGood "Created and enabled systemd services for ${#proxy_ports[@]} SOCKS proxies (ports: ${proxy_ports[*]})."
    echo; printStatus "Each proxy will run as an independent service and restart automatically if it fails."
    echo; printStatus "You can manage individual proxies with: systemctl [start|stop|status] socks_proxy_PORT.service"
    
    # Save list of proxies for reference
    echo "${proxy_ports[*]}" > $setipsFolder/proxies.autostart
    echo; printStatus "Port list saved to $setipsFolder/proxies.autostart"
}


createStaticYAML() {
    # Make backup directory if it doesn't exist
    mkdir -p $setipsFolder/netplan.backups
    
    # Backup existing netplan files if present
    for file in /etc/netplan/*.yaml; do
        if [[ -f "$file" && "$file" != "$netplanConfig" ]]; then
            cp "$file" "$setipsFolder/netplan.backups/$(basename $file).$(date +"%Y-%m-%d_%H-%M-%S")"
        fi
    done
    
    # Delete all YAML files in /etc/netplan/ directory
    rm -f /etc/netplan/*.yaml /etc/netplan/*.yml
    
    # Ensure GATEWAY is set
    GATEWAY=${GATEWAY:-$(getInternetInfo 3)}
    
    # Ensure MTU is set
    MTU=${MTU:-1500}
    
    # Ensure NAMESERVERS is set
    if [[ -z "$NAMESERVERS" ]]; then
        NAMESERVERS="8.8.8.8,8.8.4.4"
        printStatus "No DNS servers specified, using default Google DNS servers"
    fi
    
    # Create a clean YAML file
    cat > $netplanConfig << EOF
network:
  version: 2
  ethernets:
    $ethInt:
      dhcp4: false
      addresses: [$IP]
      routes:
        - to: 0.0.0.0/0
          via: $GATEWAY
          on-link: true
      mtu: $MTU
      nameservers:
        addresses: [$NAMESERVERS]
EOF
    
    # Ensure YAML is not viewable by others
    chmod 600 $netplanConfig
    
    printGood "Created network configuration at $netplanConfig"
}

setupStaticIP(){
    # Get current settings first before asking for new ones
    currentIP=$(listCoreIP)
    currentGateway="$( getInternetInfo 3 )"
    currentMTU="$( ip a | grep $ethInt | grep mtu | grep -v lo | awk '{for(i=1;i<=NF;i++)if($i=="mtu")print $(i+1)}' )"
    currentDNS=$(cat /etc/resolv.conf | grep nameserver | cut -d " " -f2 | awk '{printf "%s,",$0} END {print ""}' | sed 's/.$//')
    
    # Initialize variables with current values if they exist
    IP=${IP:-$currentIP}
    GATEWAY=${GATEWAY:-$currentGateway}
    MTU=${MTU:-$currentMTU}
    NAMESERVERS=${NAMESERVERS:-$currentDNS}
    
    # Ask for new settings or confirm current ones
    setIP
    setGateway
    setDNS
    setMTU
    
    # Ensure we have values for critical variables before creating YAML
    if [[ -z "$IP" ]]; then
        printError "No IP address set. Cannot create network configuration."
        return 1
    fi
    
    if [[ -z "$ethInt" ]]; then
        printError "No interface selected. Cannot create network configuration."
        return 1
    fi
    
    # Now recreate the YAML file with the updated settings
    createStaticYAML
    
    # Apply the changes
    netplan generate
    netplan apply
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
    
    # Check for existing proxies
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
    
    # Setup SSH key
    setupSSHKey
    
    echo; printGood "Starting up SOCKS proxy..."
    printStatus "The startup process will take ~5 secs."
    echo "    You will be returned to the setips menu when setup is complete."
    
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
    
    # Start SSH SOCKS proxy using key authentication
    screen -dmS ssh_socks ssh -i /root/.ssh/setips_proxy -o StrictHostKeyChecking=no -N -D 0.0.0.0:$proxyport -p $sshPort root@127.0.0.1
    # Check if it started correctly
    sleep 2
    if ss -ltpn | grep -v grep | grep $proxyport > /dev/null; then
        echo; printGood "SUCCESS...SOCKS proxy started on Port $proxyport."
        ss -ltpn | grep $proxyport
    else
        echo; printError "FAIL...looks like the SOCKS proxy didn't start correctly."
        echo "Try running the script again or check system logs for errors."
        exit 1
    fi
    
    echo; echo "To use, copy the following to the end of your local /etc/proxychains.conf file (replace any other proxies in the file):"
    displayProxies

	# Always restore socks proxies on reboot
	autoStartSOCKSProxy

    # Always turn ON IP table randomization when starting SOCKS proxy
    iptablesToggleRandomSource ON
    
    # Always save iptables and ensure they restore on reboot
    saveIPTables
    autoStartIPTables
    
    echo; printGood "IP randomization enabled and iptables persistence configured."
    echo; printGood "The SOCKS proxy will restore on reboot."
}

# Stop SOCKS proxy - improved version with reordered steps
stopSOCKS(){
    echo "Stopping all SOCKS proxies..."
    
    # 1. First identify all running proxy processes and their ports
    echo "Identifying all SOCKS proxy processes..."
    proxy_processes=$(ss -ltpn | grep -v grep | grep 0.0.0.0 | grep -v sshd | grep ssh)
    
    if [ -n "$proxy_processes" ]; then
        echo "Found SOCKS proxy processes by port:"
        echo "$proxy_processes"
        
        # Extract ports for use in systemd service removal
        ports=$(echo "$proxy_processes" | grep -o "0.0.0.0:\([0-9]\+\)" | cut -d':' -f2 | sort -u)
    fi
    
    # 2. Identify and disable all systemd services for SOCKS proxies
    echo "Identifying and disabling all SOCKS proxy systemd services..."
    
    # Find any systemd services matching our naming pattern
    service_ports=$(find /etc/systemd/system -name "socks_proxy_*.service" | grep -o '[0-9]\+\.service' | cut -d. -f1)
    
    # Combine with the ports we already found from running processes
    if [ -n "$ports" ] && [ -n "$service_ports" ]; then
        all_ports="$ports $service_ports"
    elif [ -n "$ports" ]; then
        all_ports="$ports"
    else
        all_ports="$service_ports"
    fi
    
    # Stop and disable each service first
    if [ -n "$all_ports" ]; then
        for port in $all_ports; do
            if [ -f "/etc/systemd/system/socks_proxy_${port}.service" ]; then
                echo "Stopping and disabling service for port $port"
                systemctl stop socks_proxy_${port}.service 2>/dev/null
                systemctl disable socks_proxy_${port}.service 2>/dev/null
            fi
        done
    fi
    
    # Also look for any other socks proxy services that might have different naming patterns
    other_socks_services=$(find /etc/systemd/system -name "*socks*.service" -o -name "*proxy*.service")
    for service in $other_socks_services; do
        if grep -q "SOCKS" "$service" || grep -q "ssh.*-D" "$service"; then
            echo "Found additional SOCKS service: $service"
            service_name=$(basename $service)
            systemctl stop $service_name 2>/dev/null
            systemctl disable $service_name 2>/dev/null
        fi
    done
    
    # 3. Remove all systemd service files
    echo "Removing all SOCKS proxy systemd service files..."
    
    if [ -n "$all_ports" ]; then
        for port in $all_ports; do
            if [ -f "/etc/systemd/system/socks_proxy_${port}.service" ]; then
                echo "Removing service file for port $port"
                rm -f "/etc/systemd/system/socks_proxy_${port}.service" 2>/dev/null
            fi
        done
    fi
    
    # Remove any other identified SOCKS service files
    for service in $other_socks_services; do
        if grep -q "SOCKS" "$service" || grep -q "ssh.*-D" "$service"; then
            echo "Removing additional service file: $service"
            rm -f "$service" 2>/dev/null
        fi
    done
    
    # Force systemd to reload its configuration
    systemctl daemon-reload
    
    # 4. Clean up the autostart proxy list file early
    if [ -f "$setipsFolder/proxies.autostart" ]; then
        echo "Removing autostart proxy configuration"
        rm -f "$setipsFolder/proxies.autostart"
    fi
    
    # 5. Turn OFF source IP randomization explicitly before killing processes
    iptablesToggleRandomSource OFF
    
    # 6. Now terminate screen sessions related to SSH
    if screen -ls | grep -q "\.ssh"; then
        echo "Killing SOCKS proxy screen sessions..."
        screen -ls | grep "\.ssh" | cut -d"." -f1 | awk '{print $1}' | while read pid; do
            echo "Killing screen session: $pid.ssh"
            screen -X -S $pid.ssh quit
        done
    fi
    
    # 7. Kill all processes identified earlier
    if [ -n "$proxy_processes" ]; then
        echo "Killing SOCKS proxy processes by PID..."
        pids=$(echo "$proxy_processes" | grep -o 'pid=[0-9]*' | cut -d= -f2)
        for pid in $pids; do
            echo "Killing process $pid"
            kill -9 $pid 2>/dev/null
            sleep 0.5
        done
    fi
    
    # 8. Kill all SSH processes with -D option (Dynamic forwarding/SOCKS)
    echo "Looking for SSH processes with dynamic forwarding..."
    socks_ssh_pids=$(ps aux | grep ssh | grep -E '\-D' | grep -v grep | awk '{print $2}')
    if [ -n "$socks_ssh_pids" ]; then
        echo "Found SSH processes with dynamic forwarding:"
        ps aux | grep ssh | grep -E '\-D' | grep -v grep
        
        for pid in $socks_ssh_pids; do
            echo "Killing SSH process with dynamic forwarding: $pid"
            kill -9 $pid 2>/dev/null
            sleep 0.5
        done
    fi
    
    # 9. Explicitly kill any SSH process connecting to localhost (likely our SOCKS proxies)
    echo "Looking for SSH processes connecting to localhost..."
    local_ssh_pids=$(ps aux | grep ssh | grep -E 'root@127.0.0.1|root@localhost' | grep -v grep | awk '{print $2}')
    if [ -n "$local_ssh_pids" ]; then
        echo "Found SSH processes connecting to localhost:"
        ps aux | grep ssh | grep -E 'root@127.0.0.1|root@localhost' | grep -v grep
        
        for pid in $local_ssh_pids; do
            echo "Killing local SSH process: $pid"
            kill -9 $pid 2>/dev/null
            sleep 0.5
        done
    fi
    
    # 10. Final verification - check if any SSH SOCKS proxies remain
    echo "Performing final verification..."
    sleep 2  # Allow time for processes to terminate
    
    remaining_proxies=$(ss -ltpn | grep -v grep | grep 0.0.0.0 | grep -v sshd | grep ssh)
    if [ -n "$remaining_proxies" ]; then
        echo "WARNING: Some SSH proxies still running after cleanup:"
        echo "$remaining_proxies"
        
        # Force kill any remaining processes
        pids=$(echo "$remaining_proxies" | grep -o 'pid=[0-9]*' | cut -d= -f2)
        for pid in $pids; do
            echo "Force killing stubborn process $pid"
            kill -9 $pid 2>/dev/null
        done
        
        # Final check
        if ss -ltpn | grep -v grep | grep 0.0.0.0 | grep -v sshd | grep ssh > /dev/null; then
            echo "ERROR: Failed to stop all SOCKS proxies. Manual intervention required."
        else
            echo "All SOCKS proxies successfully terminated after second attempt."
        fi
    else
        echo "All SOCKS proxies successfully terminated."
    fi
    
    # Cleanup any temporary files
    rm -f /tmp/socks.tmp 2>/dev/null
}

cleanIPPivots(){
	tmp=`mktemp`
	iptables-save | uniq > $tmp; sed -i '/--to-destination/ {d;}' $tmp; sed -i '/--to-source/ {d;}' $tmp
	iptables-restore < $tmp; rm $tmp
}

iptablesToggleRandomSource(){
	tmp=`mktemp`
	# Check if current iptables is set to random source address
	if [[ $1 == "OFF" || $(iptables-save | grep "SNAT") ]]; then 
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
    # First, make sure we have a current backup
    if [ ! -f "$setipsFolder/iptables.current" ]; then
        saveIPTables
    fi
    
    cat > /etc/systemd/system/restore_iptables.service << EOF
[Unit]
Description="Restore iptable rules on reboot"
After=network.target

[Service]
Type=oneshot
ExecStart=/sbin/iptables-restore $setipsFolder/iptables.current
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable restore_iptables.service
    echo; printGood "IPTables will be automatically restored at boot time"
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
# Function to display menu - now with an option to suppress the question for submenu returns
whatToDo(){
    # Clear any previous menu display for consistency
    echo
    echo "If needed, click Return for menu."
    echo
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
		select su in "Add-Subinterfaces" "Add-Subinterfaces-From-File" "Remove-All-Subinterfaces" "Restore-Subinterfaces" "Main-Menu"; do
			case $su in
				Add-Subinterfaces )
				whatInterface
				addSubInts
				autoStartIPTables
				break
				;;

				Add-Subinterfaces-From-File )
				whatInterface
				restoreSubIntsFile
				netplan generate; netplan apply
				autoStartIPTables
				break
				;;

				Remove-All-Subinterfaces )
				whatInterface
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

# Process command-line arguments first
if [[ "$1" == "-n" ]]; then
    # Skip firstTime check for the -n option
    :  # Null command (do nothing)
# Ask to run interface setup or, if setup, collect information
else
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
fi

# Checking ssh service is turned on and enabled for password login
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
		(n) # New setup - restore to default state
			echo; printStatus "Restoring this endpoint to a default state..."
			
            # Stop services
            stopSocatPivot
            stopSOCKS
            cleanIPTables
            saveIPTables
            
			# Remove the setips-files folder
			rm -rf $setipsFolder
			
			# Create the setips-files folder with only an empty log file and basic config
			mkdir -p $setipsFolder
			touch "$setipsFolder/setips.log"
			createConfig

			# Create a basic DHCP netplan configuration
			if [[ -f /etc/netplan/setips-network.yaml ]]; then
				# Backup existing config first
				cp /etc/netplan/setips-network.yaml /etc/netplan/setips-network.yaml.bak
			fi
			
			# Detect primary interface if possible
			primaryInterface=$(ip route | grep default | awk '{print $5}' | head -n 1)
			# If no interface found, use ethInt from config or just "eth0" as fallback
			primaryInterface=${primaryInterface:-${ethInt:-eth0}}
			
			# Create DHCP config
			cat > /etc/netplan/setips-network.yaml << EOF
network:
  version: 2
  ethernets:
    $primaryInterface:
      dhcp4: true
      dhcp-identifier: mac
EOF
			
			# Set proper permissions
			chmod 600 /etc/netplan/setips-network.yaml
			
			# Apply the configuration
			netplan generate
			netplan apply
			
			echo; printGood "Endpoint restored to default state with DHCP enabled."
			echo; printGood "When you next run setips.sh, it will perform first-time setup."
			exit 0
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