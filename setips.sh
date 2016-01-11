#!/bin/bash
############################################################################
# Shellscript:	"setips.sh" Generates randoms ips within the user
#	user provided network range. This script automatically assigns
#	each ip to a new sub-interface starting with the sub-int number
#	provided. It does not set gateway nor dns nameservers.
#
# Author : spatiald
############################################################################
#
# Highly recommended tools to install (can be installed with script via Option 3 then 13):
# apt-get -y install unzip fping ipcalc socat libreadline5 screen
#
# Offline programs to put on local storage/web server under root folder called software (e.g. http://192.168.1.1/software)
# These files can be prepped in ONLINE mode via undocumented feature --> run this:  ./setips.sh -s
# - sublime32/64.deb
# - cobaltstrike.zip
# - c2profiles.zip
# - powersploit.zip
# - veil.zip

# Fix backspace
stty sane

#in case you wish to kill it
trap 'exit 3' 1 2 3 15

# Setup some path variables
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
version=BETA
setipsFolder="$HOME/setips-files" # Main setips data folder
numberConfigLines="22" # Number of lines in the createConfig function's created file below

createConfig(){
	cat > $setipsFolder/setips.conf << 'EOF'
defaultMTU=1300 # Normal is 1500, Exercises are normally 1300
internet="" # "0"=Offline, "1"=Online, ""=(ie Blank) Force ask
downloadSoftware="" # "O"=Do not download offline software, "1"=Always download, ""=(ie Blank) Force ask
localSoftwareDir="$HOME/software" # Location where you want your downloaded software located
cobaltstrikeDir="$HOME/cobaltstrike" # Cobaltstrike folder
c2profilesDir="$HOME/c2profiles" # Cobaltstrike C2 Profiles folder
veilDir="$HOME/veil" # Veil folder
empireDir="$HOME/empire" # Empire folder
powersploitDir="$HOME/powersploit" # Powersploit folder
redteamShareAuth="0" # "0"=No user auth, "1"=Use user auth
redteamShare="" #e.g. 192.168.1.1 or share.com/remote.php/webdav/software
redteamShareUser="redteam" # Redteam share user
redteamWikiAuth="0" # "0"=No user auth, "1"=Use user auth
redteamWiki="http://wiki.rt/current-wiki" # Redteam wiki full web address
redteamWikiUser="redteam" # Redteam wiki user
redteamPathToUpdateSetips="linux/setips.sh" # Path on Redteam wiki to retrieve setips.sh script
redteamPathToUpdateSetipsBeta="linux/setips-beta.sh" # Path on Redteam wiki to retrieve setips.sh beta script
setipsUpdateFileDownloadLocation="$HOME/setips.sh" # Path to setips.sh script download location
redteamPathToPullSnortRules="scripts/community.rules" # Path on Redteam wiki to retrieve snort rules file
snortRulesFile="community.rules" # What we should call the downloaded snort rules file on local system
snortRulesDirectory="$HOME/snort-rules" # Path to snort rules FOLDER on local system (not a file)
snortRulesFileDownloadLocation="$snortRulesDirectory/$snortRulesFile" # Full path to snort community-rules file on local system
EOF
}

### DO NOT CHANGE the following
offlineServer(){
	if [[ $redteamShareAuth == 1 ]]; then
		# OwnCloud repo
		offlineDownloadServer="wget --show-progress -c -nH -r --no-parent -e robots=off --reject "index.html*" --http-user=$redteamShareUser --http-password=$redteamSharePassword $redteamShare/remote.php/webdav/software"
	else
		# Generic web server
		offlineDownloadServer="wget --show-progress -c -nH -r --no-parent -e robots=off --reject "index.html*" http://$redteamShare/software/"
	fi
}
os="$(awk -F '=' '/^ID=/ {print $2}' /etc/os-release 2>&-)"
osVersion=$(awk -F '=' '/VERSION_ID=/ {print $2}' /etc/os-release 2>&-)
osFullVersion=$(awk -F '=' '/VERSION=/ {print $2}' /etc/os-release 2>&-)
currentDateTime=`date +"%Y%b%d-%H%M"`
currentgw=`route -n|grep eth0| head -n 1|cut -d"." -f4-7|cut -d" " -f10`
ipsSaved="$setipsFolder/ips-saved.txt" # Save file for restoring IPs
ipsArchive="$setipsFolder/ips-archive.txt" # IP archive listed by date/time for reference during exercises
iptablesBackup="$setipsFolder/iptables"
iptablesBackupfile="iptables-$currentDateTime"
subintsBackup="$setipsFolder/subints"
downloadError="0"
counter=0
inundator=`which inundator`
ifconfig=`which ifconfig`
fping=`which fping`
ping=`which ping`
ipcalc=`which ipcalc`
iptables=`which iptables`

### Updated rarely
onlineVariables(){
	socatDownload="apt-get -y install socat"
	cobaltstrikeDownload=""
	c2profilesDownload="git clone https://github.com/rsmudge/Malleable-C2-Profiles $c2profilesDir"
	veilDownload="git clone https://github.com/Veil-Framework/Veil $veilDir"
	empireDownload="git clone https://github.com/PowerShellEmpire/Empire.git $empireDir"
	powersploitDownload="git clone https://github.com/mattifestation/PowerSploit $powersploitDir"
	sublime32Download="wget -c http://c758482.r82.cf2.rackcdn.com/sublime-text_build-3083_i386.deb -O $localSoftwareDir/sublime32.deb"
	sublime64Download="wget -c http://c758482.r82.cf2.rackcdn.com/sublime-text_build-3083_amd64.deb -O $localSoftwareDir/sublime64.deb"
	inundatorDownload="wget http://downloads.sourceforge.net/project/inundator/0.5/inundator_0.5_all.deb -O $localSoftwareDir/inundator_0.5_all.deb"
	snortRulesDownload="wget -c https://www.snort.org/downloads/community/community-rules.tar.gz -O $localSoftwareDir/community-rules.tar.gz"
}

offlineVariables(){
	socatDownload="apt-get -y install socat"
	cobaltstrikeDownload="unzip -u $localSoftwareDir/cobaltstrike.zip -d $HOME"
	c2profilesDownload="unzip -u $localSoftwareDir/c2profiles.zip -d $HOME"
	veilDownload="unzip -u $localSoftwareDir/veil.zip -d $HOME"
	empireDownload="unzip -u $localSoftwareDir/empireDir/powershellempire.zip -d $HOME"
	powersploitDownload="unzip -u $localSoftwareDir/powersploit.zip -d $HOME"
	sublime32Download="$localSoftwareDir/sublime32.deb"
	sublime64Download="$localSoftwareDir/sublime64.deb"
	inundatorDownload="unzip -u $localSoftwareDir/inundator_0.5_all.deb.zip -d $localSoftwareDir"
	snortRulesDownload=""
}

buildSoftwareList(){
	cat > $localSoftwareDir/software.lst << 'EOF'
sublime32.deb
sublime64.deb
cobaltstrike
c2profiles
veil
empire
powersploit
inundator_0.5_all.deb
snort-rules
EOF
}

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
    set -x
    trap ctrlC INT

	downloadOfflineSoftwareRepo
	installAdditionalSoftware

    downloadError="0"
    exit 1
}

osCheck(){
	if [[ -z "$os" ]] || [[ -z "$osVersion" ]]; then
	  printError "Internal issue. Couldn't detect OS information."
	elif [[ "$os" == "kali" ]]; then
	  printGood "Kali Linux ${osVersion} $(uname -m) Detected."
	elif [[ "$os" == "ubuntu" ]]; then
	  osVersion=$(awk -F '["=]' '/^VERSION_ID=/ {print $3}' /etc/os-release 2>&- | cut -d'.' -f1)
	  printGood "Ubuntu ${osFullVersion} $(uname -m) Detected."
	elif [[ "$os" == "debian" ]]; then
	  printGood "Debian ${osVersion} $(uname -m) Detected."
	fi
}

opMode(){
    trap ctrlC INT
    opModeOnline(){
		printGood "Script set for 'ONLINE' mode."
		internet=1
		setOnline
		onlineVariables
		checkInternet
    }
    opModeOffline(){
		printGood "Script set for 'OFFLINE' mode."
		internet=0
		setOffline
		offlineVariables
    }
    if [[ -z $internet ]]; then
    	printGood "Script set for 'ASK EVERY TIME' mode."
	    echo; printQuestion "Do you want to run in ONLINE or OFFLINE mode?"
	    select MODE in "ONLINE" "OFFLINE"; do
	        case $MODE in
	        # ONLINE
	        ONLINE)
				opModeOnline
	            break
	        ;;
	        # OFFLINE
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
	trap ctrlC INT
	echo; printStatus "Checking internet connectivity..."
    if [[ $internet == "1" || -z $internet ]]; then
        # Check internet connecivity
        WGET=`which wget`
        $WGET -q --tries=10 --timeout=5 --spider -U "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; AS; rv:11.0) like Gecko" http://ipchicken.com
        if [[ $? -eq 0 ]]; then
            printGood "Internet connection confirmed...continuing."
            internet=1
        else
            printError "No internet connectivity; waiting 10 seconds and then I will try again."
            # Progress bar to visualize wait period
            while true;do echo -n .;sleep 1;done & 
            sleep 10
            kill $!; trap 'kill $!' SIGTERM
            $WGET -q --tries=10 --timeout=5 --spider http://google.com
            if [[ $? -eq 0 ]]; then
                echo; printGood "Internet connected confirmed...continuing."
                internet=1
            else
                echo; printError "No internet connectivity; entering 'OFFLINE' mode."
                offlineVariables
                internet=0
            fi
        fi
    fi
}

# Capture a users Ctrl-C
ctrlC(){
	stty sane
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

collectInfo(){
	# Collect missing information
	if [[ ! -f $setipsFolder/mtu.current ]]; then
		echo; printStatus "Help me Obi Wan...I am missing some information."
		whatMTU
	fi
	if [[ ! -f $setipsFolder/subnet.current ]]; then
		whatInterface
		currentCoreIP=$($ifconfig $ethInt | grep "inet addr" | head -n 1 | cut -d":" -f2 | cut -d" " -f1)
		currentCoreNetmask=$(ifconfig $ethInt | grep "inet addr" | head -n 1 | cut -d":" -f4)
		if [[ $ipcalc ]]; then
			$ipcalc $currentCoreIP/$currentCoreNetmask | grep Netmask | cut -d" " -f6 > $setipsFolder/subnet.current
		else
			echo; printStatus "Current netmask:  $currentCoreNetmask"
			echo; printStatus "The force is not with me...I can't figure out the subnet CIDR you are on."
			printQuestion "What is the CIDR of the subnet you are on (ie 16 for 255.255.0.0)? "; read subnet
			echo $subnet > $setipsFolder/subnet.current
		fi
	fi
}

downloadOfflineSoftwareRepo(){
	downloadError=0	
	# If OFFLINE, download software from exercise repo
	if [[ $internet == 0 ]] && [[ $downloadSoftware == "" || $downloadSoftware == "1" ]]; then
		echo; printQuestion "For offline exercises, an offline software repository is usually available."
		read -p "Do you want to download/update your offline software repository? (y/N) " REPLY
		if [[ $REPLY =~ ^[Yy]$ ]]; then
			echo; printStatus "Checking for offline software updates."
			#	if [[ $internet == "0" ]]; then
			#		echo; printQuestion "What is the password to the redteam network share (press enter if blank)?"; read -s redteamSharePassword
			#	fi
			if [[ -z $redteamShare ]]; then
				echo; printQuestion "What is the IP/domain for the local server software repository?"; read redteamShare
				sed -i 's/^redteamShare="" #/redteamShare="'$redteamShare'" #/' $setipsFolder/setips.conf
			fi
			offlineServer
			$offlineDownloadServer
			commandStatus
			if [[ $downloadError == "1" ]]; then
				echo; printError "Download failed! Check if the variable 'offlineDownloadServer' is set correctly."
				echo "CAUTION:  Certain functions of this script will not work with these files."
			fi
		else
			echo; printStatus "User chose not to download/update their offline software repo."
			echo "HINT:  You can set the variable 'downloadsoftware' to 0 to prevent this prompt"
		fi
	fi
}

installAdditionalSoftware(){
	downloadError=0
	# Download Veil
	echo; printStatus "INSTALLING Veil"
	if [[ $os == "kali" ]] && [[ $osVersion == "2.0" ]]; then
		printError "Veil on Kali 2.0 requires additional architecture support that normally requires internet to install."
		echo "For example, Kali 2.0 does not enable i386-architecture nor have Python 2.7 installed by default"
		echo "An OFFLINE Ubuntu software repo *may* have the needed software. This script will attempt to download."
	fi
	if [[ $internet == 1 ]] && [[ -f $veilDir/Install.sh ]]; then
		if [[ -d $veilDir/Veil-Evasion ]]; then
			echo; printStatus "Veil exists, updating from GitHub."
			$veilDir/Install.sh -u
		else
			echo; printStatus "Veil does not exist, installing from GitHub."
			$veilDir/Install.sh -c
		fi
	fi
	if [[ ! -d $veilDir/Veil-Evasion ]]; then
		printStatus "Veil folder does not exist.."
		$veilDownload
		commandStatus
	else
		if [[ -d $veilDir/Veil-Evasion ]] && [[ -d $veilDir/Veil-Pillage ]] && [[ -d $veilDir/Veil-Catapult ]] && [[ -d $veilDir/Veil-Ordnance ]] && [[ -d $veilDir/PowerTools ]]; then
			printGood "Veil folders exists, moving on."
		else
			printError "Not all Veil folders exist, master...attempting to fix."
			$veilDir/Install.sh -c
		fi
	fi

	# Download Powershell Empire
	echo; printStatus "INSTALLING Powershell Empire"
	if [[ $internet == 1 ]] && [[ -f $empireDir/.git ]]; then
		echo; printStatus "Powershell Empire exists, updating from GitHub."
		cd $empireDir; git pull
	fi
	if [[ ! -d "$empireDir" ]]; then
		printStatus "Powershell Empire folder does not exist."
		$empireDownload
		commandStatus
		$empireDir/setup/install.sh
	else
		printGood "Powershell Empire folder exists, moving on."
	fi

	# Download PowerSploit
	echo; printStatus "INSTALLING Powersploit"
	if [[ $internet == 1 ]] && [[ -f $powersploitDir/.git ]]; then
		echo; printStatus "Powersploit exists, updating from GitHub."
		cd $powersploitDir; git pull
	fi
	if [[ ! -d "$powersploitDir" ]]; then
		printStatus "PowerSploit folder does not exist."
		$powersploitDownload
		commandStatus
	else
		printGood "PowerSploit folder exists, moving on."
	fi

	# Download Cobalt Strike C2 Profiles
	echo; printStatus "INSTALLING Cobaltstrike C2 Profiles"
	if [[ $internet == 1 ]] && [[ -f $c2profilesDir/.git ]]; then
		echo; printStatus "Cobalt Strike C2 Profiles exist, updating from GitHub."
		cd $c2profilesDir; git pull
	fi
	if [[ ! -d "$c2profilesDir" ]]; then
		printStatus "Cobaltstrike c2profiles folder does not exist."
		$c2profilesDownload
		commandStatus
	else
		printGood "Cobalstrike c2profiles folder exists, moving on."
	fi

	# Download Cobalt Strike
	echo; printStatus "INSTALLING Cobaltstrike"
	if [[ $internet == 0 ]] && [[ ! -f $cobaltstrikeDir/teamserver ]]; then
		printError "Cobaltstrike folder does not exist."
		$cobaltstrikeDownload
		commandStatus
	fi
	if [[ -f "$cobaltstrikeDir/teamserver" ]]; then
		printGood "Cobalstrike folder exists, moving on."
	else
		printError "Cobalt Strike folder does not exist and my powers are not strong enough to download it for you in ONLINE mode."
	fi

	downloadInundator
}

# Download/Install Inundator
downloadInundator(){
	echo; printStatus "INSTALLING Inundator"
	if [[ ! `which inundator` ]]; then
		printStatus "Inundator is not installed; installing now."
		$inundatorDownload
		apt-get -y install libnet-socks-perl
		dpkg -i $localSoftwareDir/inundator_0.5_all.deb
		commandStatus
	elif [[ `which inundator` ]] && [[ ! -f $inundatorDownload ]]; then

		printGood "Inundator is already installed, moving on."
	fi

	# Download Snort community rules
	echo; printStatus "INSTALLING/UPDATING Snort Community Rules"
	$snortRulesDownload
	mkdir -p $snortRulesDirectory
	if [[ -f $localSoftwareDir/community-rules.tar.gz ]]; then
		cd $snortRulesDirectory
		tar xvzf $localSoftwareDir/community-rules.tar.gz community-rules/community.rules
		mv $snortRulesDirectory/community-rules/community.rules $snortRulesDirectory/community.rules
		rm -rf $snortRulesDirectory/community-rules
		rm -f $localSoftwareDir/community-rules.tar.gz
	elif [[ -f $localSoftwareDir/snort-rules.zip ]]; then
		unzip $localSoftwareDir/snort-rules.zip -d $HOME
	fi
}

# Setup Sublime Text
downloadSublimeText(){
	# Determine the installer needed
	if [[ $(uname -m) == "x86_64" ]]; then
		sublimeInstaller=$localSoftwareDir/sublime64.deb
	else
		sublimeInstaller=$localSoftwareDir/sublime32.deb
	fi

	if [[ $internet = "1" ]]; then
		echo; printStatus "Downloading Sublime Text installer."
		if [[ $(uname -m) == "x86_64" ]]; then
			$sublime64Download
			commandStatus
		else
			$sublime32Download
			commandStatus
		fi
	elif [[ $internet = "0" ]] && [[ ! -f $sublimeInstaller.zip ]] && [[ ! -f $sublimeInstaller ]]; then
		downloadOfflineSoftwareRepo
	fi

	if [[ -f $sublimeInstaller.zip ]] && [[ ! -f $sublimeInstaller ]]; then
		unzip -u $sublimeInstaller.zip -d $localSoftwareDir
	fi

	if [[ -f $sublimeInstaller ]]; then
		echo; printGood "SublimeText installer downloaded."
	else
		echo; printError "I couldn't find the SublimeText installer...sorry."
		echo " - If ONLINE, check this link for accuracy:" 
		echo "   32-bit - $sublime32Download"
		echo "   64-bit - $sublime64Download"
		echo " - If OFFLINE, check the variable for the local software repo (offlineDownloadServer):"
		echo "   $offlineDownloadServer"
	fi
}

# Install SublimeText
installSublime(){
	if [[ ! -f /opt/sublime_text/sublime_text ]]; then
		downloadSublimeText
		echo; printStatus "Installing Sublime Text."
		if [[ -f $sublimeInstaller.zip ]]; then unzip -u $sublimeInstaller.zip -d $localSoftwareDir ; fi
		dpkg -i $sublimeInstaller
		if [[ ! -f /opt/sublime_text/sublime_text ]]; then 
			echo; printError "Something went wrong, check the log file:  $setipsFolder/setips.log"
		else
			echo; printGood "SublimeText installed successfully!"
		fi
	else
		echo; printGood "SublimeText is already installed."
	fi
}

# Show status of local software repo
offlineSoftwareRepoStatus(){
	if [[ -f $localSoftwareDir/software.lst ]]; then
		echo; printStatus "Offline software repository status:"
		echo "---------------------------------------"
		while read p; do
			if [[ -f $localSoftwareDir/$p.zip ]]; then printGood "$p"; else printError "$p"; fi
		done <$localSoftwareDir/software.lst
	else
		echo; printError "The software list does not exist --> $localSoftwareDir/software.lst"
	fi
}

# Find the IP addresses in use
listIPs(){
	echo; printStatus "Ethernet interfaces that have assigned addresses:"
	$ifconfig | grep -B1 "inet addr" |awk '{ if ( $1 == "inet" ) { print $2 } else if ( $2 == "Link" ) { printf "%s:" ,$1 } }' | sed 's/[addr]//g' |awk -F:: '{ print $1 " " $NF }' | sed "/lo/d"
}

# Find the core IP address in use
listCoreInterfaces(){
	echo; printStatus "Core IP addresses on this system:"
	#$ifconfig | head -n2 | awk '{ if ( $1 == "inet" ) { print $2, $4 } else if ( $2 == "Link" ) { printf "%s " ,$1 } }'
	$ifconfig | awk '{ if ( $1 == "inet" ) { print $2, $4 } else if ( $2 == "Link" ) { printf "%s " ,$1 } }' | grep -v eth'[0-9]': | head -n -1
}

# Show only the core IP address
listCoreIPAddr(){
	$ifconfig $ethInt |grep -B1 "inet addr" |awk '{ if ( $1 == "inet" ) { print $2 } else if ( $2 == "Link" ) { printf "%s:" ,$1 } }' | sed 's/[addr]//g' | awk -F:: '{ print $2 }' | head -n 1 2>&1
}

# List the interfaces without addresses assigned
listInts(){
	echo; printStatus "Ethernet interfaces:"
	$ifconfig -a |grep "eth" | awk '{ print $1 " " }' | sed "/lo/d" | sed "/:/d"
}

# Ask which ethernet port you want to create subinterfaces for
whatInterface(){
#if [[ ! -z ${ethInt:+x} ]]; then
listCoreInterfaces
#	listInts
while :; do
	echo; printQuestion "What ethernet interface do you want to work with (choose a root interface, ie eth0, eth1...)?"; read ethInt
	if [[ "$ethInt" =~ ^[A-Za-z]{3}+[0-9]{1}$ ]]; then
		break
	else
		echo; printError "Please enter the root ethernet interface (for example, enter eth0 not eth0:1)"
	fi
done
#fi
}

# List IPs, single line, comma-seperated
listIPs-oneline(){
	# List IPs for use in Armitage/Cobalt Strike "Teamserver"
	$ifconfig | grep -B1 "inet addr" |awk '{ if ( $1 == "inet" ) { print $2 } else if ( $2 == "Link" ) { printf "%s:" ,$1 } }' | sed 's/[addr]//g'| awk -F:: '{ print $NF }' | head -n -1 | awk '{printf "%s,",$0} END {print ""}' | sed 's/.$//'
}

# Tests IP for connectivity
pingTest(){
	if [[ `which fping` ]]; then
		$fping -c 1 $unusedip || echo $unusedip/$subnet >> /tmp/ips.txt
	else
		$ping -c 1 -w 0.5 $unusedip || echo "Available IP: "$unusedip; echo $unusedip/$subnet mtu $mtu >> /tmp/ips.txt
	fi
}

# What MTU
whatMTU(){
	# MTU
	if [[ -f $setipsFolder/mtu.current ]]; then
		echo; printStatus "Your current mtu is:  $(cat $setipsFolder/mtu.current)";
		mtu=$(cat $setipsFolder/mtu.current)
		echo; read -p "Do you want to change your mtu? (y/N)" -n 1 -r
		if [[ $REPLY =~ ^[Yy]$ ]]; then
			echo; echo; printQuestion "What is your desired MTU setting (current default is $defaultMTU)?"; read mtu || return
		else
			echo; printError "MTU not changed."
		fi
	else
		echo; printQuestion "What is your desired MTU setting (current default is $defaultMTU)?"; read mtu || return
	fi
	if [[ -z ${mtu:+x} ]]; then
		printGood "Setting mtu of $defaultMTU."
		mtu=$defaultMTU
	fi
	# Add MTU to backup file
	echo $mtu > $setipsFolder/mtu.current
}

# Remove all subinterfaces
removeSubInts(){
	$ifconfig | grep $ethInt |cut -d" " -f1 |tail -n +2 >> /tmp/sub.txt
	while IFS= read sub; do
	$ifconfig $sub down > /dev/null 2>&1
	done < "/tmp/sub.txt"

	if [[ -s /tmp/sub.txt ]]; then
		echo; printStatus "[-]Removed subinterface(s):"
		cat /tmp/sub.txt
		rm /tmp/sub.txt > /dev/null 2>&1
		rm /tmp/ips.txt > /dev/null 2>&1
	fi
}

# Add subinterfaces
addSubInts(){
	{ rm /tmp/ips.txt; touch /tmp/ips.txt; } > /dev/null 2>&1
	# MTU
	whatMTU

	# SUBNET
	echo; printQuestion "What subnet class are you creating IPs for?"
	select class in "A" "B" "C"; do
		case $class in
		A)
		# Find out the range that we are setting
		echo; printQuestion "What is the IP's first octet (number)?"; read octet1
		printQuestion "What is the IP's second octet (range; ie 1-255)?"; read octet2
		printQuestion "What is the IP's third octet (range; ie 1-255)?"; read octet3
		printQuestion "What is the IP's fourth octet (range; ie 1-255)?"; read octet4
		echo; printQuestion "What subnet (ie 8 for a 255.0.0.0)?"; read subnet

		#Ask how many subinterface ips the user would like
		echo; printQuestion "How many virtual ips (subinterfaces) would you like?"; read numberips

		until [[ $numberips = $(wc -l < /tmp/ips.txt) ]]; do
			unusedip=$octet1"."$(shuf -i $octet2 -n 1)"."$(shuf -i $octet3 -n 1)"."$(shuf -i $octet4 -n 1)
			pingTest
		sort -u /tmp/ips.txt > /tmp/ips2.txt; mv /tmp/ips2.txt /tmp/ips.txt
		done

		echo; printGood "Identified $numberips available IPs; setting subinterface IPs!"
		break
		;;

		B)
		# Find out the range that we are setting
		echo; printQuestion "What is the IP's first octet (number)?"; read octet1
		printQuestion "What is the IP's second octet (number)?"; read octet2
		printQuestion "What is the IP's third octet (range; ie 1-255)?"; read octet3
		printQuestion "What is the IP's fourth octet (range; ie 1-255)?"; read octet4
		echo; printQuestion "What subnet (ie 16 for a 255.255.0.0)?"; read subnet

		#Ask how many subinterface ips the user would like
		echo; printQuestion "How many virtual ips (subinterfaces) would you like?"; read numberips

		until [[ $numberips = $(wc -l < /tmp/ips.txt) ]]; do
			unusedip=$octet1"."$octet2"."$(shuf -i $octet3 -n 1)"."$(shuf -i $octet4 -n 1)
			pingTest
		sort -u /tmp/ips.txt > /tmp/ips2.txt; mv /tmp/ips2.txt /tmp/ips.txt
		done
		echo; printGood "Identified $numberips available IPs; setting subinterface IPs!"
		break
		;;

		C)
		# Find out the range that we are setting
		echo; printQuestion "What is the IP's first octet (number)?"; read octet1
		printQuestion "What is the IP's second octet (number)?"; read octet2
		printQuestion "What is the IP's third octet (number)?"; read octet3
		printQuestion "What is the IP's fourth octet (range; ie 1-255)?"; read octet4
		echo; printQuestion "What subnet (ie 24 for a 255.255.255.0)?"; read subnet

		#Ask how many subinterface ips the user would like
		echo; printQuestion "How many virtual ips (subinterfaces) would you like?"; read numberips

		until [[ $numberips = $(wc -l < /tmp/ips.txt) ]]; do
			unusedip=$octet1"."$octet2"."$octet3"."$(shuf -i $octet4 -n 1)
			pingTest
		sort -u /tmp/ips.txt > /tmp/ips2.txt; mv /tmp/ips2.txt /tmp/ips.txt
		done
		echo; printGood "Identified $numberips available IPs; setting subinterface IPs!"
		break
		;;
		esac
	done

	# Add subnet to backup file
	echo $subnet > $setipsFolder/subnet.current

	echo; printQuestion "What subinterface number would you like to start assigning ips to?"; read num; num=$((num-1))
	while IFS= read ip; do
		num=$((num+1))
		$ifconfig $ethInt:$num $ip mtu $mtu
	done < "/tmp/ips.txt"
	printGood "Done."; echo
	cp -f /tmp/ips.txt $ipsSaved

	# Save ips set for future restore by this script
	$ifconfig |grep -B1 "inet addr" |awk '{ if ( $1 == "inet" ) { print $2 } else if ( $2 == "Link" ) { printf "%s:" ,$1 } }' | sed 's/[addr]//g' | awk -F:: '{ print $1 " " $NF }' | sed -e "s/$/\/$subnet mtu $mtu/" | sed "/lo/d" > $ipsSaved

	# Append ips to running log
	echo \n$(date) >> $ipsArchive
	listIPs-oneline >> $ipsArchive

	printGood "Your IP settings were saved to three files:";
	echo "   - $ipsSaved -> restore them with this program";
	echo "   - $ipsArchive -> running log of all IPs used during an exercise/event";
	rm -rf /tmp/ips*.txt /tmp/sub.txt > /dev/null 2>&1
}

# Check for subinterfaces
checkForSubinterfaces(){
	$ifconfig | grep $ethInt |cut -d" " -f1 |tail -n +2 >> /tmp/sub.txt
	if [[ ! -s /tmp/sub.txt ]]; then
		echo; read -p "No subinterfaces exist...would you like to create some? (y/n) " -n 1 -r
		if [[ $REPLY =~ ^[Yy]$ ]]; then
			addSubInts
		fi
	else
		echo; printStatus "Current subinterfaces:"
		ifconfig |grep -B1 "inet addr" |awk '{ if ( $1 == "inet" ) { print $2 } else if ( $2 == "Link" ) { printf "%s:" ,$1 } }' | sed 's/[addr]//g' |awk -F:: '{ print $1 " " $NF }' | sed "/lo/d" | tail -n +2
		echo; read -p "Do you want to change your current subinterface IPs? (y/n) " -n 1 -r
		if [[ $REPLY =~ ^[Yy]$ ]]; then
			removeSubInts
			addSubInts
		fi
	fi
}

# Restore subinterface IPs from file
restoreSubIntsFile(){
	# Identify the subinterfaces save file
	echo; printQuestion "What is the full path to the setips save file (default is $ipsSaved)?"; read savefile || return
	if [[ -z ${savefile:+x} ]]; then
		printGood "Restoring from $ipsSaved."
		savefile=$ipsSaved
	else
		printGood "Restoring from $savefile"
	fi
	gatewayip=`route -n|grep $ethInt|grep 0.0.0.0|grep G|head -n 1|cut -d"." -f4-7|cut -d" " -f10`
	echo; printStatus "Your current gateway is set to:  $gatewayip"
	echo; read -p "Do you want to change your gateway? (y/N) " -n 1 -r
	if [[ $REPLY =~ ^[Yy]$ ]]; then
		echo; printQuestion "What is the IP of the gateway?"; read gatewayip || return
	fi
	# Add subinterfaces
	while IFS= read intip; do
		$ifconfig $intip
	done < "$savefile"
	# Add new gw
	route add default gw $gatewayip
}

# Set default gateway
setGateway(){
	echo
	currentgw=`route -n|grep $ethInt|grep 0.0.0.0|grep G|head -n 1|cut -d"." -f4-7|cut -d" " -f10`
	gatewayip=$currentgw
	if [[ -z ${currentgw:+x} ]]; then
		echo; printError "You do not have a default gateway set."
	else
		echo; printStatus "Your current gateway is:  $gatewayip"
	fi
	echo; read -p "Do you want to change your gateway? (y/N) " -n 1 -r
	if [[ $REPLY =~ ^[Yy]$ ]]; then
		echo; printQuestion "What is the IP of the gateway?"; read gatewayip || return
		# Remove current gw
		route del default gw $currentgw
		# Add new gw
		route add default gw $gatewayip
		newgw=`route -n|grep $ethInt|grep 0.0.0.0|grep G|head -n 1|cut -d"." -f4-7|cut -d" " -f10`
		if [[ -z ${newgw:+x} ]]; then
			echo; printError "Something went wrong...check your desired gateway."
		else
			echo; printGood "Your gateway was updated to:  $newgw"; echo
			# Print current routing table
			route -n; echo
		fi
	else
		echo; printError "Gateway not changed."
	fi
}

# Set DNS
setDNS(){
	echo; printStatus "Your current DNS settings:"
	cat /etc/resolv.conf
	echo; read -p "Do you want to change your DNS servers? (y/N) " -n 1 -r
	if [[ $REPLY =~ ^[Yy]$ ]]; then
		echo; printQuestion "What are the DNS server IPs (space separated)?"; read dnsips || return
		rm /etc/resolv.conf
		IFS=' '; set -f
		eval "array=(\$dnsips)"
		for x in "${array[@]}"; do echo "nameserver $x" >> /etc/resolv.conf; echo; done
		echo; printGood "Your DNS settings were updated as follows:"
		cat /etc/resolv.conf; echo;
	else
		echo; printError "DNS not changed."
	fi
}

# Auto set subinterface IPs on system start/reboot
autoSetIPsOnStart(){
	rm /root/setips-atstart.sh > /dev/null 2>&1 # check for old version
	subnet=`cat $setipsFolder/subnet.current`
	$ifconfig |grep -B1 "inet addr" |awk '{ if ( $1 == "inet" ) { print $2 } else if ( $2 == "Link" ) { printf "%s:" ,$1 } }' | sed 's/[addr]//g' | awk -F:: '{ print $1 " " $NF }' | sed -e "s/$/\/$subnet/" | sed "/lo/d" > $ipsSaved
	removeSetIPsOnStart
	gatewayip=`route -n|grep 0.0.0.0|grep G|head -n 1|cut -d"." -f4-7|cut -d" " -f10`
	if [[ ! -z ${gateway:+x} ]]; then
		setGateway
	fi
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
}

# Remove setips script from /etc/rc.local
removeSetIPsOnStart(){
	sed -i '/setips-atboot/d' /etc/rc.local
	rm -f /root/setips-atboot.sh
}

# Change /etc/ssh/sshd_config conifguration for root to only login "without-password" to "yes"
fixSSHConfigRoot(){
	awk 'BEGIN{OFS=FS=" "} $1~/PermitRootLogin/ {$2="yes";}1' /etc/ssh/sshd_config > /tmp/sshd_config.tmp; mv /tmp/sshd_config.tmp /etc/ssh/sshd_config
	service ssh restart
	echo; printGood "Modified /etc/ssh/sshd_config file to allow root to login with a password, restarted ssh."
}

# Add ssh socks proxy to /etc/rc.local
autoStartSOCKSProxy(){
	sed -i '/screen/d' /etc/rc.local
	sed -i '$e echo "#SOCKS - Auto-start SOCKS proxy on startup using screen"' /etc/rc.local
	sed -i '$e cat /tmp/ssh.tmp' /etc/rc.local
	rm -f /tmp/ssh.tmp
	echo; echo; printGood "Added SOCKS proxy auto-start script to /etc/rc.local"
}

setupStaticIP(){
	configureStaticIP=1
	echo "# This config was auto-generated using the setips.sh script" > /etc/network/interfaces
	echo "auto lo" >> /etc/network/interfaces
	echo "iface lo inet loopback" >> /etc/network/interfaces
	while [[ $configureStaticIP == 1 ]]; do
		whatInterface
		sed -i '/'$ethInt' START/,/'$ethInt' STOP/d' /etc/network/interfaces
		whatMTU
		echo; printQuestion "What IP do you want to set?"; read ip
		echo; printQuestion "What subnet (ie 8 for a 255.0.0.0)?"; read subnet
		# Configure address on interface
		$ifconfig $ethInt $ip/$subnet mtu $mtu
		# Add subnet to backup file
		echo $subnet > $setipsFolder/subnet.current
		echo; printGood "Your $ethInt interface is setup:"
		echo; ifconfig $ethInt
		if [[ ! $(cat /etc/network/interfaces | grep gateway) ]]; then
			setGateway
			setDNS
		fi

		# Configure /etc/network/interfaces file
		echo "# $ethInt START" >> /etc/network/interfaces
		echo "auto $ethInt" >> /etc/network/interfaces
		echo "iface $ethInt inet static" >> /etc/network/interfaces
		echo "address $ip" >> /etc/network/interfaces
		netmask=$(ifconfig $ethInt | grep "inet addr" | head -n 1 | cut -d":" -f4)
		echo "netmask $netmask" >> /etc/network/interfaces
		if [[ ! $(cat /etc/network/interfaces | grep gateway) ]]; then
			gatewayip=`route -n|grep $ethInt|grep 0.0.0.0|grep G|head -n 1|cut -d"." -f4-7|cut -d" " -f10`
			echo "gateway $gatewayip" >> /etc/network/interfaces
			dns=`cat /etc/resolv.conf | grep nameserver | awk '{ print $2}' | awk '{printf "%s ",$0} END {print ""}'`
			echo "dns-nameservers $dns" >> /etc/network/interfaces
		fi
		echo "# $ethInt STOP" >> /etc/network/interfaces
		echo; read -p "Do you want to setup another CORE interface with a static IP? (y/N)" -n 1 -r
		if [[ $REPLY =~ ^[Yy]$ ]]; then
			configureStaticIP=1
		else
			configureStaticIP=0
		fi
		echo
	done
}

# Setup SOCKS proxy
setupSOCKS(){
	# Check for dependencies
	if ! which socat > /dev/null; then
		echo; printError "The program socat is not installed and is required...downloading now."
		apt-get -y install socat libreadline5
		if ! which socat > /dev/null; then
			echo; printError "The program socat could not be downloaded. The SOCKS proxy requires it and will not be setup, exiting."
			break
		fi
	fi
	if [[ -f $setipsFolder/proxies.current ]]; then
		echo; printStatus "You currently have proxies running on the following ports:"
		cat $setipsFolder/proxies.current
		echo; read -p "Do you want to remove them? (y/N)" -n 1 -r
		if [[ $REPLY =~ ^[Yy]$ ]]; then
			echo; printStatus "Killing previous setips SSH SOCKS proxies."
			stopSOCKS
		else
			printStatus "Keeping existing proxies and continuing."
		fi
	fi
	echo; printGood "Starting up SOCKS proxy..."
	printStatus "The startup process will take ~5 secs."
	echo "    You will be returned to the setips menu when setup is complete."
	echo; printQuestion "What port do you want to use for your proxy?"; read proxyport
	while :; do
		if netstat -antp |grep 0.0.0.0:$proxyport
		then
			echo; printError "Something is already listening on that port, please try a different port."
			echo; printQuestion "What port do you want to use for your proxy?"; read proxyport
		else
			break
		fi
	done
	echo; printQuestion "What is root's password?"; read -s password
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

	if cat /etc/ssh/sshd_config | grep "without-password" | grep -v '"PermitRootLogin without-password"' > /dev/null; then
		echo; printError "I have to fix your sshd_config file to allow login with password."
		fixSSHConfigRoot
	fi

	echo; printGood "Setting up the SSH SOCKS proxy...please wait..."
	sshPort=`netstat -antp | grep "sshd" | head -n 1 | cut -d":" -f2| cut -d" " -f1`
	while :; do
		(sleep 2; echo $password; sleep 2; echo ""; sleep 1) | socat - EXEC:"screen -S ssh ssh -o StrictHostKeyChecking=no -gD$proxyport -p $sshPort -l root localhost",pty,setsid,ctty > /dev/null
		echo "(sleep 2; echo $password; sleep 2; echo ""; sleep 1) | socat - EXEC:'screen -S ssh ssh -o StrictHostKeyChecking=no -p $sshPort -gD"$proxyport" -l root localhost',pty,setsid,ctty" > /tmp/ssh.tmp
		if netstat -antp | grep -v grep | grep $proxyport > /dev/null; then
			echo; printGood "SUCCESS...SOCKS proxy started on Port $proxyport."
			echo $proxyport >> $setipsFolder/proxies.current
			netstat -antp | grep $proxyport
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
	$ifconfig | grep -B1 "inet addr" |awk '{ if ( $1 == "inet" ) { print $2 } else if ( $2 == "Link" ) { printf "%s:" ,$1 } }' | sed 's/[addr]//g' | awk -F:: '{ print "socks4 " $NF }' | awk '{ print $0 "'" $proxyport"'"}' | head -n -1

	# Ask if you want to start the SOCKS proxy automatically on boot (careful, this will put your root password in the /etc/rc.local file)
        echo; read -p "Would you like the SOCKS proxy to start on reboot? (y/n)" -n 1 -r
        if [[ $REPLY =~ ^[Yy]$ ]]; then
		autoStartSOCKSProxy
	else
		rm -rf /tmp/ssh.tmp;
	fi
	echo
}

# Stop SOCKS proxy
stopSOCKS(){
	screen -ls |grep ssh|cut -d"." -f1|cut -b2- > /tmp/socks.tmp
	while read p; do screen -X -S $p.ssh kill; done < /tmp/socks.tmp
	rm -f /tmp/socks.tmp
	sed -i '/screen/d' /etc/rc.local
	rm -f $setipsFolder/proxies.current
}

# Flush all current IPTable rules
flushIPTables(){
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
autoStartIPTables(){
		sed -i '/iptable*/d' /etc/rc.local
		sed -i '$e echo "#IPTables - Restore iptable rules on reboot"' /etc/rc.local
		sed -i '$e echo "iptables-restore < PATHTO"' /etc/rc.local
		awk 'BEGIN{OFS=FS=" "} $1~/iptables-restore/ {$3="'$setipsFolder'/iptables.current";}1' /etc/rc.local > /tmp/iptables.tmp; mv /tmp/iptables.tmp /etc/rc.local
}

# Remove iptables reinstall script from /etc/rc.local
removeStartIPTables(){
	sed -i '/iptable/d' /etc/rc.local
}

# Display the current IPTables list
displayIPTables(){
	if [[ -z `iptables-save` ]]; then
		echo; printError "There are no iptable rules."
	else
		echo; printGood "Displaying your current iptables rules:"
		echo; iptables-save
	fi
}

# Setup IPTables SRC NAT Pivot
setupIPTablesPivot(){
	# Ask if you want to start the SOCKS proxy automatically on boot (careful, this will put your root password in the /etc/rc.local file)
	echo; read -p "Would you like to flush the current iptable rules? (y/n)" -n 1 -r
	if [[ $REPLY =~ ^[Yy]$ ]]; then
		echo; read -p "ARE YOU SURE? (y/n)" -n 1 -r
		if [[ $REPLY =~ ^[Yy]$ ]]; then
			flushIPTables
		fi
	fi
	echo; printGood "Let's set up some IPTables..."
	listIPs
	echo; echo 'Is the traffic "tcp" or "udp"?'; read prot
	echo; printQuestion "What subinterface IP should the pivot listen on?"; read subintip
	while true; do
		if [[ ! $subintip =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
			echo; printError "That doesn't appear to be a valid IP."
			printQuestion "What subinterface *IP* should the pivot listen on?"; read subintip
		else
			break
		fi
	done
	echo; printQuestion "What port should the pivot subinterface listen on?"; read incomingport
	echo; printQuestion "What is the redteam *IP* the pivot redirects incoming traffic to?"; read redteamip
	echo; printQuestion "What is the redteam *PORT* the pivot redirects incoming traffic to?"; read redteamport
	$iptables -t nat -A PREROUTING -p $prot -j DNAT -d $subintip --dport $incomingport --to $redteamip:$redteamport
	$iptables -t filter -I FORWARD 1 -j ACCEPT
	# Ask if you want to reapply the iptables rules automatically on boot (/etc/rc.local file)
	if [[ $(grep iptable /etc/rc.local) ]]; then
		echo; read -e -p "Would you like to apply these rules automatically on reboot? (y/n) " -r
		if [[ $REPLY =~ ^[Yy]$ ]]; then
			autoStartIPTables
		fi
	fi
	echo
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
		if [[ $(netstat -antp | grep 0.0.0.0:$socatport) || $(netstat -antp | grep 127.0.0.1:$socatport) ]]; then
			echo; printError "Something is already listening on that port, please try a different port."
			echo; netstat -antp | grep $socatport
			echo; printQuestion "What port do you want to pivot (i.e. the one socat will listen for)?"; read socatport
		else
			break
		fi
	done
	echo; printQuestion "What is the redteam *IP* the pivot redirects incoming traffic to?"; read redteamip
	echo; printQuestion "What is the redteam *PORT* the pivot redirects incoming traffic to?"; read redteamport
	socat -d -d -d -lf $setipsFolder/socat.log TCP-LISTEN:$socatport,reuseaddr,fork,su=nobody TCP:$redteamip:$redteamport&
	if [[ $(netstat -antp | grep -v grep | grep socat | grep $socatport | wc -l) -ge "1" ]]; then
		echo; printGood "SUCCESS! Socat pivot setup; logging to $setipsFolder/socat.log"
		netstat -antp | grep socat
		break
	else
		echo; printError "FAIL...looks like the socat pivot didn't setup correctly, check $setipsFolder/socat.log for errors."
		break
	fi
}

# Setup Cobaltstrike Teamserver
setupTeamserver(){
	trap ctrlC INT

	# Check for installed software
	installAdditionalSoftware

	# Startup teamserver
	coreIPAddr=$(listCoreIPAddr)
	echo; printError "What teamserver password would you like to use?"; read teamPass

	# Ask if you will use a c2profile with the teamserver
	echo; read -e -p "Would you like to use a c2profile (if you don't know what that is, type 'n')? (y/n) "
	if [[ $REPLY =~ ^[Yy]$ ]]; then
		c2profile=""
		cd $c2profilesDir; ls -R *; cd
		echo; printError "What c2profile would you like to use? (enter just the name)"; read c2profile
		c2profile=`find $c2profilesDir/ -name $c2profile`
	fi

#	# Populate tables in background - OLD v2 setup that required msfprcd
#	msfrpcdpid=`ps aux|grep msfrpcd|head -n 1|awk '{ print $2 }'`
#	kill -9 $msfrpcdpid
#	service postgresql start
#	service metasploit start
#	service metasploit stop

	printStatus "If the teamserver fails to start, correct the issues and then type this command from the cobaltstrike folder:"
	echo "    ./teamserver $coreIPAddr $teamPass $c2profile"
	cd $cobaltstrikeDir; ./teamserver $coreIPAddr $teamPass $c2profile
}

# Install highly recommended tools
installRecommendedTools(){
	downloadError=0
	echo; printStatus "Updating package repository."
	apt-get update
	echo; printStatus "Attempting to install:  unzip, fping, ipcalc, socat, libreadline5, screen"
	apt-get -y install unzip fping ipcalc socat libreadline5 screen
	commandStatus
	if [[ $downloadError == 1 ]]; then 
		echo; printError "Something went wrong...one or more downloads didn't complete successfully." 
	else
		echo; printGood "Done."
	fi
}

# Loop function to redisplay menu
whatToDo(){
	echo; printQuestion "What would you like to do next?"
	echo "1)Setup  2)Subinterfaces  3)Utilities  4)Export  5)Quit"
}

# Clean old crap from iptables
cleanIPTables(){
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
saveIPTables(){
	currentDateTime=`date +"%Y%b%d-%H%M"`
	iptablesBackupfile="iptables-$currentDateTime"
	iptables-save > $iptablesBackup/$iptablesBackupfile
	cp $iptablesBackup/$iptablesBackupfile $setipsFolder/iptables.current
	echo; printGood "Backup of iptables rules saved to $iptablesBackup/$iptablesBackupfile"
}

# Create IPTables to randomize source port when pivoting
randomizePivotIP(){
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

setOnline(){
	sed -i 's/^internet="" #/internet="1" #/' $setipsFolder/setips.conf
	sed -i 's/^internet="0" #/internet="1" #/' $setipsFolder/setips.conf
	internet="1"
}

setOffline(){
	sed -i 's/^internet="" #/internet="0" #/' $setipsFolder/setips.conf
	sed -i 's/^internet="1" #/internet="0" #/' $setipsFolder/setips.conf
	internet="0"
}

setAskEachTime(){
	sed -i 's/^internet="0" #/internet="" #/' $setipsFolder/setips.conf
	sed -i 's/^internet="1" #/internet="" #/' $setipsFolder/setips.conf
	internet=""
}

# Start fully interactive mode (default when no options given or by adding "-i")
interactiveMode(){
echo; printError "Remember to remove your $ipsArchive file if you are starting a new exercise."; echo
select ar in "Setup" "Subinterfaces" "Utilities" "Export" "Quit"; do
	case $ar in
		Setup )
		echo
		select au in "Initial-Kali-Setup" "Setup-Redirector" "SSH-SOCKS-Proxy" "IPTables-SRC-NAT-Pivot" "Socat-Pivot" "Teamserver" "SublimeText" "Cobaltstrike-C2Profiles-Veil-PowershellEmpire-Powersploit-Inundator" "Static-IP" "Main-Menu"; do
			case $au in
				Initial-Kali-Setup)
				echo; printStatus "Setting up a static IP."
				setupStaticIP
				echo; printStatus "Install local system software repository and installing software."
				findRedteamShare(){
					echo; printQuestion "What is the IP/domain for the local server software repository?"; read redteamShare
					sed -i 's/^redteamShare="" #/redteamShare="'$redteamShare'" #/' $setipsFolder/setips.conf
				}
				if [[ -z $redteamShare ]]; then
					findRedteamShare
				else
					if [[ `which fping` ]]; then
						$fping -c 1 $redteamShare || findRedteamShare
					else
						$ping -c 1 -w 0.5 $redteamShare || findRedteamShare
					fi
				fi
				offlineServer
				downloadOfflineSoftwareRepo
				installAdditionalSoftware
				installSublime
				echo; printGood "Initial setup completed."
				break
				;;

				Setup-Redirector )
				echo; printStatus "Setting up a static IP."
				setupStaticIP
				echo; printStatus "Installing redirector tools/programs."
				installRecommendedTools
				echo; printGood "Redirector setup completed."
				break
				;;

				SSH-SOCKS-Proxy )
				whatInterface
				checkForSubinterfaces
				autoSetIPsOnStart
				randomizePivotIP
				cleanIPTables
				saveIPTables
				setupSOCKS
				break
				;;

				IPTables-SRC-NAT-Pivot )
				whatInterface
				checkForSubinterfaces
				autoSetIPsOnStart
				echo; displayIPTables
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
				setupTeamserver
				break
				;;

				SublimeText )
				installSublime
				break
				;;

				Cobaltstrike-C2Profiles-Veil-PowershellEmpire-Powersploit-Inundator )
				downloadOfflineSoftwareRepo
				installAdditionalSoftware
				break
				;;

				Static-IP )
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
				printGood "Here are your current settings:";
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
		select ut in "Change-Internet-OpMode" "Set-Gateway" "Set-DNS" "Fix-SSH-Without-Password" "Display-IPTables" "Flush-IPTables" "Auto-set-IPTables-on-startup" "Remove-auto-set-IPTables-on-startup" "Auto-set-IPs-on-startup" "Remove-auto-set-IPs-on-startup" "Startup-SOCKS-Proxy" "Stop-All-SOCKS-Proxies" "Install-Recommended-Tools" "Create-Setips-Config" "Main-Menu"; do
			case $ut in
				Change-Internet-OpMode )
				echo; printStatus "Change Internet OpMode"
				echo "----------------------"
				echo "Persistantly changes this script's operational mode (can be changed at any time)."
				opMode
				echo; printQuestion "What OpMode would you like to use:"
				select om in "ONLINE" "OFFLINE" "ASK-EACH-TIME" "Main-Menu"; do
					case $om in
						ONLINE )
						setOnline
						opMode
						break
						;;

						OFFLINE )
						setOffline
						opMode
						break
						;;

						ASK-EACH-TIME )
						setAskEachTime
						opMode
						break
						;;

						Main-Menu )
						break
						;;
					esac
				done
				break
				;;

				Display-IPTables )
				displayIPTables
				break
				;;

				Flush-IPTables )
				flushIPTables
				echo; printGood "IPTables successfully flushed."
				break
				;;

				Auto-set-IPTables-on-startup )
				autoStartIPTables
  				echo; printGood "Added iptables restore script to /etc/rc.local."
				break
				;;

				Remove-auto-set-IPTables-on-startup )
				removeStartIPTables
  				echo; printGood "Removed iptables auto-set script."
				break
				;;

				Auto-set-IPs-on-startup )
				whatInterface
				autoSetIPsOnStart
  				echo; printGood "Added setips auto-set script to /etc/rc.local."
				break
				;;

				Remove-auto-set-IPs-on-startup )
				removeSetIPsOnStart
  				echo; printGood "Removed setips auto-set script."
				break
				;;

				Startup-SOCKS-Proxy )
				setupSOCKS
  				echo; printGood "SSH SOCKS Proxy started."
				break
				;;

				Stop-All-SOCKS-Proxies )
				stopSOCKS
  				echo; printGood "SSH SOCKS Proxies stopped."
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

				Install-Recommended-Tools )
				installRecommendedTools
				break
				;;

				Create-Setips-Config )
				createConfig
				echo; printGood "Setips config file created/recreated."
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
		echo; printQuestion "What format do you want to export?"; echo
		select ex in "Cobaltstrike-Teamserver" "Proxychains" "List-Current-IPs" "List-Previously-Used-IPs" "Show-OFFLINE-Software-Repo-Status" "Main-Menu"; do
 			case $ex in
 				Cobaltstrike-Teamserver )
 				listIPs-oneline
				break
 				;;

				Proxychains )
				echo; printQuestion "What port do you want to use for your proxy?"; read proxyport
				echo; echo "Copy the following to the end of /etc/proxychains.conf"
				$ifconfig | grep -B1 "inet addr" |awk '{ if ( $1 == "inet" ) { print $2 } else if ( $2 == "Link" ) { printf "%s:" ,$1 } }' | sed 's/[addr]//g' | awk -F:: '{ print "socks4 " $NF }' | awk '{ print $0 "'" $proxyport"'"}' | head -n -1
				break
				;;

				List-Current-IPs )
				listIPs
				break
				;;

				List-Previously-Used-IPs )
				echo; cat $ipsArchive
				break
				;;

				Show-OFFLINE-Software-Repo-Status )
				offlineSoftwareRepoStatus
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
	echo "setips.sh Usage: [-h] [-i] [-l] [-r] [-a <protocol> <subintip> <subintport> <tgtIP> <tgtPort>]"
	echo "       [-f <fileName>] [-d <protocol> <subintip> <subintport> <tgtIP> <tgtPort>]"
	echo "       [-u] [-x <victim IP> <# of threads>] [-z]"
	echo
}

#### MAIN PROGRAM ####

# Check /etc/rc.local for the execute bit
chmod +x /etc/rc.local

# Check that we're root
if [[ $UID -ne 0 ]]; then
        printError "Superuser (i.e. root) privileges are required to run this script."
        exit 1
fi

# Setup setips folder (for saving setips scripts/backup files)
if [[ ! -d "$setipsFolder" ]]; then
	mkdir -p $setipsFolder > /dev/null 2>&1
fi

# Logging
exec &> >(tee "$setipsFolder/setips.log")

# Starting core script
echo; echo "Setips Script - Version $version"
printGood "Started:  $(date)"
printGood "Configuration and logging directory:  $setipsFolder"

# ONLY CHANGE the following variables in the config file -> $setipsFolder/setips.conf
# If it doesn't exist, create config file
if [[ ! -f $setipsFolder/setips.conf ]]; then
	createConfig
elif [[ `wc -l < $setipsFolder/setips.conf` != $numberConfigLines ]]; then # Sanity check the number of lines in config file 
	createConfig
fi

### Import config file
configFile="$setipsFolder/setips.conf"
configFileClean="/tmp/setips.conf"
# check if the file contains something we don't want
if egrep -q -v '^#|^[^ ]*=[^;]*' "$configFile"; then
  echo "Config file is unclean, cleaning it..." >&2
  # filter the original to a new file
  egrep '^#|^[^ ]*=[^;&]*'  "$configFile" > "$configFileClean"
  configFile="$configFileClean"
fi
# now source it, either the original or the filtered variant
source "$configFile"

# Check OS version
osCheck

# Determine the operational mode - ONLINE or OFFLINE
opMode

# Setup local software folder (for offline software installs)
if [[ ! -f "$localSoftwareDir/software.lst" ]]; then
	mkdir -p $localSoftwareDir > /dev/null 2>&1
	echo; printGood "Created $localSoftwareDir; all offline software is stored there."
fi
buildSoftwareList

# Ask to run interface setup or, if setup, collect information
if [[ ! -f $setipsFolder/subnet.current || ! -f $setipsFolder/mtu.current ]]; then
	checkForIP=$($ifconfig | awk '/inet addr/{print substr($2,6)}' | head -n -1 | wc -l)
	if [[ $checkForIP -ge "1" ]]; then
		echo; printStatus "I need to collect some info since you already have your interface setup."
		collectInfo
	elif [[ $checkForIP == "0" ]]; then
		echo; printStatus "You don't have an IP on any interface, starting initial setup."
		setupStaticIP
	fi
fi

if [[ $1 == "" || $1 == "--help" ]]; then
	echo; printHelp
else
	IAM=${0##*/} # Short basename
	while getopts ":a:d:f:hilrstux:z" opt
	do sc=0 #no option or 1 option arguments
		case $opt in
		(a) # IMPORT - Quick entry to iptables src nat
			if [[ $# -lt $((OPTIND + 1)) ]]; then
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
			printGood "Imported rule specified."
			cleanIPTables >&2
			saveIPTables >&2
			echo
			sc=4 #5 args
			;;
		(d) # DELETE - Quick delete iptables rule
			if [[ $# -lt $((OPTIND + 1)) ]]; then
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
			echo; printGood "Deleted rule specified."
			saveIPTables >&2
			echo
			sc=4 #5 args
			;;
		(f) # IMPORT - Import list of src nat entries from file
			#File format, one entry per line:  <tcp or udp> <pivot-subinterface-IP> <pivot-subinterface-listen-port> <target-IP> <target-port> 
			srcnatfile=$OPTARG
			sed -i '/^\x*$/d' $srcnatfile > /tmp/srcnatfile #Remove blank lines
			read -e -p "Do you want to delete your current 1-to-1 NAT rules (y/n)? " -r
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
			echo "Update setips.sh scripts with RELEASE version from the Redteam wiki."
			echo; echo "./setips -z"
			echo "Update setips.sh scripts with BETA version from the Redteam wiki."
			echo; echo "./setips.sh -x <target-IP> <#-of-threads>"
			echo "Inundator - Setup subinterfaces (if necessary), run inudator to blind snort sensors but send all the default snort rules across their sensors."
			echo
			;;
		(i) # Fully interactive mode
			interactiveMode >&2
			;;
		(l) # List current IPTables rules
			displayIPTables >&2
			;;
		(r) # REPAIR - quick repair; doesn't hurt if run multiple times.
			printGood "Cleaning up/repair the current IPTables ruleset."
			printGood "Saving backup of your IPTables before repair attempt to $iptablesBackup/$iptablesBackupfile"
			iptables-save > $iptablesBackup/$iptablesBackupfile
			cleanIPTables >&2
			autoStartIPTables >&2
			autoSetIPsOnStart >&2
			saveIPTables >&2
			printGood "Repair complete, saving IPTables backup...run './setips.sh -l' to view current IPTables."
			;;
		(s) # Setup offline software repository
			if [[ $internet != 1 ]]; then echo; printError "You must be online to run this command."; echo; break; fi
			if [[ $os != "kali" ]]; then echo; printError "This setup must be run on Kali, exiting."; echo; break; fi
			cd $localSoftwareDir
			echo; printStatus "Install/update core programs."
			installRecommendedTools
			echo; printStatus "Downloading additional software."
			downloadOfflineSoftwareRepo
			installAdditionalSoftware
			echo; $sublime32Download
			echo; $sublime64Download
#			echo; $inundatorDownload
			rm -rf $localSoftwareDir/*.zip
			echo; printStatus "Zip'ing and moving software to folder:  $localSoftwareDir"
			while read p; do
				# Check $HOME directory
				cd $HOME
				echo; zip -r $localSoftwareDir/$p.zip $p
				# Check $localSoftwareDir directory
				cd $localSoftwareDir
				echo; zip -r $localSoftwareDir/$p.zip $p
			done <$localSoftwareDir/software.lst
			offlineSoftwareRepoStatus
			echo; printGood "OFFLINE Software Repo setup --> $localSoftwareDir"
			echo; printStatus "Sending software zip's to local server software repository."
			printStatus "CAUTION: This command assumes you already have a folder on the local server in /var/www/html/software"
			printQuestion "What is the IP of the local server (Ctrl-C to exit)?"; read softwareRepoIP
			rsync -avh --progress $localSoftwareDir/*.zip root@$softwareRepoIP:/var/www/html/software
			echo
			;;
		(t) # Testing script
			testingScript >&2
			;;
		(u) # UPDATE - Update setips.sh to the latest release build.
			if [[ $internet == 1 ]]; then
				rm -rf /root/setips
				git clone https://github.com/spatiald/setips.git
				cd /root/setips
				git checkout master
				commandStatus
				cp /root/setips/setips.sh /root/setips.sh
				chmod +x /root/setips.sh
				if [[ -f /root/setips.sh ]]; then echo; printGood "setips.sh downloaded to /root/setips.sh"; fi
			else
				echo; printStatus "You are currently in OFFLINE mode."
				echo; printQuestion "To download the latest version, I need to know the password to the Redteam wiki?"; read -s redteamWikiPassword
				setipsDownloadLink="wget --http-user=$redteamWikiUser --http-password=$redteamWikiPassword $redteamWiki/$redteamPathToUpdateSetips -O $setipsUpdateFileDownloadLocation.tmp"
				$setipsDownloadLink >&2
				if [[ -s $setipsUpdateFileDownloadLocation.tmp ]]; then
					mv $setipsUpdateFileDownloadLocation $setipsFolder/setips.sh.last
					mv $setipsUpdateFileDownloadLocation.tmp $setipsUpdateFileDownloadLocation
					chmod +x $setipsUpdateFileDownloadLocation
					printGood "Success! Downloaded update to /root/setips.sh"
				else
					printStatus "Fail! Check the password you entered in the following command, fix if necessary, confirm your download and run this script again:"
					echo "$setipsDownloadLink"
					echo
				fi
			fi
			;;
		(z) # UPDATE - Update setips.sh to the latest beta build.
			if [[ $internet == 1 ]]; then
				rm -rf /root/setips
				git clone https://github.com/spatiald/setips.git
				cd /root/setips
				git checkout beta
				commandStatus
				cp /root/setips/setips.sh /root/setips.sh
				chmod +x /root/setips.sh
				if [[ -f /root/setips.sh ]]; then echo; printGood "setips.sh downloaded to /root/setips.sh"; fi
			else
				echo; printQuestion "To download the latest version, I need to know the password to the Redteam wiki?"; read -s redteamWikiPassword
				setipsDownloadLink="wget --http-user=$redteamWikiUser --http-password=$redteamWikiPassword $redteamWiki/$redteamPathToUpdateSetipsBeta -O $setipsUpdateFileDownloadLocation.tmp"
				$setipsDownloadLink >&2
				if [[ -s $setipsUpdateFileDownloadLocation.tmp ]]; then
					mv $setipsUpdateFileDownloadLocation $setipsFolder/setips.sh.last
					mv $setipsUpdateFileDownloadLocation.tmp $setipsUpdateFileDownloadLocation
					chmod +x $setipsUpdateFileDownloadLocation
					printGood "Success! Downloaded update to /root/setips.sh"
				else
					printStatus "Fail! Check the password you entered in the following command, fix if necessary, confirm your download and run this script again:"
					echo "$setipsDownloadLink"
					echo
				fi
			fi
			;;
		(x) # INUNDATOR - Setup subinterfaces (if necessary), run inudator to replay snort rules that "inundates" snort sensors by sending all the default snort rules across their sensors
			# inundator 76.161.37.18 --verbose --thread 10 --proxy 37.75.5.41:1080 --rules /root/community-rules/

			# Install inundator, if not available (Kali 2.0)
			# Also, download/update Snort Community Rules
			downloadInundator

			if [[ $# -lt $((OPTIND)) ]]; then
				echo "$IAM: Option -x argument(s) missing...needs 2!" >&2
				echo; printHelp >&2
				exit 2
			fi
			OPTINDplus1=$((OPTIND + 1))
			tgtIP=$OPTARG
			eval threads=\$$OPTIND
			# Start setup
			if [[ ! -f $localSoftwareDir/community-rules/community.rules ]]; then
				echo; printStatus "You will need snort rules to run this script. If you want to download a copy, select 'n' to get them from the Redteam share"
				while :; do
					read -e -p "Do you already have them downloaded already (y/n)? " -r
					if [[ $REPLY =~ ^[Nn]$ ]]; then
						echo; printQuestion "What is the password to the network share?"; read -s redteamSharePassword
						mkdir -p $snortRulesDirectory
						# Downloading snort rulesets
						snortRulesDownloadLink="wget --http-user=$redteamShareUser --http-password=$redteamSharePassword $redteamShare/$redteamPathToPullSnortRules -O $snortRulesFileDownloadLocation"
						$snortRulesDownloadLink >&2
						if [[ -s $snortRulesFileDownloadLocation ]]; then
							echo; printGood "Success! Downloaded rules to $snortRulesFileDownloadLocation"
						else
							echo; printStatus "Fail! Check the password you entered in the following command, fix if necessary, confirm your download and run this script again:"
							echo "$snortRulesDownloadLink"
							exit 1
						fi
						break
					elif [[ $REPLY =~ ^[Yy]$ ]]; then
						echo; printQuestion "What is the path to your Snort rules *directory* (no trailing slash)? "; read snortRulesUserProvidedDirectory
						snortRulesDirectory="$snortRulesUserProvidedDirectory"
						break
					else
						echo; printError "You need to enter y (yes) or n (no)."
					fi
				done
			fi
			# Check config file for correct rules path
			sed -i '/snort/d' 
			echo 'snortRulesFile="'$snortRulesFile'" # What we should call the downloaded snort rules file on local system/' >> $setipsFolder/setips.conf
			echo 'snortRulesDirectory="'$snortRulesDirectory'" # Path to snort rules FOLDER on local system (not a file)/' >> $setipsFolder/setips.conf
			echo 'snortRulesFileDownloadLocation="$snortRulesDirectory/$snortRulesFile" # Full path to snort rules file on local system' >> $setipsFolder/setips.conf
			echo; printStatus "You need to use a proxy to increase your effects. Select 'n' to use a different server redirector IP:port"
			read -e -p "Do you want to setup a proxy on your local box (y/n)? " -r
			while :; do
				if [[ $REPLY =~ ^[Yy]$ ]]; then
					whatInterface >&2
					checkForSubinterfaces >&2
					autoSetIPsOnStart >&2
					cleanIPTables >&2
					saveIPTables >&2
					echo; read -e -p "Enter 9050 when asked for your port...enter 'y' to confirm that you understand (y/n) " -r
					echo
					setupSOCKS
					proxy="localhost:9050"
					break
				elif [[ $REPLY =~ ^[Nn]$ ]]; then
					echo; printQuestion "What is the IP:Port of the external proxy (format as IP:Port)? "; read proxy
					break
				fi
			done
			echo; printGood "Command built, this is what I will execute:"
			echo "$inundator --thread $threads --proxy $proxy --rules $snortRulesDirectory --verbose $tgtIP"
			echo; printStatus "If you receive errors, check your commands for the accuracy."
			echo; read -e -p "Are you ready to execute? (y/n) " -r
			while :; do
				if [[ $REPLY =~ ^[Yy]$ ]]; then
					echo; read -e -p "ARE YOU SURE? (y/n) " -r
					if [[ $REPLY =~ ^[Yy]$ ]]; then
						echo; $inundator --thread $threads --proxy $proxy --rules $snortRulesDirectory --verbose $tgtIP
						commandStatus
						exit 1
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
		if [[ $OPTIND != 1 ]]; then #This test fails only if multiple options are stacked after a single "-"
			shift $((OPTIND - 1 + sc))
			OPTIND=1
		fi
	done
fi
# Remove clear screen commands from log file <-- created by the Veil scripts
sed -i '/=======/d' $setipsFolder/setips.log

