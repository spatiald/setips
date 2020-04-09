#!/bin/bash
#set -x
############################################################################
# Shellscript:  "setips.sh" Generates randoms ips within the user
#	user provided network range. This script automatically assigns
#	each ip to a new sub-interface starting with the sub-int number
#	provided. It does not set gateway nor dns nameservers.
#
# Author : spatiald
############################################################################
#
# For exercises, set your redteam share/setips server (mostly likely, Git Gogs) below
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

scriptVersion=3.0e

# CHANGE THESE for every exercise (if needed)
_defaultMTU=1500 # IO Range requires 1300, normal networks are 1500
_internet="" # "0"=Offline, "1"=Online, ""=(ie Blank) Force ask
## Redteam Share IP info and user
_redteamShareAuth="1" # "0"=No user auth, "1"=Use user auth
_redteamShare="" #e.g. 192.168.1.1 or share.com/remote.php/webdav/software where the Red Team software repo is located
_redteamShareUser="opfor" # Redteam share user
## setips.sh script IP info and user
_redteamGogsAuth="0" # "0"=No user auth, "1"=Use user auth
_redteamGogs="10.30.192.2" # Redteam Gogs (Github) address
## Software locations
_cobaltstrikeDir="/redteam/exploitation/cobaltstrike" # Cobaltstrike folder
_c2profilesDir="/redteam/git-pulls/Malleable-C2-Profiles" # Cobaltstrike C2 Profiles folder
_veilDir="/redteam/avevasion/Veil" # Veil folder
_empireDir="/redteam/git-pulls/Empire" # Empire folder
_powersploitDir="/redteam/git-pulls/PowerSploit" # Powersploit folder

# OPTIONAL setup variables (NOT normally changed)
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
setipsFolder="$HOME/setips-files" # Main setips data folder
setipsGitFolder="$HOME/setips" # Cloned Gogs repo for setips
configFile="$setipsFolder/setips.conf"
defaultMTU="$_defaultMTU" # Normal is 1500; exercises are typically 1280 or 900
internet="$_internet" # "0"=Offline, "1"=Online, ""=(ie Blank) Force ask
downloadSoftware="1" # "O"=Do not download offline software, "1"=Always download, ""=(ie Blank) Force ask
localSoftwareDirPath="/root"
localsoftwareDirName="software"
localSoftwareDir="$localSoftwareDirPath/$localsoftwareDirName" # Location where you want your downloaded software located
cobaltstrikeDir="$_cobaltstrikeDir" # Cobaltstrike folder
c2profilesDir="$_c2profilesDir" # Cobaltstrike C2 Profiles folder
veilDir="$_veilDir" # Veil folder
empireDir="$_empireDir" # Empire folder
powersploitDir="$_powersploitDir" # Powersploit folder
redteamShareAuth="$_redteamShareAuth" # "0"=No user auth, "1"=Use user auth
redteamShare="$_redteamShare" #e.g. 192.168.1.1 or share.com/remote.php/webdav/software where the Red Team software repo is located
redteamShareUser="$_redteamShareUser" # Redteam share user
redteamGogsAuth="$_redteamGogsAuth" # "0"=No user auth, "1"=Use user auth
redteamGogs="$_redteamGogs" # Redteam wiki full web address
redteamPathToUpdateSetips="linux/setips.sh" # Path on Redteam wiki to retrieve setips.sh script
redteamPathToUpdateSetipsBeta="linux/setips-beta.sh" # Path on Redteam wiki to retrieve setips.sh beta script
setipsUpdateFileDownloadLocation="$HOME/setips.sh" # Path to setips.sh script download location

# Print version only, if requested
if [[ $1 == "--version" ]]; then
	echo $scriptVersion
	exit 0
fi

#stty sane # Fix backspace
trap cleanup EXIT # Cleanup if script exits for any reason

buildSoftwareList(){
	cat > $localSoftwareDir/software.lst << 'EOF'
sublime32.deb
sublime64.deb
cobaltstrike
c2profiles
veil
powershellempire
powersploit
EOF
}

createConfig(){
	cat > $setipsFolder/setips.conf << 'EOF'
# Setips config file
# Add custom variables here and they will supercede the default ones
EOF
}

### DO NOT CHANGE the following
offlineServer(){
	if [[ $redteamShareAuth == 1 ]]; then
		offlineDownloadServer="wget --http-user=\"$redteamShareUser\" --http-password=\"$redteamSharePassword\" --progress=bar -c -nH -r --no-parent -e robots=off --reject "index.html*" http://$redteamShare/software/"
	else
		offlineDownloadServer="$(wget --progress=bar -c -nH -r --no-parent -e robots=off --reject "index.html*" http://$redteamShare/software/)"
	fi
}
os="$(awk -F '=' '/^ID=/ {print $2}' /etc/os-release 2>&-)"
osIssue="$(cat /etc/issue|awk -F '\' '{ print $1 }')"
osVersion=$(awk -F '=' '/VERSION_ID=/ {print $2}' /etc/os-release 2>&-)
osFullVersion=$(awk -F '=' '/VERSION=/ {print $2}' /etc/os-release 2>&-)
currentDateTime=$(date +"%Y%b%d-%H%M")
#currentgw=$(route -n|grep eth0| head -n 1|cut -d"." -f4-7|cut -d" " -f10)
ipsSaved="$setipsFolder/ips-saved.txt" # Save file for restoring IPs
ipsArchive="$setipsFolder/ips-archive.txt" # IP archive listed by date/time for reference during exercises
pivotRulesBackup="$setipsFolder/pivotRules"
iptablesBackup="$setipsFolder/iptables"
iptablesBackupFile="iptables-$currentDateTime"
subintsBackup="$setipsFolder/subints"
downloadError="0"
counter=0
ifconfig=$(which ifconfig)
fping=$(which fping)
ping=$(which ping)
ipcalc=$(which ipcalc)
iptables=$(which iptables)

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
}

offlineVariables(){
	socatDownload="apt-get -y install socat"
	cobaltstrikeDownload="unzip -u $localSoftwareDir/cobaltstrike.zip -d $cobaltstrikeDir"
	c2profilesDownload="unzip -u $localSoftwareDir/c2profiles.zip -d $c2profilesDir"
	veilDownload="unzip -u $localSoftwareDir/veil.zip -d $veilDir"
	empireDownload="unzip -u $localSoftwareDir/powershellempire.zip -d $empireDir"
	powersploitDownload="unzip -u $localSoftwareDir/powersploit.zip -d $powersploitDir"
	sublime32Download="$localSoftwareDir/sublime32.deb"
	sublime64Download="$localSoftwareDir/sublime64.deb"
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
	# Add functions here
	exit 1
}

cleanup(){
	# kill $! # Kills the last run background process
	trap 'kill $1' SIGTERM
	# Remove clear screen commands from log file <-- created by the Veil scripts
	sed -i '/=======/d' $setipsFolder/setips.log

	# # Check /etc/rc.local for the execute bit
	# chmod +x /etc/rc.local
	# rm -f /tmp/tmp.*
	#stty sane
	echo; exit $?
}

osCheck(){
	if [[ -z "$os" ]] || [[ -z "$osVersion" ]] || [[ -z "$osIssue" ]]; then
	  printError "Internal issue. Couldn't detect OS information."
	elif [[ "$os" == "kali" ]]; then
	  printGood "Kali Linux ${osVersion} $(uname -m) Detected."
	elif [[ "$os" == "ubuntu" ]]; then
	  osVersion=$(awk -F '["=]' '/^VERSION_ID=/ {print $3}' /etc/os-release 2>&- | cut -d'.' -f1)
	  printGood "Ubuntu ${osFullVersion} $(uname -m) Detected."
	elif [[ "$os" == "debian" ]]; then
	  printGood "Debian ${osVersion} $(uname -m) Detected."
	else
	  printGood "$(echo $osIssue)"
	fi
}

opMode(){
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

collectInfo(){
	# Collect missing information
	if [[ ! -f $setipsFolder/mtu.current ]]; then
		echo; printStatus "Help me Obi Wan...I am missing some information."
		whatMTU
	fi
	if [[ ! -f $setipsFolder/subnet.current ]]; then
		whatInterface
		currentCoreIP=$(ip address show $ethInt | grep "inet" | grep -v "inet6" | awk '{ print $2 }' | cut -d/ -f1)
		currentCoreNetmask=$(ip address show $ethInt | grep "inet" | grep -v "inet6" | awk '{ print $2 }' | cut -d/ -f2)
		if [[ $ipcalc ]]; then
			$ipcalc $currentCoreIP/$currentCoreNetmask | grep Netmask | cut -d" " -f6 > $setipsFolder/subnet.current
		elif [[ -z $currentCoreNetmask ]]; then
			echo; printStatus "The force is not with me...I can't figure out the CIDR you are on."
			printQuestion "What is the CIDR of the subnet you are on (ie 16 for 255.255.0.0)? "; read subnet
			echo $subnet > $setipsFolder/subnet.current
		else
			echo; printStatus "Current netmask:  $currentCoreNetmask"
			echo $currentCoreNetmask > $setipsFolder/subnet.current
		fi
	fi
}

downloadOfflineSoftwareRepo(){
	downloadError=0
	# If OFFLINE, download software from exercise repo
	if [[ $internet == 0 ]] && [[ $downloadSoftware == "" || $downloadSoftware == "1" ]]; then
		echo; printQuestion "For offline exercises, an offline software repository is usually available."
		echo "Do you want to download/update your offline software repository? (y/N) "; read REPLY
		if [[ $REPLY =~ ^[Yy]$ ]]; then
			echo; printStatus "Checking for offline software updates."
			if [[ $redteamShareAuth == 1 ]]; then
				echo; printQuestion "What is the password to the redteam network share (press enter if blank)?"; read -s redteamSharePassword
			fi
			echo $redteamShare
			if [[ -z $redteamShare ]]; then
			echo; printQuestion "What is the IP/domain for the local server software repository?"; read redteamShare
			sed -i 's/^redteamShare="" #/redteamShare="'$redteamShare'" #/' $setipsFolder/setips.conf
			fi
			offlineServer
			cd $localSoftwareDirPath
			exec &> /dev/tty
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
		mkdir -p $veilDir
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
		mkdir -p $empireDir
		$empireDownload
		commandStatus
		cd $empireDir/setup
		./reset.sh
		./install.sh
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
		mkdir -p $powersploitDir
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
		mkdir -p $c2profilesDir
		$c2profilesDownload
		commandStatus
	else
		printGood "Cobalstrike c2profiles folder exists, moving on."
	fi

	# Download Cobalt Strike
	echo; printStatus "INSTALLING Cobaltstrike"
	if [[ $internet == 0 ]] && [[ ! -f $cobaltstrikeDir/teamserver ]]; then
		printError "Cobaltstrike folder does not exist."
		mkdir -p $cobaltstrikeDir
		$cobaltstrikeDownload
		commandStatus
	fi
	if [[ -f "$cobaltstrikeDir/teamserver" ]]; then
		printGood "Cobalstrike folder exists, moving on."
	else
		printError "Cobalt Strike folder does not exist and my powers are not strong enough to download it for you."
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
	ip address show | grep secondary | awk '{ print $8 }'
}

# Find the core IP address in use
listCoreInterfaces(){
	echo; printStatus "Core IP addresses on this system:"
	ip address show | grep "inet" | grep -v "inet6" | grep -v "secondary" | awk '{ print $2, $7 }' | sed '/127.0/d'
}

# Show only the core IP address (for setupteamserver function)
listCoreIPAddr(){
	echo "$(ip address show $ethInt | grep "inet" | grep -v "inet6" | grep -v "secondary" | awk '{ print $2 }' | cut -d/ -f1)"
}

# Ask which ethernet port you want to create subinterfaces for
whatInterface(){
	#stty sane
#	ints=$(ip address show | grep "inet" | grep -v "inet6" | grep -v "secondary" | awk '{ print $2, $7 }' | grep -v "127.0.0.1/8" | awk '{ print $2 }')
	ints=$(ip address show | grep state | grep -v LOOPBACK | awk '{ print $2 }' | cut -d: -f1)
	echo; printQuestion "What ethernet interface?"
	select int in $ints; do 
		export ethInt=$int
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
	# Check if in the available list (test 2)
	if [[ $(cat $tmpUsedIPs | grep $availIP) ]]; then
		return 1
	else
		echo $availIP >> $tmpUsedIPs
		echo $availIP/$subnet >> $tmpIPs
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

# What MTU
whatMTU(){
	# MTU
	if [[ -f $setipsFolder/mtu.current ]]; then
		echo; printStatus "Your current mtu is:  $(cat $setipsFolder/mtu.current)";
		mtu=$(cat $setipsFolder/mtu.current)
		printQuestion "Do you want to change your mtu? (y/N)"; read REPLY
		if [[ $REPLY =~ ^[Yy]$ ]]; then
			echo; printQuestion "What is your desired MTU setting (current default is $defaultMTU)?"; read mtu || return
		else
			printError "MTU not changed."
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

# Add dual gateways
dualGateways(){
	echo; printStatus "Dual Gateway Setup"
	listCoreInterfaces
	echo; echo "Enter network info using the following example:"
	echo "<ip> <cidr> <network-address> <gateway-ip>"
	echo "192.168.100.5 24 192.168.100.0 192.168.100.1"
	ethIntList=$(listInts)
	echo; printQuestion "What is Network 1's ethernet interface?"
	select int in $ethIntList; do
		network1EthInt=$int
		break
	done
	while :; do
		echo; printQuestion "What is Network 1's info:"; read network1
		if [[ "$network1" =~ ^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})[[:blank:]]([0-9]{,2})[[:blank:]]([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})[[:blank:]]([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$ ]]; then
			break
		else
			echo; printError "You entered the required information incorrectly."
			echo "Please enter Network 1's info again with space separation (for example, enter <ip> <cidr> <network-address> <gateway-ip)"
		fi
	done
	ethIntList=$(listInts)
	echo; printQuestion "What is Network 2's ethernet interface?"
	select int in $ethIntList; do
		network2EthInt=$int
		break
	done
	while :; do
		echo; printQuestion "What is Network 2's info:"; read network2
		if [[ "$network2" =~ ^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})[[:blank:]]([0-9]{,2})[[:blank:]]([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})[[:blank:]]([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$ ]]; then
			break
		else
			echo; printError "You entered the required information incorrectly."
			echo "Please enter Network 2's info again with space separation (for example, enter <ip> <cidr> <network-address> <gateway-ip)"
		fi
	done

	network1IP="$(echo $network1 | awk -F" " '{ print $1 }')"
	network1CIDR="$(echo $network1 | awk -F" " '{ print $2 }')"
	network1Network="$(echo $network1 | awk -F" " '{ print $3 }')"
	network1Gateway="$(echo $network1 | awk -F" " '{ print $4 }')"
	network2IP="$(echo $network2 | awk -F" " '{ print $1 }')"
	network2CIDR="$(echo $network2 | awk -F" " '{ print $2 }')"
	network2Network="$(echo $network2 | awk -F" " '{ print $3 }')"
	network2Gateway="$(echo $network2 | awk -F" " '{ print $4 }')"

	echo; printStatus "Using the following information to setup dual gateways:"
	echo "Network1 IP:  $network1IP"
	echo "Network1 CIDR:  $network1CIDR"
	echo "Network1 Network:  $network1Network"
	echo "Network1 Gateway:  $network1Gateway"
	echo "- - - - -"
	echo "Network2 IP:  $network2IP"
	echo "Network2 CIDR:  $network2CIDR"
	echo "Network2 Network:  $network2Network"
	echo "Network2 Gateway:  $network2Gateway"

	echo; printQuestion "Are you ready to continue? (y/N) "; read REPLY
	if [[ $REPLY =~ ^[Yy]$ ]]; then
		echo; printStatus "Setting up networks..."

		echo "1 network1" >> /etc/iproute2/rt_tables
		echo "2 network2" >> /etc/iproute2/rt_tables

		ifconfig $network1EthInt $network1IP/$network1CIDR
		ifconfig $network2EthInt $network2IP/$network2CIDR

		ip route add $network1Network/$network1CIDR dev $network1EthInt table network1
		ip route add $network2Network/$network2CIDR dev $network2EthInt table network2

		ip route add default via $network1Gateway dev $network1EthInt table network1
		ip route add default via $network2Gateway dev $network2EthInt table network2

		ip rule add from $network1IP/32 table network1
		ip rule add from $network2IP/32 table network2

		echo; printGood "Done."
	else
		echo; printError "User requested to exit dual gateway setup."
	fi
}

# Remove all subinterfaces
removeSubInts(){
	tmp=`mktemp`
	rm -f $tmp
	ip addr show $ethInt | grep inet | grep -v inet6 | awk '{ print $8 }' | tail -n +2 >> $tmp
	while IFS= read sub; do
	$ifconfig $sub down > /dev/null 2>&1
	done < "$tmp"

	if [[ -s $tmp ]]; then
		echo; printStatus "Removed subinterface(s):"
		cat $tmp
	fi
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
#	rm -f /tmp/ips.txt; touch /tmp/ips.txt
#	rm -f /tmp/usedips.txt; touch /tmp/usedips.txt
	# MTU
	whatMTU
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
		echo; printQuestion "What is the CIDR of the subnet you are on (ie 8 for 255.0.0.0)?"; read subnet

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
		echo; printQuestion "What is the CIDR of the subnet you are on (ie 16 for a 255.255.0.0)?"; read subnet

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
		echo; printQuestion "What is the CIDR of the subnet you are on (ie 24 for a 255.255.255.0)?"; read subnet

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

	# Add subnet to backup file
	echo $subnet > $setipsFolder/subnet.current
	echo; printQuestion "What subinterface number would you like to start assigning ips to?"; read subNum; subNum=$((subNum-1))
	while IFS= read ip; do
		subNum=$((subNum+1))
		$ifconfig $ethInt:$subNum $ip mtu $mtu
	done < "$tmpIPs"
	printGood "Done."; echo
	saveCurrentIPs

	# Append ips to running log
	echo -e "\n$(date)" >> $ipsArchive
	listIPs-oneline >> $ipsArchive

	printGood "Your IP settings were saved to three files:";
	echo "   - $ipsSaved -> restore them with this program";
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
	echo; printQuestion "What is the full path to the setips save file (default is $ipsSaved)?"; read savefile || return
	if [[ -z ${savefile:+x} ]]; then
		printGood "Restoring from $ipsSaved"
		savefile=$ipsSaved
	else
		printGood "Restoring from $savefile"
	fi
	gatewayip=`route -n|grep $ethInt|grep 0.0.0.0|grep G|head -n 1|cut -d"." -f4-7|cut -d" " -f10`
	echo; printStatus "Your current gateway is set to:  $gatewayip"
	echo; printQuestion "Do you want to change your gateway? (y/N) "; read REPLY
	if [[ $REPLY =~ ^[Yy]$ ]]; then
		echo; printQuestion "What is the IP of the gateway?"; read gatewayip || return
	fi
	# Add subinterfaces
	while IFS= read subip; do
		$ifconfig $subip
	done < "$savefile"
	# Add new gw
	route add default gw $gatewayip
}

# Set default gateway
setGateway(){
	echo; printStatus "Current route table:"
	route -n
	currentgw=`route -n|grep $ethInt|grep 0.0.0.0|grep G|head -n 1|cut -d"." -f4-7|cut -d" " -f10`
	gatewayip=$currentgw
	if [[ -z ${currentgw:+x} ]]; then
		echo; printError "You do not have a default gateway set."
	else
		echo; printStatus "Your current gateway is:  $gatewayip"
	fi
	echo; printQuestion "Do you want to change your gateway? (y/N) "; read REPLY
	if [[ $REPLY =~ ^[Yy]$ ]]; then
		echo; printQuestion "What is the IP of the gateway?"; read gatewayip || return
		# Remove current gw
		route del default gw $currentgw > /dev/null 2>&1
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
	echo; printQuestion "Do you want to change your DNS servers? (y/N) "; read REPLY
	if [[ $REPLY =~ ^[Yy]$ ]]; then
		echo; printQuestion "What are the DNS server IPs (space separated)?"; read dnsips || return
		rm /etc/resolv.conf
		IFS=' '; set -f
		eval "array=(\$dnsips)"
		for x in "${array[@]}"; do echo "nameserver $x" >> /etc/resolv.conf; echo; done
		echo; printGood "Your DNS settings were updated as follows:"
		cat /etc/resolv.conf; echo
	else
		echo; printError "DNS not changed."
	fi
}

# Save current IPs for restore
saveCurrentIPs(){
	# Save ips set for future restore by this script
	ip address show |grep "inet" |grep -v "inet6"|awk '{ print $2, $7, $8 }' | sed 's/ secondary//g' | grep -v "127.0.0.1/8" | while IFS=" " read a b; do echo "$b $a mtu $mtu"; done > $ipsSaved
}

# Auto set subinterface IPs on system start/reboot
autoSetIPsOnStart(){
	rm /root/setips-atstart.sh > /dev/null 2>&1 # check for old version
	saveCurrentIPs
	removeSetIPsOnStart > /dev/null
	gatewayIP=$(route -n|grep 0.0.0.0|grep G|head -n 1|cut -d"." -f4-7|cut -d" " -f10)
	if [[ -z ${gatewayIP:+x} ]]; then setGateway; fi
	sed "s,%SETIPSFOLDER%,$setipsFolder,g;s,%GATEWAYIP%,$gatewayIP,g" >$setipsFolder/setips-atboot.sh << 'EOF'
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
	# rc.local cleanup
	# sed -i '$e echo "#setips - Auto-set IPs on startup using setips-atboot.sh script"' /etc/rc.local
	# sed -i '$e echo "'$setipsFolder'/setips-atboot.sh&"' /etc/rc.local
	# awk 'BEGIN{OFS=FS="/"} $1~/$setipsFolder/ {$1="'$setipsFolder'";}1' /etc/rc.local > /tmp/rclocal.tmp; mv /tmp/rclocal.tmp /etc/rc.local
	cat > /etc/systemd/system/setips_atboot.service << EOF
[Unit]
Description="Auto-set IPs on startup using setips-atboot.sh script"
After=network.target

[Service]
ExecStart=$setipsFolder/setips-atboot.sh

[Install]
WantedBy=multi-user.target
EOF
	systemctl enable setips_atboot.service
}

# Remove systemd unit file for setting IPs at boot
removeSetIPsOnStart(){
	# rc.local delete
	# sed -i '/setips-atboot/d' /etc/rc.local
	# rm -f /root/setips-atboot.sh
	systemctl disable setips_atboot.service
}

# Change /etc/ssh/sshd_config conifguration for root to only login "without-password" to "yes"
checkSSH(){
	if cat /etc/ssh/sshd_config | grep '#PermitRootLogin'; then
		echo; printError "I have to fix your sshd_config file to allow login with password."
		sed -i 's/.*PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config
		echo; printStatus "Checking SSH service is enabled and accepts passwords."
		systemctl restart ssh
		systemctl enable ssh
	fi
}

# Check for and (if exists) disable netplan.io
checkNetplan(){
	if [[ ! -s /run/network/ifstate ]]; then
		apt update; apt install ifupdown
		ifdown --force enp0s3 lo && ifup -a
		systemctl unmask networking
		systemctl enable networking
		systemctl restart networking
		systemctl stop systemd-networkd.socket systemd-networkd networkd-dispatcher systemd-networkd-wait-online
		systemctl disable systemd-networkd.socket systemd-networkd networkd-dispatcher systemd-networkd-wait-online
		systemctl mask systemd-networkd.socket systemd-networkd networkd-dispatcher systemd-networkd-wait-online
		apt-get --assume-yes purge nplan netplan.io
		ifup enp0s3
		printGood "Netplan is in use and will be removed; reverted to ifupdown for networking."
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
	echo; printGood "Created systemd unit file for starting SOCKS proxy"
}

setupStaticIP(){
	configureStaticIP(){
		configureStaticIP=1
		listCoreInterfaces
		while [[ $configureStaticIP == 1 ]]; do
			whatMTU
			echo; printQuestion "What IP do you want to set?"; read ip
			echo; printQuestion "What is the CIDR of the subnet you are on (ie 16 for 255.255.0.0)?"; read subnet
			# Configure address on interface
			$ifconfig $ethInt up
			$ifconfig $ethInt $ip/$subnet mtu $mtu
			# Add subnet to backup file
			echo $subnet > $setipsFolder/subnet.current
			echo; printGood "Your $ethInt interface is setup:"
			echo; listIPs
			if [[ ! $(cat /etc/network/interfaces | grep gateway) ]]; then
				echo; printQuestion "Do you want to setup a default gateway and DNS? (y/N)"; read REPLY
				if [[ $REPLY =~ ^[Yy]$ ]]; then
					setGateway
					setDNS
				fi
			fi
			# Configure /etc/network/interfaces file
			if [[ ! $(cat /etc/network/interfaces|grep setips.sh) ]]; then
				echo "# This config was auto-generated using the setips.sh script" > /etc/network/interfaces
				echo "auto lo" >> /etc/network/interfaces
				echo "iface lo inet loopback" >> /etc/network/interfaces
			fi
			sed -i '/'$ethInt' START/,/'$ethInt' STOP/d' /etc/network/interfaces
			echo "# $ethInt START" >> /etc/network/interfaces
			echo "auto $ethInt" >> /etc/network/interfaces
			echo "iface $ethInt inet static" >> /etc/network/interfaces
			echo "address $ip" >> /etc/network/interfaces
			netmask=$($ifconfig $ethInt | grep "inet" | head -n 1 | awk '{ print $4 }' | cut -d":" -f2)
			echo "netmask $netmask" >> /etc/network/interfaces
			if [[ ! $(cat /etc/network/interfaces | grep gateway) ]]; then
				gatewayip=`route -n|grep $ethInt|grep 0.0.0.0|grep G|head -n 1|cut -d"." -f4-7|cut -d" " -f10`
				if [[ $gatewayip ]]; then echo "gateway $gatewayip" >> /etc/network/interfaces; fi
				dns=`cat /etc/resolv.conf | grep nameserver | awk '{ print $2}' | awk '{printf "%s ",$0} END {print ""}'`
				if [[ $dns ]]; then echo "dns-nameservers $dns" >> /etc/network/interfaces; fi
			fi
			echo "mtu $mtu" >> /etc/network/interfaces
			echo "# $ethInt STOP" >> /etc/network/interfaces
			echo; printQuestion "Do you want to setup another CORE interface with a static IP? (y/N)"; read REPLY
			if [[ $REPLY =~ ^[Yy]$ ]]; then
				configureStaticIP=1
				listCoreInterfaces
				whatInterface
			else
				configureStaticIP=0
			fi
			echo
		done
	}
	if [[ $(cat /etc/network/interfaces|grep setips.sh) ]] && [[ $(cat /etc/network/interfaces|grep "# $ethInt START") ]]; then
		echo; printQuestion "You have already setup a static IP with this script; do you want to continue? (y/N)"; read REPLY
		if [[ $REPLY =~ ^[Yy]$ ]]; then
			checkNetplan
			configureStaticIP
		fi
	else
		checkNetplan
		configureStaticIP
	fi
}

# Display SOCKS proxies
displayProxies(){
	ip address show $ethInt |grep "inet" |grep -v "inet6"|awk '{ print $2 }'|cut -d/ -f1 |  grep -v "127.0.0.1" | tail -n +2 | awk '{printf "%s\n",$0} END {print ""}' | sed '/^$/d' | awk -F:: '{ print "socks4 " $NF }' | awk '{ print $0 "'" $proxyport"'"}'
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
	if netstat -antp | grep -v grep | grep ::: | grep -v sshd | grep ssh > /dev/null; then
		echo; printStatus "You currently have proxies running on the following ports:"
		netstat -antp | grep -v grep | grep ::: | grep -v sshd | grep ssh
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
		if netstat -antp | grep "0.0.0.0:$proxyport "; then
			echo; printError "Something is already listening on that port, please try a different port."
			echo; netstat -antp | grep ":$proxyport "
			echo; printQuestion "What *PORT* do you want to use for your proxy?"; read proxyport
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

	checkSSH

	echo; printStatus "Setting up the SSH SOCKS proxy...please wait..."
	sshPort=`netstat -antp | grep "sshd" | head -n 1 | cut -d":" -f2| cut -d" " -f1`
	while :; do
		(sleep 2; echo $password; sleep 2; echo ""; sleep 1) | socat - EXEC:"screen -S ssh ssh -o StrictHostKeyChecking=no -gD$proxyport -p $sshPort -l root localhost",pty,setsid,ctty > /dev/null
		export autostartSOCKS="(sleep 2; echo $password; sleep 2; echo \"\"; sleep 1) | socat - EXEC:'screen -S ssh ssh -o StrictHostKeyChecking=no -p $sshPort -gD\"$proxyport\" -l root localhost',pty,setsid,ctty"
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
	displayProxies

	# Ask if you want to start the SOCKS proxy automatically on boot (careful, this will put your root password in a systemd unit file)
	echo; printQuestion "Would you like the SOCKS proxy to start on reboot? (y/N)"; read REPLY
	if [[ $REPLY =~ ^[Yy]$ ]]; then
		autoStartSOCKSProxy
	# rc.local delete
	# else
		# rm -f /tmp/ssh.tmp
	fi
}

# Stop SOCKS proxy
stopSOCKS(){
	screen -ls |grep ssh|cut -d"." -f1|cut -b2- > /tmp/socks.tmp
	while read p; do screen -X -S $p.ssh kill; done < /tmp/socks.tmp
	rm -f /tmp/socks.tmp
	# rc.local delete
	# sed -i '/screen/d' /etc/rc.local
	systemctl disable autostart_socks.service
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

iptablesToggleRandomSource(){
	tmp=`mktemp`
	# Check if current iptables is set to random source address
	if [[ $(iptables-save | grep "SNAT") ]]; then randomIPs=1; fi
	if [[ $randomIPs == 1 ]]; then 
		# Save off current iptables, delete all SNAT rules with the word "statistic", and restore the table
		iptables-save > $tmp; sed -i "/SNAT/d" $tmp; iptables-restore < $tmp; rm $tmp
		echo; printGood "Turned OFF outgoing source IP randomization."
	else
		# Randomize source IPs on all outgoing packets
		randomizePivotIP
		echo; printGood "Turned ** ON ** outgoing source IP randomization."
	fi
}

# Create systemd unit file to restore iptable rules on reboot
autoStartIPTables(){
	# rc.local delete
	# sed -i '/iptable*/d' /etc/rc.local
	# sed -i '$e echo "#IPTables - Restore iptable rules on reboot"' /etc/rc.local
	# sed -i '$e echo "iptables-restore < PATHTO"' /etc/rc.local
	# awk 'BEGIN{OFS=FS=" "} $1~/iptables-restore/ {$3="'$setipsFolder'/iptables.current";}1' /etc/rc.local > /tmp/iptables.tmp; mv /tmp/iptables.tmp /etc/rc.local
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
	# rc.local delete
	# sed -i '/iptable/d' /etc/rc.local
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
				sed -i '/DNAT/d' iptables.tmp
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
			redirSetipsServer=$(cat $configFile |grep ^redteamGogs|cut -d"\"" -f2)
			echo; printQuestion "What is the IP of the redirector that you want to setup? "; read redirIP
			echo; printStatus "Pinging target for viability..."
			$ping -c 1 $redirIP > /dev/null
			if [[ $? == 0 ]]; then
				printGood "Target is alive."
				sshBytes=$(cat /root/.ssh/id_rsa.pub | cut -d" " -f2| tail -c 6)
				echo; printStatus "Here are the last 5 characters of your public key:  $sshBytes"
				printStatus "Checking for your SSH key on the target system."
				ssh root@$redirIP "sed -i '/UseDNS/d' /etc/ssh/sshd_config; echo 'UseDNS no' >> /etc/ssh/sshd_config; service ssh restart; grep $sshBytes /root/.ssh/authorized_keys > /dev/null"
				if [[ $? -gt 0 ]]; then
					echo; printStatus "SSH Key not found on target system; uploading..."
					ssh-copy-id root@$redirIP
				else
					printGood "SSH key found."
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
		if [[ $(netstat -antp | grep "0.0.0.0:$socatport ") || $(netstat -antp | grep "127.0.0.1:$socatport ") ]]; then
			echo; printError "Something is already listening on that port, please try a different port."
			echo; netstat -antp | grep ":$socatport "
			echo; printQuestion "What port do you want to pivot (i.e. the one socat will listen for)?"; read socatport
		else
			break
		fi
	done
	echo; printQuestion "What is the redteam *IP* the pivot redirects incoming traffic to?"; read redteamip
	echo; printQuestion "What is the redteam *PORT* the pivot redirects incoming traffic to?"; read redteamport
	socat -d -d -d -lf $setipsFolder/socat.log TCP-LISTEN:$socatport,reuseaddr,fork,su=nobody TCP:$redteamip:$redteamport&
	disown
	if [[ $(netstat -antp | grep -v grep | grep socat | grep $socatport | wc -l) -ge "1" ]]; then
		echo; printGood "SUCCESS! Socat pivot setup; logging to $setipsFolder/socat.log"
		netstat -antp | grep socat
	else
		echo; printError "FAIL...looks like the socat pivot didn't setup correctly, check $setipsFolder/socat.log for errors."
	fi
}

# Stop SOCKS proxy
stopSocatPivot(){
	tmp=`mktemp`
	netstat -antp | grep socat | awk '{ print $7 }' | cut -d/ -f1 > $tmp
	while read p; do kill -9 $p; done < $tmp
	rm -f $tmp
}

# Setup Cobaltstrike Teamserver
setupTeamserver(){
	# Check for installed software
	installAdditionalSoftware

	# Startup teamserver
	coreIPAddr=$(listCoreIPAddr)
	echo; printError "What teamserver password would you like to use?"; read teamPass

	# Ask if you will use a c2profile with the teamserver
	echo; printQuestion "Would you like to use a C2 profile?"
	select profile in "Yes-from-Github" "Yes-Custom" "No-Profile"; do
		case $profile in
			Yes-from-Github )
				printStatus "Checking for profiles here:  $c2profilesDir"
				if [[ ! -d $c2profilesDir ]]; then 
					printError "That directory does not exist; check for it and try again."
					echo; exit 1
				fi
				c2profile=""
				cd $c2profilesDir; ls -R *; cd
				echo; printError "What c2profile would you like to use? (enter just the name)"; read c2profile
				c2profile=`find $c2profilesDir/ -name $c2profile`
				break
			;;
			Yes-Custom )
				c2profile=""
				echo; printQuestion "What is the full path to the C2 profile (eg /root/amazon.profile)?"; read c2profile || return
				while :; do
					if [[ ! -f "$c2profile" ]]; then
						echo; printError "I could not find the C2 profile you provided; please try again."
						printQuestion "What is the full path to the C2 profile (eg /root/amazon.profile)?"; read c2profile || return
					else
						break
					fi
				done
				break
			;;
			No-Profile )
				break
			;;
		esac
	done

	if ps aux | grep "/bin/bash ./teamserver" | grep -v grep > /dev/null; then
		echo; printStatus "You currently have a teamserver running:"
		ps aux | grep "/bin/bash ./teamserver" | grep -v grep
		echo; printQuestion "Do you want to stop it and start a new one? (y/N)"; read REPLY
		if [[ $REPLY =~ ^[Yy]$ ]]; then
			echo; printStatus "Killing previous teamserver instance."
			screen -X -S teamserver quit
		else
			printError "You can only have one instance of teamserver running; exiting."
			echo; exit 1
		fi
	fi
	echo; printStatus "The teamserver is starting in the background via screen..."
	echo "Connect by typing:  screen -r"
	echo "Disconnect from screen:  Ctrl-A, then D"
	cd $cobaltstrikeDir; screen -dmS teamserver ./teamserver $coreIPAddr $teamPass $c2profile
	echo; screen -ls
	if ps aux | grep "/bin/bash ./teamserver" | grep -v grep > /dev/null; then
		printGood "SUCCESS...Teamserver started."
		ps aux | grep "/bin/bash ./teamserver" | grep -v grep
		break
	else
		echo; printError "FAIL...looks like the teamserver didn't start correctly; try these possible fixes:"
		echo '- Type "screen -r" from the command line to see if the screened session has any errors.  Once in screen, type "Ctrl-D" to get back to original command line.'
		echo "- Try typing this command FROM the cobaltstrike folder and check for errrors:"
		echo "	./teamserver $coreIPAddr $teamPass $c2profile"
		echo; exit 1
	fi
}

# Install highly recommended tools
installRecommendedTools(){
	downloadError=0
	echo; printStatus "Updating package repository."
	apt-get update
	echo; printStatus "Attempting to install:  unzip, fping, ipcalc, socat, libreadline5, screen, traceroute, nmap"
	apt-get -y install unzip fping ipcalc socat libreadline5 screen traceroute nmap
	commandStatus
	if [[ $downloadError == 1 ]]; then
		echo; printError "Something went wrong...one or more downloads didn't complete successfully."
	else
		echo; printGood "Done."
	fi
}

# Install redirector tools
installRedirTools(){
	downloadError=0
	echo; printStatus "Updating package repository."
	apt-get update
	apt-get autoremove
	echo; printStatus "Attempting to install:  unzip fping ipcalc socat libreadline5 screen traceroute nmap proxychains vsftpd apache2 php"
	apt-get -y install unzip fping ipcalc socat libreadline5 screen traceroute nmap proxychains vsftpd apache2 php libapache2-mod-php7.0
	commandStatus
	systemctl stop apache2
	systemctl stop vsftpd
	update-rc.d apache2 disable
	update-rc.d vsftpd disable
	# Add vsftpd config files
	mkdir /var/ftp/upload
	chown ftp:ftp /var/ftp/upload
	mkdir /etc/vsftpd
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
	tmpDNAT=`mktemp`
	# Clean duplicate items that are next to each other; enable ipv4/ipv6 forwarding; remove old MASQUERADE method of "proxying"
	# older forwarding technique
	echo 1 > /proc/sys/net/ipv4/ip_forward
	# newer forwarding technique
	sed -i '/net.ipv4.ip_forward=1/s/^#//g' /etc/sysctl.conf
	sed -i '/net.ipv6.conf.all.forwarding=1/s/^#//g' /etc/sysctl.conf
	sysctl -p
	sysctl --system
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
	sed -i '/^internet/d' $setipsFolder/setips.conf
	echo 'internet="1"' >> $setipsFolder/setips.conf
	internet="1"
}

setOffline(){
	sed -i '/^internet/d' $setipsFolder/setips.conf
	echo 'internet="0"' >> $setipsFolder/setips.conf
	internet="0"
}

setAskEachTime(){
	sed -i '/^internet/d' $setipsFolder/setips.conf
	echo 'internet=""' >> $setipsFolder/setips.conf
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
		echo "[Initial-Kali] persistent static IP, installs core software"
		echo "[Initial-Redirector] persistent static IP"
		echo "[Initial-Teamserver] persistent static IP, teamserver setup"
		echo "[SSH-SOCKS-Proxy] sets up SOCKS proxy on a port"
		echo "[IPTables-Pivot-IPs] redirects redirector IP/Port to target IP/Port"
		echo "[Socat-Pivot] sets up socat listener that redirects to target IP/Port"
		echo "[SublimeText] installs SublimeText"
		echo "[Cobaltstrike...] installs the programs listed"
		echo "[Dual-Gateways] setps up a dual-homed system"
		echo "[Static-IP] persistent static IP"
		echo
		select au in "Initial-Kali" "Initial-Redirector" "Initial-Teamserver" "Remote-Redirector" "Addtl-Redir-Pivot-IPs" "SSH-SOCKS-Proxy" "IPTables-Pivot-IPs" "Socat-Pivot" "SublimeText" "Dual-Gateways" "Static-IP" "Main-Menu"; do
			case $au in
				Initial-Kali)
				echo; printStatus "Setting up a static IP."
				whatInterface
				setupStaticIP
				echo; printStatus "Install local system software repository and installing software."
				#downloadOfflineSoftwareRepo
				if [[ $internet = 1 ]]; then echo; installAdditionalSoftware; installSublime; fi
				echo; printGood "Initial setup completed."
				break
				;;

				Initial-Redirector )
				echo; printStatus "Setting up a static IP."
				whatInterface
				setupStaticIP
				if [[ $internet = 1 ]]; then echo; installRedirTools; fi
				echo; printGood "Redirector setup completed."
				break
				;;

				Initial-Teamserver )
				listCoreInterfaces
				whatInterface
				setupStaticIP
				#downloadOfflineSoftwareRepo
				setupTeamserver
				break
				;;

				Remote-Redirector )
				setupAnotherRedirector
				break
				;;

				Addtl-Redir-Pivot-IPs )
				listCoreInterfaces
				whatInterface
				echo; displayIPTables
				setupIPTablesRedirectorIPs
				autoSetIPsOnStart
				cleanIPTables
				iptables-save |grep -v statistic | iptables-restore
				savePivotRules
				saveIPTables
				break
				;;

				SSH-SOCKS-Proxy )
				listCoreInterfaces
				whatInterface
				checkForSubinterfaces
				autoSetIPsOnStart
				cleanIPTables
				saveIPTables
				setupSOCKS
				break
				;;

				IPTables-Pivot-IPs )
				listCoreInterfaces
				whatInterface
				checkForSubinterfaces
				autoSetIPsOnStart
				echo; displayIPTables
				setupIPTablesPivot
				cleanIPTables
				iptables-save |grep -v statistic | iptables-restore
				saveIPTables
				break
				;;

				Socat-Pivot )
				setupSocatPivot
				break
				;;

				SublimeText )
				installSublime
				break
				;;

				Dual-Gateways )
				dualGateways
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
				listCoreInterfaces
				whatInterface
				addSubInts
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
				listCoreInterfaces
				whatInterface
				removeSubInts
				restoreSubIntsFile
				autoSetIPsOnStart
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
		select ut in "Change-Internet-OpMode" "Set-Gateway" "Set-DNS" "Fix-SSH-Without-Password" "IPTables-show" "IPTables-flush" "IPTables-toggle-random-source-IPs" "IPTables-restore-on-startup" "IPTables-REMOVE-restore-on-startup" "IPs-restore-on-startup" "IPs-REMOVE-restore-on-startup" "SOCAT-Pivots-REMOVE-ALL" "SOCKS-Proxy-setup" "SOCKS-Proxy-REMOVE-ALL" "Install-Recommended-Tools" "Reset-Setips-Config" "Main-Menu"; do
			case $ut in
				Change-Internet-OpMode )
				echo; printStatus "Change Internet OpMode"
				echo "----------------------"
				echo "Persistently changes this script's operational mode (can be changed at any time)."
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
						exit 1
						break
						;;

						Main-Menu )
						break
						;;
					esac
				done
				break
				;;

				IPTables-show )
				displayIPTables
				break
				;;

				IPTables-flush )
				flushIPTables
				echo; printGood "IPTables successfully flushed."
				break
				;;

				IPTables-toggle-random-source-IPs )
				iptablesToggleRandomSource
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

				IPs-restore-on-startup )
				whatInterface
				autoSetIPsOnStart
				echo; printGood "Created systemd unit file to restore IPs on reboot."
				break
				;;

				IPs-REMOVE-restore-on-startup )
				removeSetIPsOnStart
				echo; printGood "Removed systemd unit file to restore IPs on reboot."
				break
				;;

				SOCAT-Pivots-REMOVE-ALL )
				stopSocatPivot
				echo; printGood "All SOCAT pivoting stopped."
				break
				;;

				SOCKS-Proxy-setup )
				setupSOCKS
				echo; printGood "SSH SOCKS Proxy started."
				break
				;;

				SOCKS-Proxy-REMOVE-ALL )
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

				Reset-Setips-Config )
				rm -f $setipsFolder/setips.conf
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

		View-Info )
		echo; printQuestion "What IP format do you want to view?"; echo
		select ex in "Cobaltstrike-Teamserver" "Proxychains" "List-Current-IPs" "List-Previously-Used-IPs" "Show-OFFLINE-Software-Repo-Status" "Main-Menu"; do
			case $ex in
				Cobaltstrike-Teamserver )
				listIPs-oneline
				break
				;;

				Proxychains )
				echo; printQuestion "What *PORT* do you want to use for your proxy?"; read proxyport
				echo; echo "Copy the following to the end of /etc/proxychains.conf"
				displayProxies
				break
				;;

				List-Current-IPs )
				echo; printStatus "CHECK IT OUT -> You can find the save file here:  $ipsSaved"
				listIPs
				break
				;;

				List-Previously-Used-IPs )
				echo; printStatus "CHECK IT OUT -> You can find the archive file here:  $ipsArchive"
				cat $ipsArchive
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
	echo "Usage: [-h] [-i] [-l] [-r] [-a <protocol> <subintip> <subintport> <tgtIP> <tgtPort>]"
	echo "	   [-f <fileName>] [-d <protocol> <subintip> <subintport> <tgtIP> <tgtPort>]"
	echo
}

#### MAIN PROGRAM ####

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
echo; echo "Setips Script - Version $scriptVersion"
printGood "Started:  $(date)"
printGood "Configuration and logging directory:  $setipsFolder"

# ONLY CHANGE the following variables in the config file -> $setipsFolder/setips.conf
# If it doesn't exist, create config file
if [[ ! -f $setipsFolder/setips.conf ]]; then
	createConfig
fi

if [[ ! `grep -v "#Setips config file" $setipsFolder/setips.conf` ]]; then
	createConfig
fi

### Import config file
configFileClean="/tmp/setips.conf"
# check if the file contains something we don't want
if egrep -q -v '^#|^[^ ]*=[^;]*' "$configFile"; then
  echo "Config file is unclean, cleaning it..." >&2
  # filter the original to a new file
  egrep '^#|^[^ ]*=[^;&]*'  "$configFile" > "$configFileClean"
  configFile="$configFileClean"
fi
# now source it, either the original or the filtered variant
source $configFile

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

# Ask to run interface setup or, if setup, collect information
if [[ ! -f $setipsFolder/subnet.current || ! -f $setipsFolder/mtu.current ]]; then
	checkForIP=$(listIPs | wc -l)
	if [[ $checkForIP -ge "1" ]]; then
		echo; printStatus "I need to collect some info since you already have your interface setup."
		collectInfo
	elif [[ $checkForIP == "0" ]]; then
		echo; printStatus "You don't have an IP on any interface, starting initial setup."
		whatInterface
		setupStaticIP
	fi
fi

if [[ $1 == "" || $1 == "--help" ]]; then
	echo; printHelp
else
	IAM=${0##*/} # Short basename
	while getopts ":a:d:f:hilnrstu" opt
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
			echo
			;;
		(i) # Fully interactive mode
			interactiveMode >&2
			;;
		(l) # List current IPTables rules
			displayIPTables >&2
			;;
		(n) # New IPs for redirector (local or remote)
			echo; printGood "Let's setup IPs for a remote redirector."
			if [[ -z $ethInt ]]; then
				whatInterface
			fi
			if [[ ! $(grep START /etc/network/interfaces) ]]; then
				setupStaticIP
			fi
			displayIPTables
			setupIPTablesRedirectorIPs
			autoSetIPsOnStart
			cleanIPTables
			iptables-save |grep -v statistic | iptables-restore
			savePivotRules
			saveIPTables
			printGood "Setup complete."
			;;
		(r) # REPAIR - quick repair; doesn't hurt if run multiple times.
			printGood "Cleaning up/repair the current IPTables ruleset."
			printGood "Saving backup of your IPTables before repair attempt to $iptablesBackup/$iptablesBackupFile"
			iptables-save > $iptablesBackup/$iptablesBackupFile
			cleanIPTables >&2
			iptables-save |grep -v statistic | iptables-restore
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
				ln -s $HOME/setips/setips.sh $HOME/setips.sh
				chmod +x /root/setips/setips.sh
				if [[ -f /root/setips.sh ]]; then echo; printGood "setips.sh downloaded to /root/setips.sh"; fi
			else
				echo; printStatus "You are currently in OFFLINE mode."
				if [[ ! -z $redteamGogs ]]; then
					if [[ ! -d $setipsGitFolder ]]; then
						cd $HOME
						git clone http://$redteamGogs:3000/spatiald/setips.git
						ln -s $setipsGitFolder/setips.sh $HOME/setips.sh > /dev/null 2>&1
					else
						cd $setipsGitFolder; git pull
						ln -s $setipsGitFolder/setips.sh $HOME/setips.sh > /dev/null 2>&1
						echo
					fi
				else
					printError "You do not have an IP set for the Gogs (Github) server."
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
