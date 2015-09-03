#!/bin/bash
eventID="Operation RED TEAM"
wikiServer="127.0.0.1"
date=`date +"%Y%b%d-%H%M"`
webserversetipsdir="$webserversetipsdir"
printf "Enter version (beta or #): "; read versionnum
eventversion="$eventID.$versionnum ($date)"
# Copy setips.nightly to tmp file
cp setips.nightly setips.tmp
# Add current verison to setips.sh script
awk 'BEGIN{OFS=FS=" "} $1~/version=BETA/ {$1="version='"'$eventversion'"'";}1' setips.tmp > tmp; mv tmp setips.tmp
# Copy setips-releasenotes to tmp file
cp setips-releasenotes.md setips-releasenotes.tmp
# Add current verison to Release Notes
awk '/Current/{print;print "Version: '"'$eventversion'"'";next}1' setips-releasenotes.tmp > tmp; mv tmp setips-releasenotes.tmp
# Ask for the version
if [[ $versionnum = "" ]]; then
	echo "[!] You need a version number, try again."
	rm setips.tmp setips-releasenotes.tmp
	exit 1
# If "beta" upload setips-beta.shand setips-releasenotes-beta
elif [[ $versionnum = "beta" ]]; then
	echo $eventversion
	echo "[+] Connecting to wiki..."
	scp setips.tmp root@$wikiServer:$webserversetipsdir/setips-beta.sh
	echo "[+] Published beta version setips-beta.sh...copying release notes."
	scp setips-releasenotes.tmp root@$wikiServer:$webserversetipsdir/setips-releasenotes-beta.md
	echo "[+] Published beta version setips-beta.sh release notes."
	cp setips.tmp archive/setips.beta-$date
	cp setips-releasenotes.tmp archive/setips-releasenotes-beta-$date
	echo "[+] Published beta version and copied to archive."
# If "release" upload setips.sh and setips-releasenotes
else
	echo $eventversion
	echo "[+] Connecting to wiki..."
	scp setips.tmp root@$wikiServer:$webserversetipsdir/setips.sh
	echo "[+] Published beta version setips.sh...copying release notes."
	scp setips-releasenotes.tmp root@$wikiServer:$webserversetipsdir/setips-releasenotes.md
	echo "[+] Published beta version setips.sh release notes."
	cp setips.tmp archive/setips-$date
	cp setips-releasenotes.tmp archive/setips-releasenotes-$date
	echo "[+] Published new setips.sh and copied to archive."
	mv setips-releasenotes.tmp setips-releasenotes.md
fi
# Remove tmp files
rm setips.tmp setips-releasenotes.tmp > /dev/null 2>&1

: <<'END'
Testing:
- - - -
eventID="FLUFFY BUNNY"
date=`date +"%Y%b%d-%H%M"`
printf "Enter version (beta or #): "; read versionnum

eventversion="$eventID.$versionnum ($date)"
echo $eventversion

cp setips.nightly setips.tmp
awk 'BEGIN{OFS=FS=" "} $1~/version=BETA/ {$1="version='"'$eventversion'"'";}1' setips.tmp > tmp; mv tmp setips.tmp
cat setips.tmp | head -17

cp setips-releasenotes.md setips-releasenotes.tmp
awk '/Current/{print;print "Version: '"'$eventversion'"'";next}1' setips-releasenotes.tmp > tmp; mv tmp setips-releasenotes.tmp
cat setips-releasenotes.tmp | head -8

- - - -

awk 'BEGIN{OFS=FS=" "} $1~/version=BETA/ {$1="Version: '"'$eventversion'"'";}1' setips-releasenotes.tmp > tmp; mv tmp setips-releasenotes.tmp
awk 'BEGIN{OFS=FS=" "} $1~/version=BETA/ {$1="Version: '"'$eventversion'"'";}1' setips-releasenotes.md > tmp; mv tmp setips-releasenotes.md
END
