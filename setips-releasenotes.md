# setips.sh RELEASE NOTES

## Current Version
Version: '2.7 (2017Feb15-2147)'
- Updated inundator (-x option) to check for pre-reqs and install/download, if necessary
- /etc/rc.local wasn't modified correctly to be executable
- networkLevel check refined; off doesn't prompt for networkLevel
- Added support to remotely setup redirectors; under Setup menu
- Added option to add more redirector ips to current box
- Changed menu option "Export" to "View-Info" to more accurately reflect its purpose (and because Don and John couldn't figure out what it was doing)
- Added dual gateway support (v2.7d)
- Fix interface identification; caused issues with various functions (v2.7e)
- Changed ipconfig to ifconfig (oops); reworked setupStaticIP function (v2.7f)
- Poor attempts to fix what the "in-game" Kali broke in networking output (v2.7g-v2.7i)
- MASSIVE update to support both "normal" and "in-game" Kali instances that are dumb (v2.7j)
- Collect static IP info prior to changing /etc/network/interfaces (v2.7k)
- Error checking on add sub ints; fixed remove sub ints fail; cleaned up tabs vs spaces (v2.7l)

Version: '2.6 (2016Feb15-1435)'
- Updated setips

Version: '2.4 (2016Jan11-1300)'
- Fix the updater for master/beta versions

Version: '2.3 (2016Jan11-1118)'
- Bug fixes in Snort community.rules download/update

Version: '2.2 (2016Jan07-1033)'
- Formal release
- Added Powershell Empire support
- Updated setips support to Veil running on Kali 2.0
- Add snort community rules for Inundator
- Fixed inundator support on Kali 2.0

Version: '2.0 (2015Nov24-1433)'
- Updates galore...review the menus to see new options

Version: '1.11 (2015Jun18-0002)'
- Lots o' bug fixes
- Added ability to update to BETA version with './setips.sh -z'
- Running './setips.sh -r' will hopefully repair problems with the system dropping subinterfaces/iptables on reboot

Version: '1.10 (2015Jun17-1645)'
- Bug fixes

Version: '1.9 (2015Jun16-2302)'
- Add check to ensure /etc/rc.local is executable
- SOCKS setup - shows netstat at end of setup to verify your SOCKS setup correctly (most common problem is mistyped password)
- Changed all 'Y' or 'N' answers to not submit automatically; allowing the operator to correct their mistypes
- Fixed bug in inundator script
- Fixed bug in single SRC NAT entry

Version: '1.8 (2015Jun14-1936)'
- Fixed the script that re-adds your sub interfaces on system reboot (run 'setips.sh -r' to fix your already installed instance)
- Built-in script updater functionality; added "-u" option to update to latest release verison
- Fixed bug in script checking for the existence of the new setips-files directory and trying to make it twice
- Updated Inundator script to allow for use of local proxy...asks for more details during build
- Minor bug fixes

Version: '1.7 (2015Jun11-2000)'
- Added option to Utilities menu to fix your /etc/ssh/sshd_config file so that root can login with password
- Added "-x" option to start Inundator - setup subinterfaces (if necessary), run inudator to replay snort rules that "inundates" snort sensors by sending all the default snort rules across their sensors
- Changed "port" to "interface" when asking what port the user wants is setting up

Version: '1.6 (2015Jun09-1910)'
- Added MASQUERADE back in but to the bottom of the ruleset as a catch all
- Fix error from different iptables when trying to restore SNAT rules - error "multiple -j flags not allowed"
- CRITICAL ERROR - failed to set "echo 1 > /proc/sys/net/ipv4/ip_forward" when running -f and -s

Version: '1.5 (2015Jun09-0635)'
- New "interface" and options for quickly adding rules, deleting rules, and viewing current iptables plus the normal interactive mode ("./setips.sh -h" will provide a full help menu)
- Cleans up iptables rulesets, removing duplicate lines
- Added a core "setips-files" folder in /root for storing all setips created files
- SOCKS setup does not echo your password as you type
- Redirector friendly - actually changes your source address on every connection
	-- this was noticed during SOCKS proxy testing and all outbound connections, regardless of proxychains ip list had the core IP of the redirector as its source port...arg!
	-- because of this, change your /etc/proxychains to "strict_chain"; comment out "random_chain", "chain_len", "proxy_dns"; you only need the core ip set in the list (example, "socks4 1.2.3.4 1080") 
- Fixes error with the setips-atboot.sh being named setips-atstart.sh
- Added protocol and subinterface IP to IPTables rules for more granularity on traffic (re)direction
