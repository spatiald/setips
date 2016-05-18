# setips Script

NOTE: COPY/PASTE BOTH LINES into your CAP shell/console

```bash
wget https://raw.githubusercontent.com/spatiald/setips/master/setips.sh \
-O /root/setips.sh; chmod +x setips.sh; /root/setips.sh
```

## Howto
Use git to clone the repository.  For Linux:
```bash
git clone https://github.com/spatiald/setips.git
```

If you need git installed, run:
```bash
apt-get update; apt-get -y install git
```

Once the ```setips``` folder downloads, you can update by changing into the setips directory and type:
```bash
git pull
```

Run the following to make the script executable:
```bash
chmod +x setips.sh
```
Recommend running the script in interactive mode first to learn it's capabilities:
```bash
./setips.sh -i
```
Some commands are capable of running as running as oneliners from the command line.  See ```Usage``` and ```Examples``` below. 

## Usage
```
Usage: [-h] [-i] [-l] [-r] [-a <protocol> <subintip> <subintport> <tgtIP> <tgtPort>] 
       [-f <fileName>] [-d <protocol> <subintip> <subintport> <tgtIP> <tgtPort>] 
       [-u] [-x <victim IP> <# of threads>] [-z]
```
#### Examples:
Displays this help menu.
```bash
./setips.sh -h
```

Interactive mode.
```bash
./setips.sh -i
```

List current IPTables rules.
```bash
./setips.sh -l
```

Repair current IPTables ruleset by removing duplicates, removing rules that conflict with SNAT source IP manipulation, and saving a backup.
```bash
./setips.sh -r
```

Add single IPTables rule - by default, it will append to the iptables file.
```bash
./setips.sh -a <tcp or udp> <pivot-subinterface-IP> <pivot-subinterface-listen-port> <target-IP> <target-port>
```

Delete single IPTables rule matching the input.
```bash
./setips.sh -d <tcp or udp> <pivot-subinterface-IP> <pivot-subinterface-listen-port> <target-IP> <target-port>
```

Add list of IPTables rules from file - Reads file and appends SRC-NAT rules to the iptables file.
File Format, one entry per line:  <tcp or udp> <pivot-subinterface-IP> <pivot-subinterface-listen-port> <target-IP> <target-port>
```bash
./setips.sh -f <file of SRC-NAT entries>
```

Update setips.sh scripts with RELEASE version from the Redteam wiki.
```bash
./setips -u
```

Update setips.sh scripts with BETA version from the Redteam wiki.
```bash
./setips -z
```

Inundator - Setup subinterfaces (if necessary), run inudator to blind snort sensors but send all the default snort rules across their sensors.
```bash
./setips.sh -x <target-IP> <#-of-threads>
```

## Troubleshooting

### Cloning error - "error: server certificate verification failed."
Add the following to your "git clone" command
```
-c http.sslVerify=false
```

## License
Setips by spatiald is licensed under a [Creative Commons Attribution-ShareAlike 4.0 International License](http://creativecommons.org/licenses/by-sa/4.0/legalcode).

### You are free to:
```Share``` — copy and redistribute the material in any medium or format

```Adapt``` — remix, transform, and build upon the material for any purpose, even commercially.

 The licensor cannot revoke these freedoms as long as you follow the license terms.

### Under the following terms:
```Attribution``` — You must give appropriate credit, provide a link to the license, and indicate if changes were made. You may do so in any reasonable manner, but not in any way that suggests the licensor endorses you or your use.

```ShareAlike``` — If you remix, transform, or build upon the material, you must distribute your contributions under the same license as the original.

```No additional restrictions``` — You may not apply legal terms or technological measures that legally restrict others from doing anything the license permits.

### Notices:
You do not have to comply with the license for elements of the material in the public domain or where your use is permitted by an applicable exception or limitation.
No warranties are given. The license may not give you all of the permissions necessary for your intended use. For example, other rights such as publicity, privacy, or moral rights may limit how you use the material.
