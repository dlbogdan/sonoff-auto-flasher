#!/bin/bash
# Bogdan Lucian Dumitru 2020


#debug levels
#	1 - info
#	2 - verbose l1
#	3 - verbose l2
mainIndex=0;



function log(){
	if [[ $DEBUGLEVEL -ge $1 ]];then  
		shift
		echo -e "$(date +"%T %d/%m/%y") - Func:[${FUNCNAME[1]}] $@"
	fi
}


function initInterface(){
	log 1 "Initializing Wireless interface"
	log 2 "cleaning up interface"
	ip link set ${INTERFACE} down
	rfkill unblock wifi
	ip link set ${INTERFACE} up
	ip addr flush dev ${INTERFACE}
	ip addr add ${AP_ADDR}/24 dev ${INTERFACE}
	log 2 "Disabling multicast snooping on docker interface"
	echo 0 > /sys/devices/virtual/net/docker0/bridge/multicast_snooping
}

function initAvahi(){
	log 1 "Initializing Avahi Discovery Service"
	log 2 "Starting dbus and avahi-daemon"
	service dbus restart > /dev/null
	avahi-daemon --no-drop-root -D
	sleep 2
}

function initAP(){
	log 1 "Initializing Access Point and discovery"
	log 2 "config"
	mkdir -p "/etc/hostapd"
	if [ ! -f "/etc/hostapd/hostapd.conf" ] ; then
		cat > "/etc/hostapd/hostapd.conf" <<EOF
interface=${INTERFACE}
driver=${DRIVER}
ssid=sonoffDiy
hw_mode=${HW_MODE}
channel=${CHANNEL}
wpa=2
wpa_passphrase=20170618sn
wpa_key_mgmt=WPA-PSK
wpa_pairwise=TKIP CCMP
wpa_ptk_rekey=600
macaddr_acl=0
auth_algs=1
ignore_broadcast_ssid=0
EOF
fi
log 1 "Starting service"
service hostapd restart > /dev/null
file=$(</etc/hostapd/hostapd.conf)
log 3 "AP Config:\n================\n${file}\n==================\n"
ip link set ${INTERFACE} up
:
}


function initDHCPD(){
	log 1 "Initializing DHCP Server"
	log 2 "Config"
	cat > "/etc/udhcpd.conf" <<EOF
start           172.10.1.10
end             172.10.1.254
interface       ${INTERFACE}
opt	dns	8.8.8.8
opt	router	${AP_ADDR}
opt	subnet	255.255.255.0
opt	lease	864000
EOF

file=$(</etc/udhcpd.conf)
log 3 "DHCPD Config:\n================\n${file}\n==================\n"
sed -i 's/DHCPD_ENABLED="no"/DHCPD_ENABLED="yes"/g' /etc/default/udhcpd
touch /var/lib/misc/udhcpd.leases
log 2 "Starting service"
udhcpd /etc/udhcpd.conf
log 2 "sleeping 10 seconds to allow association of device to this machine"
sleep 10
:
}

function init(){
	log 1 "Initializing"

	return 0
	:
}


function set_deviceIDvar(){

	deviceID=$1
}

function set_deviceIPvar(){
	deviceIP=$1
}

function scanWithAvahi(){
	log 1 "Scanning with avahi protocol"
	retryCount=0;
	avahiFound=false;
	response=""

	while [ $retryCount -lt 5 ] && ! $avahiFound; do
		response=$(avahi-browse -pt _ewelink._tcp --resolve | grep ${INTERFACE} | grep "=;")
		count=$(echo -e "$response" | wc -l)
		if [ $count -gt 1 ]; then
			log 1 "Multiple devices found. Please run docker specifying the device with DIRECTIP=<addr of device>"
			log 1 "This docker will terminate after the list"
		fi

		if [[ -z "$response" ]]; then
			log 2 "Retrying."
			((retryCount+=1));
		else
			log 1 "Found."
			avahiFound=true;
		fi
	done
	if $avahiFound; then
		#todo probably big bug if more than one avahi devices found!

#		printf "%s\n" "$response" | while IFS=';' read -r -a arr
#		do
IFS=";" read -r -a arr <<< "$response"
noItems=${#arr[@]}
if [ $noItems -ne 10 ]; then
	log 1 "Unexpected response or malformed packet."
	#                       decho $response
	return 1;
else
	log 1 "Response looks good."
	#                       printf '%s\n' "${arr[@]}"
	set_deviceIPvar ${arr[7]}
	set_deviceIDvar $(echo ${arr[6]} | cut -d"_" -f2 | cut -d"." -f1)

	log 1 "Host $deviceIP seems to be a sonoff device and has ID:$deviceID";
	doNmap=false;
fi
#				unset arr
#			done
else
	log 1 "Failed."
	return 1;

fi

if [ $count -gt 1 ]; then
	return 2;
fi
return 0;
}

ip2int()
{
	local a b c d
	{ IFS=. read a b c d; } <<< $1
		echo $(((((((a << 8) | b) << 8) | c) << 8) | d))
	}

int2ip()
{
	local ui32=$1; shift
	local ip n
	for n in 1 2 3 4; do
		ip=$((ui32 & 0xff))${ip:+.}$ip
		ui32=$((ui32 >> 8))
	done
	echo $ip
}

netmask()
# Example: netmask 24 => 255.255.255.0
{
	local mask=$((0xffffffff << (32 - $1))); shift
	int2ip $mask
}


broadcast()
# Example: broadcast 192.0.2.0 24 => 192.0.2.255
{
	local addr=$(ip2int $1); shift
	local mask=$((0xffffffff << (32 -$1))); shift
	int2ip $((addr | ~mask))
}

network()
# Example: network 192.0.2.0 24 => 192.0.2.0
{
	local addr=$(ip2int $1); shift
	local mask=$((0xffffffff << (32 -$1))); shift
	int2ip $((addr & mask))
}

function getNetworkAndMask_echo(){
	ipAndMask=$(ip -o -f inet addr show ${INTERFACE} | awk '{print $4}')
	IFS=/ read -r ip mask <<< $ipAndMask
	echo "$(network $ip $mask)/$mask"
}

function scanWithNmap(){
	log 1 "scanning with Nmap + REST API"
	netAndMask=$(getNetworkAndMask_echo)
	log 2 $netAndMask
	nmapout=$(nmap -T4 -sS -p8081 -oG - $netAndMask | grep "open")
	log 3 "$nmapout"
	count=0;
	multiplefound=true;
	local IFS=$'\n' ; 
	for hostnmap in $nmapout; do
		host=$(echo $hostnmap | awk '{print $2}')
		out=$(curl -m 1  http://${host}:8081/zeroconf/info -XPOST --data "{\"deviceid\":\"${deviceID}\",\"data\":{} }" 2>/dev/null )
		error=$(echo -e "$out" | getJSONVarFromQuery .error)
		if [[ $error == "0" ]]; then
			export deviceIP=$host
			((count+=1))
			log 1 "Host $host seems to be a sonoff device";
			if [ $count -gt 1 ]; then
				log 1 "Multiple devices found. Please run docker specifying the device with DIRECTIP=<addr of device>"
				log 1 "This docker will terminate after the list"
				multiplefound=true;
			fi


		fi
	done
	if [ $count -ne 1 ]; then
		return 1;
	fi

}

function scan(){
	log 1 "Scanning for devices"
	if [[ $FORCENMAP != "yes" ]]; then
		scanWithAvahi 
		ret=$?
	else
		log 1 "Forcing Nmap scanning"
		ret=1;
	fi
	if [ $ret -eq 1 ] && [ -z $DEVICEID ]; then
		log 1 "Getting the Device ID with Nmap is not possible. Set it manually with DEVICEID=<devid> variable."
		texit 21;
	fi
	case $ret in
		1)
			scanWithNmap || texit 21
			return 0
			;;
		2)
			texit 20;
			;;
		*)	
			return 0
			;;
	esac
}

function getHostIPOnIntf_echo(){
	ip addr show $1 | grep "inet\b" | awk '{print $2}' | cut -d/ -f1
}

function enableInternetRouting(){
	log 1 "Enabling internet routing for OTA unlocking"
	echo 1 > /proc/sys/net/ipv4/ip_forward
	internetIF=$(netstat -rn | grep ^0.0.0.0 | awk '{print $8}')
	log 1 "Routing from internet interface $internetIF to wireless AP on $INTERFACE"
	netAndMask=$(getNetworkAndMask_echo)
	log 2 "Network: $netAndMask"
	iptables -A FORWARD -o ${internetIF} -i ${INTERFACE} -s ${netAndMask} -m conntrack --ctstate NEW -j ACCEPT
	iptables -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
	iptables -t nat -F POSTROUTING
	iptables -t nat -A POSTROUTING -o ${internetIF} -j MASQUERADE
}

function unlockOTA(){
	#todo actually test if device was succesfully unlocked with JSON answer
	log 1 "unlocking OverTheAir updating"
	enableInternetRouting
	sleep 2
	log 2 "DEVICEID: $deviceID"
	out=$(curl http://${deviceIP}:8081/zeroconf/ota_unlock -XPOST --data "{\"deviceid\":\"${deviceID}\",\"data\": { } }" 2>/dev/null)
	error=$(echo -e "$out" | getJSONVarFromQuery .error)
	log 3 $out
	if [[ $error != "0" ]]; then
		log 1 "Error occured unlocking OTA"
		return 1;
	fi
	log 1 "Success!"
	:
}

function hostFileHTTP(){
	log 1 "serving File over HTTP"
	cat > "/etc/lighttpd.conf" <<EOF
server.modules = (
"mod_access",
"mod_alias",
"mod_compress",
"mod_redirect",
"mod_rewrite",
)
dir-listing.activate = "enable"
debug.log-request-header = "enable"
server.port = 9999
server.document-root        = "/firmware"
EOF
file=$(</etc/lighttpd.conf)
log 3 "HTTPD Config:\n================\n${file}\n==================\n"
log 1 "Starting service"
lighttpd -D -f /etc/lighttpd.conf &

:
}

isIpAlive_countfailed=0;
function isDeviceAlive(){

	ping -W 2 -c 1 $deviceIP > /dev/null
	if [ $? -ne 0 ]; then
		((isIpAlive_countfailed+=1))
		log 2 "ping $deviceIP failed consecutive count: $isIpAlive_countfailed"
	else
		isIpAlive_countfailed=0;
	fi

	if [ $isIpAlive_countfailed -gt 8 ]; then
		isIpAlive_countfailed=0;
		return 1
	fi

	return 0;
}

function updateFw(){
	log 1 "Updating Firmware"
	log 2 "Checking the device"
	out=$(curl -m 2  http://${deviceIP}:8081/zeroconf/info -XPOST --data "{\"deviceid\":\"${deviceID}\",\"data\":{} }" 2>/dev/null )
	error=$(echo -e "$out" | getJSONVarFromQuery .error)
	log 3 $out;
	if [[ $error != "0" ]]; then 
		echo "Device not ready"
		return 1;
	fi
	log 2 "Device should be ready"
	log 1 "Initiating"
	sha256=$(sha256sum /firmware/image.bin | awk '{print $1}');
	log 3 "Firmware image SHA256 is $sha256"
	ipaddr=$(getHostIPOnIntf_echo ${INTERFACE})
	log 2 "Our IP is $ipaddr"
	out=$(curl -m 2  http://${deviceIP}:8081/zeroconf/ota_flash -XPOST --data "{\"deviceid\":\"${deviceID}\",\"data\":{\"downloadUrl\":\"http://${ipaddr}:9999/image.bin\",\"sha256sum\":\"${sha256}\"} }" 2>/dev/null )	
	error=$(echo -e "$out" | getJSONVarFromQuery .error)
	log 2 $out;
	if [[ $error != "0" ]]; then
		log 1 "Warning! Device returned an error."
		log 1 "Will not exit because of the permanent damage posibility if the firmware is actually being updated and the http_server goes down"
		log 1 "Please stop this docker manually, or if lucky, wait for the firmware to finish updating."
		log 1 "Either way, I'm out of here. Nothing else to do but wait."
	fi
	#todo actually test current firmware transfer from output of httpd server instead of just waiting for device to die
	while isDeviceAlive; do
		: #we do nothing but just wait for the device to finish getting the image file from us.
	done
	log 1 "Device stopped responding. Probably finished updating and is restarting."
	log 1 "Waiting 10 more seconds just in case"	
	sleep 10
	log 1 "Done."
}

function pairByIP(){
	log 1 "Pairing device"

	:
}


function getJSONVarFromQuery(){
	# don't laugh but this is what I came up with
	read -r line
	if [ -z $2 ]; then
		printf '%s' "$line" | jq $1
	else 
		tmp=$(printf '%s' "$line" | jq $1)
		echo $tmp | tail -c +2 | head -c -2 | sed 's@\\@@g' | jq .ssid | tail -c +2 | head -c -2
	fi
	:
}

function getID(){

	:
}

function helpVars(){
	echo -e "\n\n\n"
	(echo "This container can either flash a custom rom on your sonoff device (diy mode)"
        echo  " or pair your device to an existing wireless network"
	echo
	echo  " Help with docker container arguments and environment variables setup"
	echo 
	echo  " This container needs to run in privileged mode and with direct access to network"
	echo  " This is achieved with --privileged --net=host docker command arguments"
	echo 
	echo  "Mode setup: "
	) | boxes -d stone
	echo -e "\n\n\n"
	texit 1
	:
}

function checkMODEvar(){
	if [[ -z $MODE ]]; then 
		log 1 "MODE must be set"
		return 1;
	fi

	if [[ $MODE != "flash" ]] && [[ $MODE != "pair" ]]; then
		log 1 "Variable MODE can be \"flash\" or \"pair\""
		return 1;
	fi

}

function checkINTERFACEvar(){
	if [[ -z $INTERFACE ]]; then
		log 1 "INTERFACE must be set"
		return 1;
	fi

	if [ ! -d "/sys/class/net/${INTERFACE}" ]; then
		log 1 "Interface $INTERFACE does not exist!"
		return 1;
	fi

	if [ -z $DIRECTIP ]; then
		if [ ! -d "/sys/class/net/${INTERFACE}/wireless" ]; then
			log 1 "Interface $INTERFACE is not a wireless interface."
			log 1 "You may use any interface only if you set variable DIRECTIP=<addr>|scan"
			return 1;
		fi
	fi

	#//todo check existance of interface

}

function checkDIRECTIPvar(){
	#// todo test if IP is reachable
	#// todo test if IP is serving HTTP on 8081 
	#// todo test if IP is on the INTERFACE	
	if [ -z $DIRECTIP ]; then
		if [[ $DIRECTIP != "scan" ]]; then
			deviceIP=$DIRECTIP
		fi
	fi

	:
}

function checkFWFILEvar(){
	#// check if file exists
	#// check ? < filesize > 0 

#	if [[ $MODE == "pair" ]]; then
#		decho "Ignoring FWFILE variable in pairing mode"
#		return 0
#	fi
#	if [[ -z $FWFILE ]]; then // using volume mounts instead
#		echo "FWFILE var must be set in flashing mode."
#		return 1
#	fi
if [[ $MODE != "flash" ]]; then 
	return 0
fi

if [ ! -f /firmware/image.bin ]; then
	log 1 "Firmware file does not exist. Please mount your folder containing the firmware to this docker. The mounted volume must contain the file named image.bin"
	log 1 "Example of docker run argument:  -v \$PWD:/firmware  which will mounting current directory to /firmware inside docker."
	echo
	return 1
fi

if [[ $ALLOWBIGFIRMWARE != "yes" ]]; then
	binSize=$(stat -c "%s" /firmware/image.bin)
	if [ $binSize -gt 520192 ]; then
		log 1 "Warning ! The firmware image exceeds 508 kBytes. The initial firmware should be less than that."
		log 1 "If you know what you're doing please set env variable ALLOWBIGFIRMWARE=yes"
		log 1 "If you aren't sure I suggest flashing a lite version of the firmware first. For example https://github.com/arendst/Tasmota/releases/download/v8.1.0/tasmota-lite.bin"
		log 1 "And then from the tasmota web server you can upgrade to the full variant. Ditto for ESPHome or anything else."
		return 1;
	fi
fi

log 1 "Checking firmware image with esptool"
if [ $DEBUGLEVEL -lt 3 ]; then
	esptool.py image_info /firmware/image.bin > /dev/null
else
	esptool.py image_info /firmware/image.bin
fi

if [ $? -ne 0 ]; then
	log 1 "Firmware file is invalid"
	return 1
fi


:
}

function checkAPSSIDvar(){
	if [[ -n $APSSID ]]; then
		if [[ $MODE == "flash" ]]; then
			log 2 "Ignoring APSSID variable in flashing mode"
			return 0
		fi

	else
		if [[ $MODE == "pair" ]]; then
			log 1 "APSSID var must be set in pairing mode"
			return 1;
		fi
	fi

	return 0

}

function checkAPPASSWvar(){
	if [[ -n $APPASSWD ]]; then
		if [[ $MODE == "flash" ]]; then
			log 2 "Ignoring APPASSW variable in flashing mode"
			return 0
		fi
	else
		if [[ $MODE == "pair" ]]; then
			log 1 "APPASSW var must be set in pairing mode"
			return 1;
		fi
	fi

	return 0
}


function checkDEVICEIDvar(){
	if [[ -n $DEVICEID ]]; then
		log 2 "DEVICEID var set, scanning possible with Nmap"
		export deviceID=$DEVICEID
	fi

}

function checkPrivilegedMode(){
	if [ ! -w "/sys" ] ; then
		log 1 "[Error] Not running in privileged mode."
		return 1;
	fi
}

function checkVars(){
	log 0 "Checking Variables"
	## defaults
	true ${CHANNEL:=1}
	true ${HW_MODE:=g}
	true ${DRIVER:=nl80211}
	true ${AP_ADDR:=172.10.1.1}
	true ${DEBUGLEVEL:=1}

	##
	checkPrivilegedMode || return 1
	checkDEVICEIDvar || return 1
	checkMODEvar || return 1
	checkINTERFACEvar || return 1
	checkDIRECTIPvar || return 1
	checkFWFILEvar || return 1
	checkAPSSIDvar || return 1
	checkAPPASSWvar || return 1

	:
}


function texit(){
	for i in {21..16} {16..21} ; do echo -en "\e[38;5;${i}m==\e[0m" ; done ; echo
	echo -e "\033[33;5m\e[1m\e[91m  Aborted. Exit code $1\033[0m" 
	for i in {21..16} {16..21} ; do echo -en "\e[38;5;${i}m==\e[0m" ; done ; echo
	if [[ -n $2 ]]; then echo $2; fi
	exit $1
}

function getIP(){
	if [[ -z $DIRECTIP ]]; then
		log 1 "Scanning on the newly created AccesPoint."
		scan || return 1;
	elif [[ $DIRECTIP != "scan" ]]; then 
		log 1 "Scanning disabled. DIRECTIP var is set."
	else 
		scan || return 1;
	fi
}

function _main(){
	if [[ $DEBUGLEVEL -ge 4 ]];then  #//special cases only
		set -x
	fi

	echo -e "\e[34m"
	echo -e "    Sonoff-Auto-Flasher\n by Bogdan L. Dumitru 2020\nbogdan.dumitru@nightshift.ro" | boxes -d ian_jones
	echo -e "\e[0m"
	checkVars || helpVars 
	init || texit 2

	if [[ $MODE == "pair" ]]; then 
		log 1 "=== PAIRING MODE ==="

		if [[ -z $DIRECTIP ]]; then 
			initInterface || texit 3
			initAvahi || texit 4
			initAP || texit 5
			initDHCPD || texit 6
		else
			initAvahi || texit 7
		fi
		getIP || texit 8
		pairByIP || texit 9


	elif [[ $MODE == "flash" ]]; then
		log 1 "=== FLASHING MODE ==="

		if [[ -z $DIRECTIP ]]; then
			initInterface || texit 10
			initAvahi || texit 11
			initAP || texit 12
			initDHCPD || texit 13
		else
			initAvahi || texit 14
		fi
		getIP || texit 15
		unlockOTA || texit 16
		hostFileHTTP || texit 17
		updateFw || texit 18
	fi

}

_main
