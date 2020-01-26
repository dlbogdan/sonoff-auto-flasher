#!/bin/bash
# Bogdan Lucian Dumitru 2020
# ALPHA VERSION

function decho(){
	if [[ $DEBUG == "on" ]]; then
		echo -e "$(date) - DEBUG > $1"
	fi

}

function initInterface(){
	echo "$(date) - Func:initInterface - Initializing Wireless interface"
	decho "initInterface: cleaning up interface"
	ip link set ${INTERFACE} down
	rfkill unblock wifi
	ip link set ${INTERFACE} up
	ip addr flush dev ${INTERFACE}
	ip addr add ${AP_ADDR}/24 dev ${INTERFACE}
	decho "Disabling multicast snooping on docker interface <<needed on most home network setups>>"
	echo 0 > /sys/devices/virtual/net/docker0/bridge/multicast_snooping
}

function initAvahi(){
	echo "$(date) - Func:initAvahi - Initializing Avahi Discovery Service"
	decho "initAvahi: starting dbus and avahi-daemon"
	service dbus restart > /dev/null
	avahi-daemon --no-drop-root -D
	sleep 2
}

function initAP(){
	echo "$(date) - Func:initAP - Initializing Access Point and discovery"
	decho "initAP: config"
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
decho "initAP: starting service"
service hostapd restart > /dev/null
file=$(</etc/hostapd/hostapd.conf)
decho "AP Config:\n================\n${file}\n==================\n"
ip link set ${INTERFACE} up
:
}


function initDHCPD(){
	echo "$(date) - Func:initDHCPD - Initializing DHCP Server"
	decho "initDHCPD: config"
	cat > "/etc/udhcpd.conf" <<EOF
start           172.10.1.10
end             172.10.1.254
interface       ${INTERFACE}
opt	dns	8.8.8.8
opt	router	${AP_ADDR}
opt	subnet	255.255.255.0
opt	lease	864000
EOF
sed -i 's/DHCPD_ENABLED="no"/DHCPD_ENABLED="yes"/g' /etc/default/udhcpd
touch /var/lib/misc/udhcpd.leases
decho "initDHCPD: starting service"
udhcpd /etc/udhcpd.conf
decho "sleeping 10 seconds to allow association of device to this machine"
sleep 10
:
}

function init(){
	echo "$(date) - Func:init - Initializing"

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
	echo "$(date) - Func:scanWithAvahi - Scanning with avahi protocol"
	retryCount=0;
	avahiFound=false;
	response=""

	while [ $retryCount -lt 5 ] && ! $avahiFound; do
		response=$(avahi-browse -pt _ewelink._tcp --resolve | grep ${INTERFACE} | grep "=;")
		count=$(echo -e "$response" | wc -l)
		if [ $count -gt 1 ]; then
			echo "Multiple devices found. Please run docker specifying the device with DIRECTIP=<addr of device>"
			echo "This docker will terminate after the list"
		fi

		if [[ -z "$response" ]]; then
			echo "Retrying."
			((retryCount+=1));
		else
			echo "Found."
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
					echo "Unexpected response or malformed packet."
					#                       decho $response
					return 1;
				else
					echo "Response looks good."
					#                       printf '%s\n' "${arr[@]}"
					set_deviceIPvar ${arr[7]}
					set_deviceIDvar $(echo ${arr[6]} | cut -d"_" -f2 | cut -d"." -f1)

					echo "Host $deviceIP seems to be a sonoff device and has ID:$deviceID";
					doNmap=false;
				fi
#				unset arr
#			done
		else
			echo "Failed."
			return 1;

		fi

		if [ $count -gt 1 ]; then
			return 2;
		fi
		echo "0: $deviceID"
		echo "0: $deviceIP"
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
	echo "$(date) - Func:scanWithNmap - scanning with Nmap + JSON Query"
	netAndMask=$(getNetworkAndMask_echo)
	decho $netAndMask
	nmapout=$(nmap -T4 -sS -p8081 -oG - $netAndMask | grep "open")
	decho "$nmapout"
	count=0;
	multiplefound=true;
	local IFS=$'\n' ; 
	for hostnmap in $nmapout; do
		host=$(echo $hostnmap | awk '{print $2}')
		out=$(curl -m 1  http://${host}:8081/zeroconf/info -XPOST --data '{"deviceid":"deviceid","data":{} }' 2>/dev/null ) #this works with 3.30 firmware, but it shouldn't as the deviceid is not legal.
		error=$(echo -e "$out" | getJSONVarFromQuery .error)
		if [[ $error == "0" ]]; then
			export deviceIP=$host
			((count+=1))
			echo "Host $host seems to be a sonoff device";
			if [ $count -gt 1 ]; then
				echo "Multiple devices found. Please run docker specifying the device with DIRECTIP=<addr of device>"
				echo "This docker will terminate after the list"
				multiplefound=true;
			fi


		fi
	done
	if [ $count -ne 1 ]; then
		return 1;
	fi

}

function scan(){
	echo "$(date) - Func:scan - Scanning for devices"
	if [[ $FORCENMAP != "yes" ]]; then
		scanWithAvahi 
		echo "1: $deviceID"
		ret=$?
	else
		echo "Forcing Nmap scanning"
		ret=1;
	fi
	if [ $ret -eq 1 ] && [ -z $DEVICEID ]; then
		echo "Getting the Device ID with Nmap is not possible. Set it manually with DEVICEID=<devid> variable."
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
  echo "Enabling internet routing for OTA unlocking"
  echo 1 > /proc/sys/net/ipv4/ip_forward
  internetIF=$(netstat -rn | grep ^0.0.0.0 | awk '{print $8}')
  netAndMask=$(getNetworkAndMask_echo)
  iptables -A FORWARD -o ${internetIF} -i ${INTERFACE} -s ${netAndMask} -m conntrack --ctstate NEW -j ACCEPT
  iptables -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
  iptables -t nat -F POSTROUTING
  iptables -t nat -A POSTROUTING -o ${internetIF} -j MASQUERADE
}

function unlockOTA(){
	echo "$(date) - Func:unlockOTA - unlocking OverTheAir updating"
	enableInternetRouting
	sleep 2
	decho "DEVICEID: $deviceID"
	out=$(curl http://${deviceIP}:8081/zeroconf/ota_unlock -XPOST --data "{\"deviceid\":\"${deviceID}\",\"data\": { } }" 2>/dev/null)
        error=$(echo -e "$out" | getJSONVarFromQuery .error)
        if [[ $error != "0" ]]; then
                echo "Error occured unlocking OTA"
                return 1;
        fi
	echo "Success!"
	:
}

function hostFileHTTP(){
	echo "$(date) - Func:hostFileHTTP - serving File over HTTP"
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
	lighttpd -D -f /etc/lighttpd.conf &

	:
}
isIpAlive_countfailed=0;
function isDeviceAlive(){

ping -W 2 -c 1 $deviceIP > /dev/null
if [ $? -ne 0 ]; then
	((isIpAlive_countfailed+=1))
	decho "ping $deviceIP failed consecutive count: $isIpAlive_countfailed"
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
	echo "$(date) - Func:updateFw - Updating Firmware"
	echo "Checking the device"
	out=$(curl -m 2  http://${deviceIP}:8081/zeroconf/info -XPOST --data "{\"deviceid\":\"${deviceID}\",\"data\":{} }" 2>/dev/null )
        error=$(echo -e "$out" | getJSONVarFromQuery .error)
	decho $out;
        if [[ $error != "0" ]]; then 
		echo "Device not ready"
		return 1;
	fi
	echo "Device should be ready"
	echo "Initiating firmware update"
	sha256=$(sha256sum /firmware/image.bin | awk '{print $1}');
	ipaddr=$(getHostIPOnIntf_echo ${INTERFACE})
	decho "Our IP is $ipaddr"
	out=$(curl -m 2  http://${deviceIP}:8081/zeroconf/ota_flash -XPOST --data "{\"deviceid\":\"${deviceID}\",\"data\":{\"downloadUrl\":\"http://${ipaddr}:9999/image.bin\",\"sha256sum\":\"${sha256}\"} }" 2>/dev/null )	
        error=$(echo -e "$out" | getJSONVarFromQuery .error)
        decho $out;
        if [[ $error != "0" ]]; then
                echo "Warning! Device returned an error."
		echo "Will not exit because of the permanent damage posibility if the firmware is actually being updated and the http_server goes down"
		echo "Please stop this docker manually, or if lucky, wait for the firmware to finish updating."
		echo "Either way, I'm out of here. Nothing else to do but wait."
        fi
	while isDeviceAlive; do
	: #we do nothing but just wait for the device to finish getting the image file from us.
	done
	echo "Device stopped responding. Probably finished updating and is restarting."
	echo "Waiting 10 more seconds just in case"	
	sleep 10
	echo "Done."
}

function pairByIP(){
	echo "$(date) - Func:pairByIP - Pairing device"

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
	echo "This container can either flash a custom rom on your sonoff device (diy mode)"
	echo "or pair your device to an existing wireless network"
	echo 
	echo "Help with docker container environment variables setup"

	texit 1
	:
}

function checkMODEvar(){
	if [[ -z $MODE ]]; then 
		echo "MODE must be set"
		return 1;
	fi

	if [[ $MODE != "flash" ]] && [[ $MODE != "pair" ]]; then
		echo "Variable MODE can be \"flash\" or \"pair\""
		return 1;
	fi

}

function checkINTERFACEvar(){
	if [[ -z $INTERFACE ]]; then
		echo "INTERFACE must be set"
		return 1;
	fi

	if [ ! -d "/sys/class/net/${INTERFACE}" ]; then
		echo "Interface $INTERFACE does not exist!"
		return 1;
	fi

	if [ -z $DIRECTIP ]; then
		if [ ! -d "/sys/class/net/${INTERFACE}/wireless" ]; then
			echo "Interface $INTERFACE is not a wireless interface."
			echo "You may use any interface only if you set variable DIRECTIP=<addr>|scan"
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
		echo "Firmware file does not exist. Please mount your folder containing the firmware to this docker. The mounted volume must contain the file named image.bin"
	        echo "Example of docker run argument:  -v \$PWD:/firmware  which will mounting current directory to /firmware inside docker."
		echo
		return 1
	fi
	
	if [[ $ALLOWBIGFIRMWARE != "yes" ]]; then
	binSize=$(stat -c "%s" /firmware/image.bin)
	if [ $binSize -gt 520192 ]; then
		echo "Warning ! The firmware image exceeds 508 kBytes. The initial firmware should be less than that."
		echo "If you know what you're doing please set env variable ALLOWBIGFIRMWARE=yes"
		echo "If you aren't sure I suggest flashing a lite version of the firmware first. For example https://github.com/arendst/Tasmota/releases/download/v8.1.0/tasmota-lite.bin"
		echo "And then from the tasmota web server you can upgrade to the full variant. Ditto for ESPHome or anything else."
		return 1;
	fi
	fi

	echo "Checking firmware image with esptool"
	echo
 	esptool.py image_info /firmware/image.bin
	if [ $? -ne 0 ]; then
		echo "Firmware file is invalid"
		return 1
	fi

		
	:
}

function checkAPSSIDvar(){
	if [[ -n $APSSID ]]; then
		if [[ $MODE == "flash" ]]; then
			decho "Ignoring APSSID variable in flashing mode"
			return 0
		fi

	else
		if [[ $MODE == "pair" ]]; then
			echo "APSSID var must be set in pairing mode"
			return 1;
		fi
	fi

	return 0

}

function checkAPPASSWvar(){
	if [[ -n $APPASSWD ]]; then
		if [[ $MODE == "flash" ]]; then
			decho "Ignoring APPASSW variable in flashing mode"
			return 0
		fi
	else
		if [[ $MODE == "pair" ]]; then
			echo "APPASSW var must be set in pairing mode"
			return 1;
		fi
	fi

	return 0
}


function checkDEVICEIDvar(){
	if [[ -n $DEVICEID ]]; then
		decho "DEVICEID var set, scanning possible with Nmap"
		export deviceID=$DEVICEID
	fi

}

function checkPrivilegedMode(){
	if [ ! -w "/sys" ] ; then
        	echo "[Error] Not running in privileged mode."
		return 1;
	fi
}

function checkVars(){
	echo "$(date) - Func:checkVars - Checking Variables"
	## defaults
	true ${CHANNEL:=1}
	true ${HW_MODE:=g}
	true ${DRIVER:=nl80211}
	true ${AP_ADDR:=172.10.1.1}
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
	echo "Aborted. Exit code $1"
	if [[ -n $2 ]]; then echo $2; fi
	exit $1
}

function getIP(){
	if [[ -z $DIRECTIP ]]; then
		echo "Scanning on the newly created AccesPoint."
		scan || return 1;
	elif [[ $DIRECTIP != "scan" ]]; then 
		echo "Scanning disabled. DIRECTIP var is set."
	else 
		scan || return 1;
	fi
	echo "2: $deviceID"
}

function main(){
	echo "============================"
	echo "Bogdan L. Dumitru 2020"
	echo "bogdan.dumitru@nightshift.ro"
	echo "============================"
	echo
	echo

	checkVars || helpVars
	init || texit 2

	if [[ $MODE == "pair" ]]; then 
		echo "=== PAIRING MODE ==="

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
		echo "=== FLASHING MODE ==="

		if [[ -z $DIRECTIP ]]; then
			initInterface || texit 10
			initAvahi || texit 11
			initAP || texit 12
			initDHCPD || texit 13
		else
			initAvahi || texit 14
		fi
		getIP || texit 15
		echo "3: $deviceID"
		unlockOTA || texit 16
		hostFileHTTP || texit 17
		updateFw || texit 18
	fi

}

main
