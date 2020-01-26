FROM ubuntu:19.10
LABEL maintainer="bogdan.dumitru@nightshift.ro"

RUN apt-get update && apt-get upgrade -y && apt-get install iputils-ping python3-setuptools python3-pip jq curl iw rfkill iptables udhcpd nmap avahi-utils dbus iproute2 wireless-tools hostapd lighttpd net-tools --no-install-recommends -y
RUN pip3 install setuptools esptool

RUN mkdir -p /var/run/dbus 
VOLUME /var/run/dbus

COPY run.sh .

CMD /run.sh
