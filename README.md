# sonoff-auto-flasher
Automatic flashing of sonoff devices with custom firmware

Example run:
docker run --rm --privileged -e DEBUGLEVEL=1 --net=host -e MODE=flash -e INTERFACE=wlp2s0 -v $PWD:/firmware/ dlbogdan/sonoff-auto-flasher
