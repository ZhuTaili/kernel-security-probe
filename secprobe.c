obj-m += secprobe.o

KDIR ?= /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean

load:
	sudo insmod ./secprobe.ko

unload:
	sudo rmmod secprobe

log:
	sudo dmesg -wT | grep --line-buffered SEC_PROBE
