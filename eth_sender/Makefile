ifneq ($(KERNELRELEASE),)
	obj-$(CONFIG_DST) += client.o

	nst-y := client.o
else

	KERNELDIR ?= /lib/modules/$(shell uname -r)/build
	PWD := $(shell pwd)

default:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules

endif
