ifneq ($(KERNELRELEASE),)
	obj-$(CONFIG_DST) += skb_send.o

	nst-y := skb_send.o
else

	KERNELDIR ?= /lib/modules/$(shell uname -r)/build
	PWD := $(shell pwd)

default:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules

endif