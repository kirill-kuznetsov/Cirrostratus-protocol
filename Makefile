
# I R MEIK UR FILEZ
ifneq ($(KERNELRELEASE),)
	obj-$(CONFIG_DST) += nst.o

	nst-y := dcore.o state.o export.o thread_pool.o crypto.o trans.o
else

	KERNELDIR ?= /lib/modules/$(shell uname -r)/build
	PWD := $(shell pwd)

default:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules

endif
clean:
	make -C clean
