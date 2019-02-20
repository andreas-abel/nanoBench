MODULE_NAME = nb

SRC := nb_km.c ../common/nanoBench.c

$(MODULE_NAME)-objs += $(SRC:.c=.o)

obj-m += $(MODULE_NAME).o

CFLAGS_nb_km.o := -DDEBUG
CFLAGS_nanoBench.o := -DDEBUG

ccflags-y+=-std=gnu99 -Wno-declaration-after-statement

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	rm -f ../common/*.o ../common/*.ur-safe
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
	
