MODULE_NAME = nb

BUILD_DIR = /lib/modules/$(shell uname -r)/build
HEADERS_EXIST = $(shell if [ -d "${BUILD_DIR}" ]; then echo "${BUILD_DIR}"; \
                  else echo ""; fi)

ifneq (${HEADERS_EXIST}, ${BUILD_DIR})
  $(warning "Check you have linux headers installed")
  $(error   "${BUILD_DIR} does not exist!")
endif

SRC := nb_km.c ../common/nanoBench.c

$(MODULE_NAME)-objs += $(SRC:.c=.o)

obj-m += $(MODULE_NAME).o

ccflags-y+=-std=gnu99 -Wno-declaration-after-statement -Wno-vla -isystem $(shell $(CC) -print-file-name=include)

OBJECT_FILES_NON_STANDARD := y

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	rm -f ../common/*.o ../common/*.ur-safe ../common/*.dwo ../common/.nanoBench.*
	rm -rf *.o *.ko *.mod *.mod.c *.ur-safe *.dwo .tmp_versions .cache.mk .nb.* .nb_km.* .modules.* .Module.* modules.order Module.symvers
