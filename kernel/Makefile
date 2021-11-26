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

CFLAGS_nb_km.o := -DDEBUG
CFLAGS_nanoBench.o := -DDEBUG

ccflags-y+=-std=gnu99 -Wno-declaration-after-statement -DDEBUG

OBJECT_FILES_NON_STANDARD := y

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	rm -f ../common/*.o ../common/*.ur-safe
	rm -rf *.o *.ko *.mod.c .tmp_versions modules.order Module.symvers
