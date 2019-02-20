.PHONY: user kernel

all: user kernel

user:
	$(MAKE) -C user/

kernel:
	cd kernel; $(MAKE)

clean:
	$(MAKE) -C user/ clean
	cd kernel; $(MAKE) clean
