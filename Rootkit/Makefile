all: kmodule cmds

kmodule:
	cd kmod; $(MAKE)

cmds:
	cd hack; $(MAKE)

clean:
	cd kmod; $(MAKE) clean; cd ..
	cd hack; $(MAKE) clean; cd ..

