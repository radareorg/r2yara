include ./CONFIG

UNAME=$(shell uname)
SUDO?=sudo
DEPENDS=
CROSSARCH=x64
R2CFG_FLAGS?=
PWD=$(shell pwd)
PACKAGE_DIR?=${PWD}

R2_VERSION=$(shell r2 -qv)

DOCKCROSS=$(PWD)/../dockcross
R2PLUGDIR=/usr/lib/radare2/$(R2_VERSION)

all: root
	$(SUDO) rm -rf control data
	$(MAKE) clean
	mkdir -p data
	cp -rf root/* data
	$(MAKE) control
	$(MAKE) deb

root:
	cd ../.. && $(MAKE) clean ; ./configure --prefix=/usr $(R2CFG_FLAGS) ; make
	mkdir -p root/$(R2PLUGDIR)
	cp -f ../../core_yara.so root/$(R2PLUGDIR)

purge: clean
	rm -rf root

summary:
	echo $(VERSION)

include deb.mk
