ROOT=$(shell pwd)/..
include ../config.mk

CFLAGS+=-g
LDFLAGS+=-lm

MOD=core_r2yara
MKDIR=mkdir -p
RULESDIR=rules-yara3

all: $(MOD).$(LIBEXT)

$(MOD).$(LIBEXT): ${MOD}.o
	$(CC) -g ${MOD}.o ${CFLAGS} ${LDFLAGS} -o ${MOD}.${LIBEXT}

clean:
	rm -f ${MOD}.o ${MOD}.${LIBEXT}

mrproper: clean
	rm -f Makefile

install:
	${INSTALL_LIB} ${MOD}.${LIBEXT} $(R2_LIBR_PLUGINS_DIR)/${MOD}.${LIBEXT}
	$(MKDIR) $(R2_LIBR_PLUGINS_DIR)/$(RULESDIR)
	cp -f ../rules/*.yara $(R2_LIBR_PLUGINS_DIR)/$(RULESDIR)/
	$(MKDIR) $(MANDIR)/man7
	cp -f ../doc/r2yara.7 $(MANDIR)/man7/r2yara.7

user-install:
	${INSTALL_LIB} ${MOD}.${LIBEXT} $(R2PM_USRPLUGIN_DIR)/${MOD}.${LIBEXT}
	mkdir -p $(R2PM_USRPLUGIN_DIR)/$(RULESDIR)
	cp -f ../rules/*.yara $(R2PM_USRPLUGIN_DIR)/$(RULESDIR)/

symstall:
	ln -fs ${PWD}/${MOD}.${LIBEXT} $(R2PM_USRPLUGIN_DIR)/$(MOD).$(LIBEXT)
	mkdir -p $(R2PM_USRPLUGIN_DIR)/$(RULESDIR)
	for a in *.gz ; do ln -fs $(PWD)/$$a $(R2PM_USRPLUGIN_DIR)/$(RULESDIR)/$$a ; done
	$(MKDIR) $(MANDIR)/man7
	ln -fs $(shell pwd)/../doc/r2yara.7 $(MANDIR)/man7/r2yara.7

uninstall:
	rm -f ${R2_LIBR_PLUGINS_DIR}/$(MOD).$(LIBEXT)
	rm -rf $(R2_LIBR_PLUGINS_DIR)/$(RULESDIR)
	rm -f $(MANDIR)/man7/r2yara.7

user-uninstall:
	rm -f ${R2PM_USRPLUGIN_DIR}/$(MOD).$(LIBEXT)
	rm -rf $(R2PM_USRPLUGIN_DIR)/$(RULESDIR)
