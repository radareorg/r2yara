include ../config.mk

CFLAGS+=-g

MOD=core_yara

all: $(MOD).$(LIBEXT)

$(MOD).$(LIBEXT): ${MOD}.o
	$(CC) -g ${MOD}.o ${CFLAGS} ${LDFLAGS} -o ${MOD}.${LIBEXT}

clean:
	rm -f ${MOD}.o ${MOD}.${LIBEXT}

mrproper: clean
	rm -f Makefile

RULESDIR=$(R2PM_USRPLUGIN_DIR)/rules-yara3

user-install install:
	${INSTALL_LIB} ${MOD}.${LIBEXT} $(R2PM_USRPLUGIN_DIR)/${MOD}.${LIBEXT}
	mkdir -p $(RULESDIR)
	cp -rf ../rules/*.yara $(RULESDIR)

symstall:
	ln -fs ${PWD}/${MOD}.${LIBEXT} $(R2PM_USRPLUGIN_DIR)/$(MOD).$(LIBEXT)
	rm -rf $(R2PM_USRPLUGIN_DIR)/yara
	mkdir -p $(RULESDIR)
	for a in *.gz ; do ln -fs $(PWD)/$$a $(RULESDIR)/$$a ; done

user-uninstall uninstall:
	rm -f ${R2PM_USRPLUGIN_DIR}/$(MOD).$(LIBEXT)
	rm -rf $(RULESDIR)
	rm -rf ${R2PM_USRPLUGIN_DIR}/yara
