include ../config.mk

CFLAGS+=-g

MOD=core_yara
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
	mkdir -p $(R2_LIBR_PLUGINS_DIR)/$(RULESDIR)
	cp -f ../rules/*.yara $(R2_LIBR_PLUGINS_DIR)/$(RULESDIR)/

user-install:
	${INSTALL_LIB} ${MOD}.${LIBEXT} $(R2PM_USRPLUGIN_DIR)/${MOD}.${LIBEXT}
	mkdir -p $(R2PM_USRPLUGIN_DIR)/$(RULESDIR)
	cp -f ../rules/*.yara $(R2PM_USRPLUGIN_DIR)/$(RULESDIR)/

symstall:
	ln -fs ${PWD}/${MOD}.${LIBEXT} $(R2PM_USRPLUGIN_DIR)/$(MOD).$(LIBEXT)
	mkdir -p $(R2PM_USRPLUGIN_DIR)/$(RULESDIR)
	for a in *.gz ; do ln -fs $(PWD)/$$a $(R2PM_USRPLUGIN_DIR)/$(RULESDIR)/$$a ; done

uninstall:
	rm -f ${R2_LIBR_PLUGINS_DIR}/$(MOD).$(LIBEXT)
	rm -rf $(R2_LIBR_PLUGINS_DIR)/$(RULESDIR)

user-uninstall:
	rm -f ${R2PM_USRPLUGIN_DIR}/$(MOD).$(LIBEXT)
	rm -rf $(R2PM_USRPLUGIN_DIR)/$(RULESDIR)
