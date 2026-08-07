R2YARA_CORE_WD=$(LIBR)/xps/p/r2yara
R2YARA_YARA_CFLAGS=$(shell pkg-config --cflags yara 2>/dev/null)
R2YARA_YARA_LDFLAGS=$(shell pkg-config --libs yara 2>/dev/null || echo -lyara)
CFLAGS+=-I$(R2YARA_CORE_WD)/src $(R2YARA_YARA_CFLAGS)
LDFLAGS+=$(R2YARA_YARA_LDFLAGS)
R2YARA_CORE_OBJ=$(R2YARA_CORE_WD)/src/core_r2yara.o
EXTERNAL_STATIC_OBJS+=$(R2YARA_CORE_OBJ)
