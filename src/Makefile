PROGRAM := discovery.elf 
SOURCES := $(wildcard *.c) 
OBJS := $(patsubst %.c,%.o,$(SOURCES))
LINKLIB  := -ldebug -ljson-c -lubox -lubus -lpthread -lblobmsg_json -luci
STAG_INCL_PATH   := $(STAGING_DIR)/usr/include
STAG_LIB_PATH    := $(STAGING_DIR)/usr/lib
INST_INCL_PATH   := $(PKG_INSTALL_DIR)/usr/include

export INFLAGS   := -I $(STAG_INCL_PATH)
export LDFLAGS   := -L $(STAG_LIB_PATH)
export DBGFLAGS  := -MMD -ggdb -Wall -Wundef -Wstrict-prototypes -Wno-trigraphs -fno-strict-aliasing -fno-common
#export DBGFLAGS  := -ggdb -Wall -fPIC -DBUILD_TIME="\"`date`\"" -DDEBUG


LINKFLAGS += -Xlinker -rpath=$(STAG_LIB_PATH)

buildapp:clean subcompile compile allcompile
	chmod 777 $(PROGRAM)

SUB_DIR-y :=	
	
subcompile:
	@for dir in $(SUB_DIR-y) ; do \
	$(MAKE) -C $$dir sub_cmp; done
	
compile:
	$(CC) -c *.c -D_GNU_SOURCE $(LINKFLAGS) $(LINKLIB) $(DBGFLAGS) $(INFLAGS)

allcompile: $(PROGRAM)
$(PROGRAM): $(OBJS)
	$(CC) -g -o $@ $^ $(LINKLIB) $(LDFLAGS)
	
clean:
	rm *.o $(PROGRAM) -f


