CC		=	cc
PKG_CONFIG	=	pkg-config

EASYCONF_ROOT	=	./easyconf
EASYCONF_INC	=	$(EASYCONF_ROOT)/include
EASYCONF_STATIC	=	$(EASYCONF_ROOT)/libeasyconf.a

CFLAGS		=	-Wall -Wextra -Wshadow -O2 -g -pipe
CFLAGS		+=	-Iinclude -I$(EASYCONF_INC)
CFLAGS		+=	$(strip $(shell $(PKG_CONFIG) --cflags openssl))
LDFLAGS		=	$(EASYCONF_STATIC)
LDFLAGS		+=	$(strip $(shell $(PKG_CONFIG) --libs openssl))

VERSION_GIT_H	=	include/version_git.h
VERSION_GIT	=	$(strip $(shell cat $(VERSION_GIT_H) 2>/dev/null))
HEAD_COMMIT	=	$(strip $(shell git describe --always --tags --abbrev=10))

BIN		=	oshd
TEST_BIN	=	oshd_tests

INSTALL_PREFIX	=	/usr/local
INSTALL_PRE_BIN	=	$(INSTALL_PREFIX)/bin
INSTALL_PRE_ETC	=	$(INSTALL_PREFIX)/etc

INSTALL_BIN	=	$(INSTALL_PRE_BIN)/$(BIN)
INSTALL_ETC	=	$(INSTALL_PRE_ETC)/oshd

SRC		=	src/crypto/cipher.c		\
			src/crypto/pkey.c		\
			src/crypto/sha3.c		\
			src/events.c			\
			src/logger.c			\
			src/main.c			\
			src/netaddr.c			\
			src/netbuffer.c			\
			src/netpacket.c			\
			src/node.c			\
			src/oshd_cmd.c			\
			src/oshd_conf.c			\
			src/oshd_device.c		\
			src/oshd_process_packet.c	\
			src/oshd_route.c		\
			src/oshd_socket.c		\
			src/oshd.c			\
			src/oshpacket.c			\
			src/random.c			\
			src/tcp.c			\
			src/tuntap.c			\
			src/xalloc.c

TEST_SRC	=	src/logger.c				\
			src/xalloc.c				\
			src/netaddr.c				\
			src/netbuffer.c				\
			tests/netaddr_tests.c			\
			tests/netbuffer_tests.c

OBJ		=	$(SRC:%.c=obj/%.o)
TEST_OBJ	=	$(TEST_SRC:%.c=obj/%.o)
DEP		=	$(OBJ:.o=.d)
TEST_DEP	=	$(TEST_OBJ:.o=.d)

all:	update_version_git	$(BIN)

update_version_git:
ifneq ($(findstring $(HEAD_COMMIT), $(VERSION_GIT)), $(HEAD_COMMIT))
	@echo Updating $(VERSION_GIT_H) with commit hash $(HEAD_COMMIT)
	@echo "#define OSH_COMMIT_HASH \"$(HEAD_COMMIT)\"" > $(VERSION_GIT_H)
endif

make_easyconf:
	@$(MAKE) -C $(EASYCONF_ROOT)

test:	$(TEST_BIN)
	@./$(TEST_BIN)

install:	$(BIN)
	mkdir -p "$(INSTALL_PRE_BIN)"
	mkdir -p "$(INSTALL_ETC)"
	cp -i "$(BIN)" "$(INSTALL_BIN)"

uninstall:
	rm -i "$(INSTALL_BIN)"
	rm -ri "$(INSTALL_ETC)"

clean:
	rm -rf obj *.gcda *.gcno

obj/%.o:	%.c
	@mkdir -p "$(shell dirname $@)"
	$(CC) -MMD $(CFLAGS) -c $<	-o $@

$(BIN):	$(EASYCONF_STATIC)	$(OBJ)
	$(CC) -o $@ $^ $(LDFLAGS)

$(TEST_BIN):	$(EASYCONF_STATIC)	$(TEST_OBJ)
	$(CC) -o $@ $^ $(LDFLAGS) -lcriterion

$(EASYCONF_STATIC):	make_easyconf

-include $(DEP)
-include $(TEST_DEP)

.PHONY:	all	update_version_git	make_easyconf	test	install	uninstall	clean