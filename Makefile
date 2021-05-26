CC		=	cc
PKG_CONFIG	=	pkg-config

CFLAGS		=	-Wall -Wextra -Wshadow -O2 -g -pipe
CFLAGS		+=	-Iinclude -Iinclude/easyconf
LDFLAGS		=

VERSION_GIT_H	=	include/version_git.h
VERSION_GIT	=	$(strip $(shell cat $(VERSION_GIT_H) 2>/dev/null))
HEAD_COMMIT	=	$(strip $(shell git describe --always --tags --abbrev=10))

BIN		=	oshd
TEST_BIN	=	oshd_tests

SRC		=	src/easyconf/easyconf.c		\
			src/easyconf/getline.c		\
			src/easyconf/parameter.c	\
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
			src/oshd_route.c		\
			src/oshd_socket.c		\
			src/oshd.c			\
			src/oshpacket.c			\
			src/tcp.c			\
			src/tuntap.c			\
			src/xalloc.c

TEST_SRC	=	src/easyconf/easyconf.c			\
			src/easyconf/getline.c			\
			src/easyconf/parameter.c		\
			src/logger.c				\
			src/xalloc.c				\
			src/netaddr.c				\
			src/netbuffer.c				\
			tests/easyconf/easyconf_tests.c		\
			tests/easyconf/getline_tests.c		\
			tests/easyconf/parameter_tests.c	\
			tests/netaddr_tests.c			\
			tests/netbuffer_tests.c

OBJ		=	$(SRC:%.c=obj/%.o)
TEST_OBJ	=	$(TEST_SRC:%.c=obj/%.o)
DEP		=	$(OBJ:.o=.d)
TEST_DEP	=	$(TEST_OBJ:.o=.d)

all:	update_version_git	$(BIN)

$(BIN):	$(OBJ)
	$(CC) -o $@ $^ $(LDFLAGS)

$(TEST_BIN):	$(TEST_OBJ)
	$(CC) -o $@ $^ $(LDFLAGS) -lcriterion

update_version_git:
ifneq ($(findstring $(HEAD_COMMIT), $(VERSION_GIT)), $(HEAD_COMMIT))
	@echo Updating $(VERSION_GIT_H) with commit hash $(HEAD_COMMIT)
	@echo "#define OSH_COMMIT_HASH \"$(HEAD_COMMIT)\"" > $(VERSION_GIT_H)
endif

test:	$(TEST_BIN)
	@./$(TEST_BIN)

clean:
	rm -rf obj *.gcda *.gcno

obj/%.o:	%.c
	@mkdir -p "$(shell dirname $@)"
	$(CC) -MMD $(CFLAGS) -c $<	-o $@

-include $(DEP)
-include $(TEST_DEP)

.PHONY:	all	update_version_git	test	clean