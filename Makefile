CC		=	cc
PKG_CONFIG	=	pkg-config

CFLAGS		=	-Wall -Wextra -Wshadow -O2 -g -pipe
CFLAGS		+=	-Iinclude -Iinclude/easyconf
LDFLAGS		=

BIN		=	oshd
TEST_BIN	=	oshd_tests

SRC		=	src/easyconf/easyconf.c		\
			src/easyconf/getline.c		\
			src/easyconf/parameter.c	\
			src/logger.c			\
			src/main.c			\
			src/netaddr.c			\
			src/netbuffer.c			\
			src/netpacket.c			\
			src/node.c			\
			src/oshd_conf.c			\
			src/oshd_device.c		\
			src/oshd_route.c		\
			src/oshd_script.c		\
			src/oshd_socket.c		\
			src/oshd.c			\
			src/oshpacket.c			\
			src/tcp.c			\
			src/tuntap.c			\
			src/xalloc.c

TEST_SRC	=	src/easyconf/easyconf.c			\
			src/easyconf/getline.c			\
			src/easyconf/parameter.c		\
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

all:	$(BIN)

$(BIN):	$(OBJ)
	$(CC) -o $@ $^ $(LDFLAGS)

$(TEST_BIN):	$(TEST_OBJ)
	$(CC) -o $@ $^ $(LDFLAGS) -lcriterion

test:	$(TEST_BIN)
	@./$(TEST_BIN)

clean:
	rm -rf obj *.gcda *.gcno

obj/%.o:	%.c
	@mkdir -p "$(shell dirname $@)"
	$(CC) -MMD $(CFLAGS) -c $<	-o $@

-include $(DEP)
-include $(TEST_DEP)

.PHONY:	all	test	clean