# Default rule
default: client server

# Debug or Release
CONFIG = -g3 -ggdb -O0 -DDEBUG=1
# CONFIG = -g2 -Os -DNDEBUG=1

OPENSSL_INCDIR = -I/usr/local/opt/openssl/include
OPENSSL_LIBDIR = -L/usr/local/opt/openssl/lib
OPENSSL_LIBS = -lssl -lcrypto

CFLAGS = $(CONFIG) $(OPENSSL_INCDIR) -std=c99 -Wall -Wextra -Wconversion -Wformat -Wformat=2 -Wformat-security -Wno-deprecated-declarations
LDFLAGS = $(OPENSSL_LIBDIR) $(OPENSSL_LIBS)

# link
#	$^ is the dependency
#   $@ is the target
client: client.o
	cc $^ -o $@ $(LDFLAGS)

# compile
#	$< is the first element in dependency list
#   $@ is the target
client.o: client.c client.h
	cc $< -o $@ -c $(CFLAGS)

server: server.o
	cc $^ -o $@ $(LDFLAGS)

server.o: server.c server.h
	cc $< -o $@ -c $(CFLAGS)

.PHONY: clean
clean:
	-rm -rf client client.o 
	-rm -rf server server.o 
	-rm -rf core *.core *.dSYM *.tmp .DS_Store