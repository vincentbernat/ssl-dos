CFLAGS=-g -Werror -Wall -ansi -std=c99 -D_POSIX_C_SOURCE=199309
LDFLAGS=
EXEC=server-vs-client.exe

all: $(EXEC)

server-vs-client.exe: server-vs-client.o common.o
	$(CC) -o $@ $^ $(LDFLAGS) -lssl -lcrypto -lpthread -lrt

CERTIFICATES = 768 1024 2048 4096
certificates: $(patsubst %,%.pem,$(CERTIFICATES))
$(patsubst %,%.pem,$(CERTIFICATES)): %.pem: %-key.pem %-cert.pem %-dh.pem
	cat $^ > $@
%-key.pem:
	certtool --bits $(subst -key.pem,,$@) --generate-privkey --outfile $@
%-cert.pem: %-key.pem
	certtool --template certtool.cfg --generate-self-signed --load-privkey $^ --outfile $@
%-dh.pem:
	certtool --bits $(subst -dh.pem,,$@) --generate-dh-params --outfile $@

clean:
	rm -f *.pem *.o $(EXEC)

.PHONY: clean certificates all
