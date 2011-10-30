CFLAGS=-g -Werror -Wall -ansi -std=c99 -D_POSIX_C_SOURCE=199309
LDFLAGS=
EXEC=server-vs-client.exe brute-shake.exe
CERTS = 768-rsa.pem 1024-rsa.pem 2048-rsa.pem 4096-rsa.pem \
	768-dsa.pem 1024-dsa.pem 2048-dsa.pem # 4096-dsa.pem

all: $(EXEC) certificates

# Tools
server-vs-client.exe: server-vs-client.o common.o
	$(CC) -o $@ $^ $(LDFLAGS) -lssl -lcrypto -lpthread -lrt
brute-shake.exe: brute-shake.o common.o
	$(CC) -o $@ $^ $(LDFLAGS) -lcrypto -lpthread

# Certificates
cert_size = $(word 1,$(subst -, ,$@))
cert_type = $(word 2,$(subst -, ,$@))
dsa = $(if $(filter dsa,$(cert_type)),--dsa)
certificates: $(CERTS)
%.pem: %-key.pem %-cert.pem %-dh.pem
	cat $^ > $@
%-key.pem:
	certtool --bits $(cert_size) --generate-privkey $(dsa) --outfile $@
%-cert.pem: %-key.pem
	certtool --template certtool.cfg --generate-self-signed $(dsa) --load-privkey $^ --outfile $@
%-dh.pem:
	certtool --bits $(cert_size) --generate-dh-params $(dsa) --outfile $@

clean:
	rm -f *.pem *.o $(EXEC)

.PHONY: clean certificates all
