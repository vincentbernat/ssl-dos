CERTIFICATES = 768 1024 2048 4096
certificates: $(patsubst %,certificate-%,$(CERTIFICATES))
$(patsubst %,certificate-%,$(CERTIFICATES)): certificate-%: %-key.pem %-cert.pem %-dh.pem
%-key.pem:
	certtool --bits $(subst -key.pem,,$@) --generate-privkey --outfile $@
%-cert.pem: %-key.pem
	certtool --template certtool.cfg --generate-self-signed --load-privkey $^ --outfile $@
%-dh.pem:
	certtool --bits $(subst -dh.pem,,$@) --generate-dh-params --outfile $@

clean:
	rm -f *.pem

.PHONY: clean certificates
