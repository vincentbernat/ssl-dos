Various tools to assess SSL resistance to DoS
=============================================

 - `server-vs-client` measures the computational difference between
   server and client. It needs a cipher suite (from `openssl ciphers`)
   and an appropriate certificate for the server side. Test it with
   RSA, DH, DSS, ECDH, ECDSA. If it is not able to do any handshake,
   you need to check if your certificate is compatible with the given
   cipher suite. Check with `openssl s_client` and `openssl s_server`.

 - `iptables.sh` is a set of iptables rule to help avoid SSL DoS.

 - `brute-shake` will do a lot of parallel handshakes against a server
   without doing any crypto operation (while the server will do a lot
   of them). Because it could be abused to take down a SSL server, it
   will only uses NULL-MD5 cipher suite. No serious SSL server will
   accept this kind of cipher suite.

You can find more information in this article:
 http://vincent.bernat.im/en/blog/2011-ssl-dos-mitigation.html
