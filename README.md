Various tools to assess SSL resistance to DoS
=============================================

 - `server-vs-client` measures the computational difference between
   server and client. It needs a cipher suite (from `openssl ciphers`)
   and an appropriate certificate for the server side. Test it with
   RSA, DH, DSS, ECDH, ECDSA. If it is not able to do any handshake,
   you need to check if your certificate is compatible with the given
   cipher suite. Check with `openssl s_client` and `openssl s_server`.

 - `iptables.sh` is a set of iptables rule to help avoid SSL DoS.
