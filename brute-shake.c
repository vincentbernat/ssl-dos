/*
 * Copyright (c) 2011 Vincent Bernat <bernat@luffy.cx>
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/* Emit massive parallel SSL handshakes to a SSL server. To limit
 * abuse, you must configure the server to accept the NULL-MD5 cipher
 * suite. Therefore, this program cannot be used on the wild.
 *
 * It will first do a normal handshake to build canned packets that
 * will be used to produce massive parallel handshakes without doing
 * any crypto operations. Handshake are done just to trigger
 * cryptographic operations on the server side. They are not complete
 * handshakes (because a complete handshake require to compute a
 * master secret).
 *
 * There are some limitations:
 *   - plain RSA only
 *   - NULL-MD5 cipher suite
 *   - TLS 1.0 only
 *   - Certificates must be shipped in the correct order, we use the
 *     first one.
 */

/* How many parallel connections we want to manage? */
#ifndef WORKERS
#define WORKERS 100
#endif

#include "common.h"

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <netdb.h>
#include <pthread.h>
#include <openssl/x509.h>
#include <openssl/rsa.h>
#include <openssl/err.h>

/* Canned client messages */

unsigned char client_hello[] = {
  /* TLS 1.0: Handshake Protocol */
  0x16, 0x03, 0x01,
  0x00, 0x2d,
  /* Client Hello */
  0x01, 0x00, 0x00, 0x29,
  0x03, 0x01,		  /* TLS 1.0 */
  0x4e, 0x5e, 0x19, 0x7e, /* Unix time (not required to be correct) */
  /* Random value */
  0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
  0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
  0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14,
  0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
  /* No session ID */
  0x00,
  /* Cipher suite */
  0x00, 0x02, 0x00, 0x01,
  /* Compression method */
  0x01, 0x00
};

int len_client_key_exchange;
unsigned char client_key_exchange[500] = {
  /* TLS 1.0: Handshake Protocol */
  0x16, 0x03, 0x01,
  0x00, 0x00,		    /* Length, will be written later */
  0x10,			    /* Client Key Exchange */
  0x00, 0x00, 0x00	    /* Length, this is above length minus 4 */
};
unsigned char change_cipher_spec[] = {
  0x14, 0x03, 0x01, 0x00, 0x01, 0x01
};
unsigned char client_finished[] = {
  /* TLS 1.0: Handshake Protocol */
  0x16, 0x03, 0x01,
  0x00, 0x24,
  /* Bogus content, the server will need to do some computation before
     being able to decrypt that. We just ship it just in case it waits
     for an encrypted message to start doing computations. */
  0x8f, 0x2c, 0xf7, 0xa1, 0x92, 0x4e, 0x6d, 0x76,
  0xdc, 0x51, 0x89, 0x57, 0x20, 0x79, 0x45, 0xd6,
  0x5b, 0xe8, 0x21, 0x9e, 0x65, 0xb9, 0x87, 0x89,
  0x8c, 0x8f, 0xb8, 0x17, 0xa6, 0xf0, 0xde, 0xbb,
  0x8e, 0x2a, 0x21, 0x92
};

static struct addrinfo *
solve(const char *host, const char *port) {
  int              err;
  char             name[INET6_ADDRSTRLEN];
  struct addrinfo  hints;
  struct addrinfo *result;

  start("Solve %s,%s", host, port);
  memset(&hints, 0, sizeof(struct addrinfo));
  hints.ai_family   = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags    = 0;
  hints.ai_protocol = 0;
  if ((err = getaddrinfo(host, port, &hints, &result)) != 0)
    fail("Unable to solve ‘%s,%s’:\n%s", host, port, gai_strerror(err));

  if ((err = getnameinfo(result->ai_addr, result->ai_addrlen,
			 name, sizeof(name), NULL, 0,
			 NI_NUMERICHOST)) != 0)
    fail("Unable to format ‘%s,%s’:\n%s", host, port, gai_strerror(err));
  end("Will connect to %s", name);  
  return result;
}

static void
send_client_hello(int s) {
  if (write(s, client_hello,
	    sizeof(client_hello)) != sizeof(client_hello))
    fail("Unable to send Client Hello:\n%m");
}

static void
send_client_end(int s) {
  struct iovec msg[3] = {
    { client_key_exchange, len_client_key_exchange },
    { change_cipher_spec, sizeof(change_cipher_spec) },
    { client_finished, sizeof(client_finished) }
  };
  if (writev(s, msg, 3) != len_client_key_exchange +
      sizeof(change_cipher_spec) +
      sizeof(client_finished))
    fail("Unable to send end message:\n%m");
}

static X509*
receive_server_hello(int s, int quick) {
  u_int16_t      l, r, m;
  unsigned char *p, *q;
  int            len_server_hello = 0;
  unsigned char  server_hello[4000];
  X509          *cert = NULL;

  while (1) {
    if ((l = read(s, server_hello + len_server_hello,
		  sizeof(server_hello) - len_server_hello)) == -1)
      fail("Unable to read Server Hello:\n%m");
    if (l == 0)
      fail("Premature end of handshake");
    len_server_hello += l;
    if (len_server_hello == sizeof(server_hello))
      fail("Answer too big");

    r = len_server_hello;
    p = server_hello;

    /* Server Hello */
    if (r < 1) continue;
    if (*p != 0x16)
      fail("Did not get a TLS record handshake (%x)", *p);
    r--; p++;
    if (r < 2) continue;
    if (*p != 0x03 || *(p + 1) != 0x01)
      fail("Server does not support TLS 1.0");
    r -= 2; p += 2;
    if (r < 2) continue;
    memcpy(&l, p, 2); l = htons(l);
    r -= 2; p += 2;
    if (r < l) continue;
    if (r < 4)
      fail("TLS record too short");
    if (*p != 0x02)
      fail("Not a Server Hello (%x)", *p);
    r -= l; p += l;

    /* Certificate */
    if (r < 1) continue;
    if (*p != 0x16)
      fail("Did not get a TLS record handshake (%x)", *p);
    r--; p++;
    if (r < 4) continue;
    r -= 2; p += 2;
    memcpy(&l, p, 2); l = htons(l);
    r -= 2; p += 2;
    if (r < l) continue;
    if (r < 4)
      fail("TLS record too short");
    if (*p != 0xb)
      fail("Not a Certificate (%x)", *p);
    if (!quick) {
      /* We'll grab the first certificate. We assume they are shipped in
	 the correct order. */
      if (l < 10)
	fail("Too short for a certificate list");
      if (*(p + 7) != 0)
	fail("Certificate too big");
      memcpy(&m, p + 8, 2); m = htons(m);
      if (l < m + 10)
	fail("Incorrect certificate size");
      /* Certificate is length m and at p + 10 */
      q = p + 10;
      if ((cert = d2i_X509(NULL, (const unsigned char **)&q, m)) == NULL)
	fail("Unable to parse X509 certificate:\n%s",
	     ERR_error_string(ERR_get_error(), NULL));
    }
    r -= l; p += l;

    /* Server Hello Done */
    if (r < 1) continue;
    if (*p != 0x16)
      fail("Did not get a TLS record handshake (%x)", *p);
    r--; p++;
    if (r < 4) continue;
    r -= 2; p += 2;
    memcpy(&l, p, 2); l = htons(l);
    r -= 2; p += 2;
    if (r < l) continue;
    if (r < 4)
      fail("TLS record too short");
    if (*p != 0xe)
      fail("Not a Server Hello Done (%x)", *p);
    r -= l; p += l;
    break;
  }

  return cert;
}

static void
can_client_keyexchange(X509 *cert) {
  start("Build Client Key Exchange message");

  /* Extract RSA public key */
  EVP_PKEY *pkey = X509_get_pubkey(cert);
  if ((pkey == NULL) || (pkey->type != EVP_PKEY_RSA) ||
      (pkey->pkey.rsa == NULL))
    fail("Certificate does not seem to have a RSA public key");
  RSA *rsa = pkey->pkey.rsa;
  EVP_PKEY_free(pkey);

  /* Build buffer to encrypt */
  unsigned char buf[48];
  buf[0] = 0x03;
  buf[1] = 0x01;
  /* We should fill random bytes, but no need, really */

  /* Encrypt */
  int n;
  u_int16_t m;
  if (sizeof(client_key_exchange) - 11 < RSA_size(rsa))
    fail("Not enough space to store encrypted premaster secret");
  n = RSA_public_encrypt(sizeof(buf),
			 buf, client_key_exchange + 11,
			 rsa, RSA_PKCS1_PADDING);
  if (n <= 0)
    fail("Unable to encrypt premaster secret");

  /* Fix lengths */
  m = htons(n);
  memcpy(client_key_exchange + 9, &m, 2);
  n += 2;
  m = htons(n);
  memcpy(client_key_exchange + 7, &m, 2);
  m = htons(n + 4);
  memcpy(client_key_exchange + 3, &m, 2);
  len_client_key_exchange = n + 9;
}

pthread_mutex_t lock;
int handshakes = 0;

static void*
statistics(void *arg) {
  int old = 0;
  int r;
  while (1) {
    sleep(1);
    pthread_mutex_lock(&lock);
    r = handshakes - old;
    old = handshakes;
    pthread_mutex_unlock(&lock);
    if (r < 0)
      continue;
    end("%d handshakes/s", r);
  }
  return NULL;
}

static void*
run(void *arg) {
  struct addrinfo *target = arg;
  int s, err;
  while (1) {
    if ((s = socket(target->ai_family,
		    target->ai_socktype,
		    target->ai_protocol)) == -1) {
      warn("Unable to create socket:\n%m");
      continue;
    }
    if ((err = connect(s, target->ai_addr, target->ai_addrlen)) == -1) {
      warn("Unable to connect:\n%m");
      close(s);
      continue;
    }
    send_client_hello(s);
    receive_server_hello(s, 1);
    send_client_end(s);
    close(s);
    pthread_mutex_lock(&lock);
    handshakes++;
    pthread_mutex_unlock(&lock);
  }
  return NULL;
}

int
main(int argc, char * const argv[]) {
  if (argc != 3) {
    fprintf(stderr, "Usage: \n");
    fprintf(stderr, "  %s host port\n", argv[0]);
    fprintf(stderr, "\n");
    fprintf(stderr, " - `host`: host to connect to (IP or name).\n");
    fprintf(stderr, " - `port`: port to use (e.g 443)\n");
    return 1;
  }

  const char      *ip     = argv[1];
  const char      *port   = argv[2];
  struct addrinfo *target = solve(ip, port);

  int err, s;
  start("Execute first handshake");

  /* Connect for first handshake */
  if ((s = socket(target->ai_family,
		  target->ai_socktype,
		  target->ai_protocol)) == -1)
    fail("Unable to create socket:\n%m");
  if ((err = connect(s, target->ai_addr, target->ai_addrlen)) == -1)
    fail("Unable to connect to ‘%s,%s’:\n%m", ip, port);

  /* First handshake */
  X509 *cert;
  start("Send Client Hello");
  send_client_hello(s);
  start("Receive Server Hello, Certificates and Server Hello Done");
  cert = receive_server_hello(s, 0);
  can_client_keyexchange(cert);
  start("Send Key Exchange, Change Cipher Spec and Finished");
  send_client_end(s);
  close(s);

  /* Now, do a lot of handshakes... We go threaded. */
  start("Starting workers");
  pthread_t workers[WORKERS];
  pthread_t stats;
  if (pthread_create(&stats, NULL, &statistics, NULL))
    fail("Unable to create stats thread");
  for (int i=0; i < WORKERS; i++) {
    if (pthread_create(&(workers[i]), NULL, &run, target))
      fail("Unable to create thread %d", i);
  }
  end("Enjoy!");
  for (int i=0; i < WORKERS; i++) {
    pthread_join(workers[i], NULL);
  }
  return 0;
}
