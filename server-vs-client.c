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

/* Tools to assess the difference of computational power between a SSL
   client and a SSL server to establish a SSL connection. Test with
   various ciphers and various certificates.

   This program will just fork a second copy to act as a client and
   exchange several SSL handshakes during a short period of time and
   measure CPU time of both client and server.
*/

#include "common.h"

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>

#define DATA_WRITES       1
#define DATA_WRITE_LEN    1

struct result {
  int handshakes;		/* Number of handshakes done. */
  struct timespec cpu;		/* CPU time */
  size_t handshake_read;
  size_t handshake_write;
  size_t data_writes;
  size_t data_len;
  size_t enc_data_len;
};
int       clientserver[2];

/* OpenSSL threading */
static pthread_mutex_t *mutex_buf = NULL;
static void locking_function(int mode, int n,
			     const char * file,
			     int line) {
  if (mode & CRYPTO_LOCK)
    pthread_mutex_lock(&mutex_buf[n]);
  else
    pthread_mutex_unlock(&mutex_buf[n]);
}
static unsigned long id_function(void) {
  return ((unsigned long)pthread_self());
}

/* Dunno why I should declare it */
extern int pthread_getcpuclockid (pthread_t,
                                  clockid_t *);

/* Record handshake bytes read and written, then determine TLS
 * record overhead by sending a single byte on the connection. */
static int determine_overhead(SSL *ssl, struct result *result) {
  char *buf[DATA_WRITE_LEN];
  int i;

  BIO *bio = SSL_get_rbio(ssl);	
  result->handshake_read = bio->num_read;
  result->handshake_write = bio->num_write;	
					
  for (i = 0; i < DATA_WRITES; i++) {			
    size_t bio_write_before = bio->num_write;
			
    int r = SSL_write(ssl, buf, DATA_WRITE_LEN);
    switch(SSL_get_error(ssl, r)) {
      case SSL_ERROR_NONE :
        result->data_writes++;
        result->data_len += DATA_WRITE_LEN;				
        if (r != DATA_WRITE_LEN) {
          fprintf(stderr, "Client incomplete write: %d\n", r);
          return -1;
        }					
        break;
      default:
        fprintf(stderr, "Client write error: %d\n", r);
        return -1;				
    }	
		
    result->enc_data_len += bio->num_write - bio_write_before;
  }

  return 1;
}

/* Client part */
static void* client_thread(void *arg) {
  SSL_CTX       *ctx = arg;
  int           left = 1000;	/* Number of handshakes left */
  static struct result result;
  result.handshakes = 0;
  result.handshake_read = 0;
  result.handshake_write = 0;
  result.data_writes = 0;
  result.data_len = 0;
  result.enc_data_len = 0;

  while (left) {
    SSL *ssl = SSL_new(ctx);
    SSL_set_fd(ssl, clientserver[0]);		
	
    if (SSL_connect(ssl) != 1) {
      fprintf(stderr, "Client failed to connect\n");
      goto client_error;
    }
	
    result.handshakes++;
    left--;
	
    if (result.handshake_read == 0) {
      if (determine_overhead(ssl, &result) < 0) {
        goto client_error;
      }
    }
		
	  SSL_shutdown(ssl);
	  SSL_shutdown(ssl);	   
    SSL_free(ssl);
	  continue;
	
client_error:
	  SSL_free(ssl);
	  break;
  }
   
  clockid_t cid;
  pthread_getcpuclockid(pthread_self(), &cid);
  clock_gettime(cid, &result.cpu);
  close(clientserver[0]);
  
  return &result;
}

static pthread_t start_client(const char *ciphersuite) {
  SSL_CTX *ctx;

  start("Initializing client");
  if ((ctx = SSL_CTX_new(TLSv1_2_client_method())) == NULL)
    fail("Unable to initialize SSL context:\n%s",
	 ERR_error_string(ERR_get_error(), NULL));
	
  #ifdef SSL_OP_NO_COMPRESSION
  SSL_CTX_set_options(ctx, SSL_OP_NO_COMPRESSION);
  #endif

  if (SSL_CTX_set_cipher_list(ctx, ciphersuite) != 1)
    fail("Unable to set cipher list to %s:\n%s",
	 ciphersuite,
	 ERR_error_string(ERR_get_error(), NULL));

  pthread_t threadid;
  if (pthread_create(&threadid, NULL, &client_thread, ctx))
    fail("Unable to create server thread");
  
  return threadid;
}

/* Server part */
static void* server_thread(void *arg) {
  SSL_CTX *ctx = arg;
  char buf[DATA_WRITE_LEN];
  static struct result result;
  result.handshakes = 0;

  while (1) {
    SSL *ssl = SSL_new(ctx);
    SSL_set_fd(ssl, clientserver[1]);
    if (SSL_accept(ssl) != 1)
      break;
    result.handshakes++;
			
		int receiving = 1;
		while(receiving) {			
			int r = SSL_read(ssl, buf, DATA_WRITE_LEN);	
			switch(SSL_get_error(ssl, r)) {
				case SSL_ERROR_NONE:
					break;
				case SSL_ERROR_ZERO_RETURN:
					receiving = 0;
					break;
				default:
          fprintf(stderr, "Server read error: %d\n", r);
					goto server_error;					
			}
		}	
	
	  SSL_shutdown(ssl);
	  SSL_shutdown(ssl);    
    SSL_free(ssl);
    continue;
    
server_error:
    SSL_free(ssl);
    break;
  }
  clockid_t cid;
  pthread_getcpuclockid(pthread_self(), &cid);
  clock_gettime(cid, &result.cpu);
  close(clientserver[1]);
  return &result;
}

static pthread_t start_server(const char *ciphersuite,
			      const char *certificate) {
  SSL_CTX *ctx;

  start("Initializing server");
  if ((ctx = SSL_CTX_new(SSLv23_server_method())) == NULL)
    fail("Unable to initialize SSL context:\n%s",
	 ERR_error_string(ERR_get_error(), NULL));
	 
  #ifdef SSL_OP_NO_COMPRESSION
  SSL_CTX_set_options(ctx, SSL_OP_NO_COMPRESSION);
  #endif

  /* Cipher suite */
  if (SSL_CTX_set_cipher_list(ctx, ciphersuite) != 1)
    fail("Unable to set cipher list to %s:\n%s",
	 ciphersuite,
	 ERR_error_string(ERR_get_error(), NULL));

  /* Certificate */
  if (SSL_CTX_use_certificate_chain_file(ctx, certificate) <= 0)
    fail("Unable to use given certificate:\n%s",
	 ERR_error_string(ERR_get_error(), NULL));
  if (SSL_CTX_use_PrivateKey_file(ctx, certificate, SSL_FILETYPE_PEM) <= 0)
    fail("Unable to use given key file:\n%s",
	 ERR_error_string(ERR_get_error(), NULL));

  /* DH */
  DH *dh;
  BIO *bio;
  bio = BIO_new_file(certificate, "r");
  if (!bio)
    fail("Unable to read certificate:\n%s",
	 ERR_error_string(ERR_get_error(), NULL));

  dh = PEM_read_bio_DHparams(bio, NULL, NULL, NULL);
  BIO_free(bio);
  if (dh) {
    SSL_CTX_set_tmp_dh(ctx, dh);
    DH_free(dh);
  }

  /* ECDH */
  EC_KEY *ecdh = NULL;
  ecdh = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
  SSL_CTX_set_tmp_ecdh(ctx,ecdh);
  EC_KEY_free(ecdh);

  pthread_t threadid;
  if (pthread_create(&threadid, NULL, &server_thread, ctx))
    fail("Unable to create server thread");
  
  return threadid;
}

int
main(int argc, char * const argv[]) {
  if (argc != 3) {
    fprintf(stderr, "Usage: \n");
    fprintf(stderr, "  %s ciphersuite certificate\n", argv[0]);
    fprintf(stderr, "\n");
    fprintf(stderr, " - `ciphersuite` is the name of cipher suite to use. Use\n");
    fprintf(stderr, "   `openssl ciphers` to choose one.\n");
    fprintf(stderr, "\n");
    fprintf(stderr, " - `certificate` is the name of the file containing\n");
    fprintf(stderr, "   the certificate, the key and appropriate additional parameters.\n");
    return 1;
  }

  const char *ciphersuite = argv[1];
  const char *certificate = argv[2];

  start("Initialize OpenSSL library");
  SSL_load_error_strings();
  SSL_library_init();
  if (!(mutex_buf = malloc(CRYPTO_num_locks() * sizeof(pthread_mutex_t))))
    fail("Unable to allocate memory for mutex");
  for (int i = 0;  i < CRYPTO_num_locks();  i++)
    pthread_mutex_init(&mutex_buf[i], NULL);
  CRYPTO_set_id_callback(id_function);
  CRYPTO_set_locking_callback(locking_function);

  pthread_t client, server;
  start("Prepare client and server");
  if (socketpair(AF_UNIX, SOCK_STREAM, 0, clientserver))
    fail("Unable to get a socket pair for client/server communication:\n%m");
  server = start_server(ciphersuite, certificate);
  client = start_client(ciphersuite);

  struct result *client_result, *server_result;
  start("Waiting for client to finish");
  if (pthread_join(client, (void **)&client_result))
    fail("Unable to join client thread");
  start("Waiting for server to finish");
  if (pthread_join(server, (void **)&server_result))
    fail("Unable to join server thread");

  end("Got the following results:\n"
      "Handshakes from client: %d\n"
      "User CPU time in client: %4ld.%03ld\n"	  
      "Handshakes from server: %d\n"
      "User CPU time in server: %4ld.%03ld\n"
      "Ratio: %.2f %%\n"
	    "\n"
	    "Client handshake bytes received: %d\n"
	    "Client handshake bytes written: %d\n"	  
	    "TLS record overhead: %d", 
      client_result->handshakes,
      client_result->cpu.tv_sec, client_result->cpu.tv_nsec / 1000000,	  
      server_result->handshakes,
      server_result->cpu.tv_sec, server_result->cpu.tv_nsec / 1000000,
      (server_result->cpu.tv_sec * 1000. + server_result->cpu.tv_nsec / 1000000.) * 100. /
      (client_result->cpu.tv_sec * 1000. + client_result->cpu.tv_nsec / 1000000.),
	    client_result->handshake_read,
	    client_result->handshake_write,
	    ((client_result->enc_data_len - client_result->data_len) / client_result->data_writes)
	  );
}
