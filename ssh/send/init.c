/*
  2017, 2018 Stef Bon <stefbon@gmail.com>

  This program is free software; you can redistribute it and/or
  modify it under the terms of the GNU General Public License
  as published by the Free Software Foundation; either version 2
  of the License, or (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program; if not, write to the Free Software
  Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.

*/

#include "global-defines.h"

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <err.h>
#include <sys/time.h>
#include <time.h>
#include <pthread.h>
#include <ctype.h>
#include <inttypes.h>

#include <sys/param.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "logging.h"
#include "main.h"
#include "workerthreads.h"

#include "utils.h"

#include "ssh-common.h"
#include "ssh-common-protocol.h"
#include "ssh-send.h"
#include "ssh-utils.h"

int init_send(struct ssh_session_s *session, unsigned int *error)
{
    struct ssh_send_s *send=&session->send;
    struct ssh_encrypt_s *encrypt=&send->encrypt;
    struct ssh_compress_s *compress=&send->compress;

    /* send */

    send->flags=0;
    pthread_mutex_init(&send->mutex, NULL);
    pthread_cond_init(&send->cond, NULL);
    send->newkeys.tv_sec=0;
    send->newkeys.tv_nsec=0;
    set_send_behaviour(send, "default"); /* start with serialized handling of the send queue */
    send->sequence_number=0;

    init_list_header(&send->senders.header, SIMPLE_LIST_TYPE_EMPTY, NULL);
    pthread_mutex_init(&send->senders.mutex, NULL);
    pthread_cond_init(&send->senders.cond, NULL);


    /* encrypt */

    encrypt->flags=0;
    memset(encrypt->ciphername, '\0', sizeof(encrypt->ciphername));
    memset(encrypt->hmacname, '\0', sizeof(encrypt->hmacname));
    init_list_header(&encrypt->waiters.cryptors, SIMPLE_LIST_TYPE_EMPTY, NULL);
    encrypt->count=0;
    encrypt->max_count=0;
    init_list_header(&encrypt->waiters.threads, SIMPLE_LIST_TYPE_EMPTY, NULL);
    pthread_mutex_init(&encrypt->waiters.mutex, NULL);
    pthread_cond_init(&encrypt->waiters.cond, NULL);
    encrypt->ops=NULL;
    init_ssh_string(&encrypt->cipher_key);
    init_ssh_string(&encrypt->cipher_iv);
    init_ssh_string(&encrypt->hmac_key);

    set_encrypt_generic(encrypt);
    strcpy(encrypt->ciphername, "none");
    strcpy(encrypt->hmacname, "none");

    /* compress */

    compress->flags=0;
    memset(compress->name, '\0', sizeof(compress->name));
    init_list_header(&compress->waiters.cryptors, SIMPLE_LIST_TYPE_EMPTY, NULL);
    init_list_header(&compress->waiters.threads, SIMPLE_LIST_TYPE_EMPTY, NULL);
    pthread_mutex_init(&compress->waiters.mutex, NULL);
    pthread_cond_init(&compress->waiters.cond, NULL);
    compress->count=0;
    compress->max_count=0; /* no limit */
    compress->ops=NULL;

    set_compress_none(compress);
    return 0;

}

void free_send(struct ssh_session_s *session)
{
    struct ssh_send_s *send=&session->send;
    struct ssh_encrypt_s *encrypt=&send->encrypt;
    struct ssh_compress_s *compress=&send->compress;

    remove_compressors(compress);
    remove_encryptors(encrypt);

    pthread_mutex_destroy(&send->mutex);
    pthread_cond_destroy(&send->cond);

    pthread_mutex_destroy(&send->senders.mutex);
    pthread_cond_destroy(&send->senders.cond);

    pthread_mutex_destroy(&compress->waiters.mutex);
    pthread_cond_destroy(&compress->waiters.cond);
    pthread_mutex_destroy(&encrypt->waiters.mutex);
    pthread_cond_destroy(&encrypt->waiters.cond);

}

void init_send_once()
{
    init_encryptors_once();
    init_compressors_once();

    init_encrypt_generic();
    init_encrypt_chacha20_poly1305_openssh_com();
    init_compress_none();

}
