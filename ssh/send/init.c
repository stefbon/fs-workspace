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
    send->senders.head=NULL;
    send->senders.tail=NULL;
    send->sending=0;
    send->newkeys.tv_sec=0;
    send->newkeys.tv_nsec=0;
    set_send_behaviour(send, "default"); /* start with serialized handling of the send queue */
    send->sequence_number=0;

    /* encrypt */

    encrypt->flags=0;
    memset(encrypt->ciphername, '\0', sizeof(encrypt->ciphername));
    memset(encrypt->hmacname, '\0', sizeof(encrypt->hmacname));
    encrypt->encryptors.head=NULL;
    encrypt->encryptors.tail=NULL;
    encrypt->count=0;
    encrypt->max_count=0;
    encrypt->waiters.head=NULL;
    encrypt->waiters.tail=NULL;
    encrypt->waiting=0;
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
    compress->compressors.head=NULL;
    compress->compressors.tail=NULL;
    compress->count=0;
    compress->max_count=0; /* no limit */
    compress->waiters.head=NULL;
    compress->waiters.tail=NULL;
    compress->waiting=0;
    compress->ops=NULL;

    set_compress_none(compress);

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

}

void init_send_once()
{
    init_encryptors_once();
    init_compressors_once();

    init_encrypt_generic();
    init_encrypt_chacha20_poly1305_openssh_com();
    init_compress_none();

}
