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

#include "logging.h"
#include "main.h"
#include "utils.h"

#include "ssh-common.h"
#include "ssh-utils.h"
#include "ssh-receive.h"
#include "encryptors.h"

static struct list_header_s list_encrypt_ops=INIT_LIST_HEADER;

struct encrypt_ops_s *get_encrypt_ops_container(struct list_element_s *list)
{
    return (struct encrypt_ops_s *) (((char *) list) - offsetof(struct encrypt_ops_s, list));
}

void add_encrypt_ops(struct encrypt_ops_s *ops)
{
    add_list_element_last(&list_encrypt_ops, &ops->list);
}

struct encrypt_ops_s *get_next_encrypt_ops(struct encrypt_ops_s *ops)
{
    if (ops) {
	struct list_element_s *next=ops->list.n;
	return (next) ? get_encrypt_ops_container(next) : NULL;

    } else {
	struct list_element_s *head=list_encrypt_ops.head;
	return (head) ? get_encrypt_ops_container(head) : NULL;

    }

    return NULL;
}

void reset_encrypt(struct ssh_session_s *session, struct algo_list_s *algo_cipher, struct algo_list_s *algo_hmac)
{
    struct ssh_send_s *send=&session->send;
    struct ssh_encrypt_s *encrypt=&send->encrypt;
    struct keyexchange_s *keyexchange=session->keyexchange;
    char *ciphername=NULL;
    char *hmacname=NULL;
    struct encrypt_ops_s *ops=(struct encrypt_ops_s *) algo_cipher->ptr;

    logoutput("reset_encrypt");

    remove_encryptors(encrypt);

    free_ssh_string(&encrypt->cipher_key);
    free_ssh_string(&encrypt->cipher_iv);
    free_ssh_string(&encrypt->hmac_key);

    memset(encrypt->ciphername, '\0', sizeof(encrypt->ciphername));
    memset(encrypt->hmacname, '\0', sizeof(encrypt->hmacname));

    ciphername=algo_cipher->sshname;
    if (algo_hmac) hmacname=algo_hmac->sshname;

    if ((* ops->get_encrypt_flag)(ciphername, hmacname, "parallel")==1) {

	encrypt->max_count=4; /* seems like a good choice, make it configurable; it's also possible to set this to 0: no limit decryptors allowed*/
	encrypt->flags |= SSH_DECRYPT_FLAG_PARALLEL;

    } else {

	if (encrypt->flags & SSH_DECRYPT_FLAG_PARALLEL) encrypt->flags -= SSH_DECRYPT_FLAG_PARALLEL;
	encrypt->max_count=1;

    }

    encrypt->ops=ops;

    strcpy(encrypt->ciphername, ciphername);
    if (hmacname) strcpy(encrypt->hmacname, hmacname);
    move_ssh_string(&encrypt->cipher_key, &keyexchange->data.cipher_key_c2s);
    move_ssh_string(&encrypt->cipher_iv, &keyexchange->data.cipher_iv_c2s);
    move_ssh_string(&encrypt->hmac_key, &keyexchange->data.hmac_key_c2s);

}

unsigned int build_cipher_list_c2s(struct ssh_session_s *session, struct algo_list_s *alist, unsigned int start)
{
    struct encrypt_ops_s *ops=NULL;

    ops=get_next_encrypt_ops(NULL);

    while (ops) {

	start=(* ops->populate_cipher)(session, ops, alist, start);
	ops=get_next_encrypt_ops(ops);

    }

    return start;

}

unsigned int build_hmac_list_c2s(struct ssh_session_s *session, struct algo_list_s *alist, unsigned int start)
{
    struct encrypt_ops_s *ops=NULL;

    ops=get_next_encrypt_ops(NULL);

    while (ops) {

	start=(* ops->populate_hmac)(session, ops, alist, start);
	ops=get_next_encrypt_ops(ops);

    }

    return start;

}
