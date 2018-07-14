/*
  2010, 2011, 2012, 2103, 2014, 2015, 2016, 2017 Stef Bon <stefbon@gmail.com>

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
#include <fcntl.h>
#include <dirent.h>
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

#include "main.h"
#include "logging.h"
#include "utils.h"

#include "ssh-common.h"
#include "ssh-common-protocol.h"

#include "ssh-data.h"
#include "ssh-utils.h"
#include "ssh-send.h"
#include "ssh-receive.h"
#include "compare.h"

static int _store_kexinit_common(struct ssh_string_s *kexinit, struct ssh_payload_s *payload, unsigned int *error)
{

    *error=0;

    if (create_ssh_string(kexinit, payload->len)==payload->len) {

	memcpy(kexinit->ptr, payload->buffer, payload->len);
	kexinit->len=payload->len;

    } else {

	*error=ENOMEM;
	kexinit->len=0;
	return -1;

    }

    return 0;

}

int store_kexinit_server(struct keyexchange_s *keyexchange, struct ssh_payload_s *payload, unsigned int *error)
{
    struct ssh_string_s *kexinit=&keyexchange->data.kexinit_server;
    return _store_kexinit_common(kexinit, payload, error);
}

int store_kexinit_client(struct keyexchange_s *keyexchange, struct ssh_payload_s *payload, unsigned int *error)
{
    struct ssh_string_s *kexinit=&keyexchange->data.kexinit_client;
    return _store_kexinit_common(kexinit, payload, error);
}

void free_kexinit_server(struct keyexchange_s *keyexchange)
{
    struct ssh_string_s *kexinit=&keyexchange->data.kexinit_server;
    free_ssh_string(kexinit);
}

void free_kexinit_client(struct keyexchange_s *keyexchange)
{
    struct ssh_string_s *kexinit=&keyexchange->data.kexinit_client;
    free_ssh_string(kexinit);
}

int start_algo_exchange(struct ssh_session_s *session, struct sessionphase_s *sessionphase)
{
    struct keyexchange_s *keyexchange=session->keyexchange;
    unsigned int error=0;
    int result=-1;
    struct algo_list_s *algos=keyexchange->data.algos;
    struct payload_queue_s *queue=keyexchange->queue;

    /* send kexinit and wait for server to reply */

    logoutput("start_algo_exchange: send kexinit");

    if (send_kexinit_message(session)==-1) {

	set_sessionphase_failed(sessionphase);
	logoutput("start_algo_exchange: failed sending kexinit packet");
	goto out;

    }

    if ((sessionphase->status & SESSION_STATUS_GENERIC_FAILED)==0 && compare_sessionphase(session, sessionphase)==0) {
	int change=0;
	struct ssh_payload_s *payload=NULL;
	struct timespec expire;
	unsigned int sequence=0;

	sessionphase->status|=SESSION_STATUS_KEYEXCHANGE_KEYINIT_C2S;
	change=change_status_sessionphase(session, sessionphase);
	if (change<0) goto out;

	/* get the SSH_MSG_KEXINIT message from server */

	get_session_expire_init(session, &expire);

	getkexinit:

	payload=get_ssh_payload(session, queue, &expire, &sequence, &error);

	if (! payload) {

	    set_sessionphase_failed(sessionphase);
	    logoutput("start_algo_exchange: error %i waiting for packet (%s)", error, strerror(error));
	    goto out;

	} else if (payload->type==SSH_MSG_KEXINIT) {

	    logoutput("start_algo_exchange: received kexinit message");

	} else {

	    logoutput("start_algo_exchange: received unexpected message (type %i)", payload->type);
	    set_sessionphase_failed(sessionphase);
	    free_payload(&payload);
	    goto out;

	}

	/* copy the payload for the computation of the H (RFC4253 8.  Diffie-Hellman Key Exchange) */

	if (store_kexinit_server(keyexchange, payload, &error)==0) {

	    logoutput("start_algo_exchange: saved kexinit s2c message");

	} else {

	    set_sessionphase_failed(sessionphase);
	    free_payload(&payload);
	    logoutput("start_algo_exchange: error %i saving kexinit s2c message (%s)", error, strerror(error));
	    goto out;

	}

	free_payload(&payload);
	sessionphase->status|=SESSION_STATUS_KEYEXCHANGE_KEYINIT_S2C;
	change=change_status_sessionphase(session, sessionphase);
	if (change<0) goto out;

    }

    /*
	    The default behaviour is that after the newkeys message the client
	    and the server use the algo's which are selected:
	    an algo for encryption c2s, an algo for mac c2s, and an algo for compression c2s
	    (and vice versa for s2c)

	    Sometimes the name for the cipher is not only a cipher, but also
	    a mac. then it's a cipher and mac combined.
	    like:

	    - chacha20-poly1305@openssh.com

	    in these cases the selected mac algo (which may also be "none") is ignored

	    See:

	    https://tools.ietf.org/html/draft-josefsson-ssh-chacha20-poly1305-openssh-00

	    Here the name of the mac algo is ignored according to the draft, and set to the same name
	    (in this case thus chacha20-poly1305@openssh.com)
	    to match the very custom/not-default behaviour

	    Although this combined cipher/mac has a different behaviour compared to the default algo's
	    here is tried to make the processing of messages (incoming and outgoing) simple and
	    without too much exceptions
    */

    /* compare the different suggested algo's */

    if (compare_msg_kexinit(session)==0) {
	struct exchange_data_s *data=&keyexchange->data;
	unsigned int index=0;

	/* correct mac names for combined cipher/mac algo's */

	index=data->chosen[SSH_ALGO_TYPE_CIPHER_C2S];

	if (strcmp(algos[index].sshname, "chacha20-poly1305@openssh.com")==0) {

	    data->chosen[SSH_ALGO_TYPE_HMAC_C2S]=-1;

	} else {
	    unsigned int index2=data->chosen[SSH_ALGO_TYPE_HMAC_C2S];

	    if (algos[index].ptr != algos[index2].ptr) {

		logoutput("start_algo_exchange: internal error finding common methods");
		set_sessionphase_failed(sessionphase);
		goto out;

	    }

	}

	index=data->chosen[SSH_ALGO_TYPE_CIPHER_S2C];

	if (strcmp(algos[index].sshname, "chacha20-poly1305@openssh.com")==0) {

	    data->chosen[SSH_ALGO_TYPE_HMAC_S2C]=-1;

	} else {
	    unsigned int index2=data->chosen[SSH_ALGO_TYPE_HMAC_S2C];

	    if (algos[index].ptr != algos[index2].ptr) {

		logoutput("start_algo_exchange: internal error finding common methods");
		set_sessionphase_failed(sessionphase);
		goto out;

	    }

	}

	result=0;

    } else {

	logoutput("start_algo_exchange: error finding common methods");
	set_sessionphase_failed(sessionphase);

    }

    out:
    return result;

}
