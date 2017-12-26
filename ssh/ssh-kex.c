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

#include "ssh-keyx.h"
#include "ssh-data.h"
#include "ssh-encryption.h"
#include "ssh-mac.h"
#include "ssh-compression.h"
#include "ssh-kexinit.h"
#include "ssh-send-kexinit.h"
#include "ssh-queue-payload.h"
#include "ssh-send.h"

#include "ssh-utils.h"

static void sendproc_newkeys_post(struct ssh_session_s *session, struct ssh_payload_s *payload, void *ptr)
{
    struct keyexchange_s *keyexchange=session->keyexchange;
    struct session_keydata_s *keydata=&keyexchange->keydata;
    struct ssh_kexinit_algo *algos=&keydata->algos;
    unsigned int error=0;

    logoutput("sendproc_newkeys_post");

    /* here do the free / set decryption etc */

    close_encrypt(session);
    free_encrypt(session);

    if (set_encryption(session, algos->encryption_c2s, &error)==0) {

	logoutput("sendproc_newkeys_post: encryption method c2s set to %s", algos->encryption_c2s);

    } else {

	logoutput("sendproc_newkeys_post: error %i setting encryption method c2s to %s (%s)", error, algos->encryption_c2s, strerror(error));
	keydata->status|=KEYEXCHANGE_STATUS_ERROR;
	return;

    }

    free_c2s_mac(session);

    if (set_hmac_c2s(session, algos->hmac_c2s, &error)==0) {

	logoutput("sendproc_newkeys_post: hmac method c2s %s", algos->hmac_c2s);

    } else {

	logoutput("sendproc_newkeys_post: error %i setting hmac method c2s to %s (%s)", error, algos->hmac_c2s, strerror(error));
	keydata->status|=KEYEXCHANGE_STATUS_ERROR;
	return;

    }

    if (set_compression_c2s(session, algos->compression_c2s, &error)==0) {

	logoutput("sendproc_newkeys_post: set compression methods c2s to %s", algos->compression_c2s);

    } else {

	logoutput("sendproc_newkeys_post: error %i setting compression methods c2s to %s (%s)", error, algos->compression_c2s, strerror(error));
	keydata->status|=KEYEXCHANGE_STATUS_ERROR;
	return;

    }

    keydata->status|=KEYEXCHANGE_STATUS_NEWKEYS_C2S;

}

static void sendproc_newkeys_post_error(struct ssh_session_s *session, struct ssh_payload_s *payload, void *ptr, unsigned int error)
{
    struct keyexchange_s *keyexchange=session->keyexchange;
    struct session_keydata_s *keydata=&keyexchange->keydata;
    struct ssh_kexinit_algo *algos=&keydata->algos;

    logoutput("sendproc_newkeys_post_error");
}

static int sendproc_newkeys_message(struct ssh_session_s *session, unsigned int *seq)
{
    struct ssh_sendproc_s sendproc;

    sendproc.get_payload=send_newkeys;
    sendproc.post_send=sendproc_newkeys_post;
    sendproc.post_send_error=sendproc_newkeys_post_error;

    return sendproc_ssh_message(session, &sendproc, NULL, seq);
}

static struct ssh_payload_s *get_ssh_payload_kex(struct ssh_session_s *session, struct timespec *expire, unsigned int *seq, unsigned int *error)
{
    struct ssh_payload_s *payload=NULL;
    struct keyexchange_s *keyexchange=session->keyexchange;

    pthread_mutex_lock(&keyexchange->mutex);

    while (keyexchange->list.head==NULL) {

	if (pthread_cond_timedwait(&keyexchange->cond, &keyexchange->mutex, expire)==ETIMEDOUT) {

	    pthread_mutex_unlock(&keyexchange->mutex);
	    *error=ETIMEDOUT;
	    return NULL;

	}

    }

    payload=keyexchange->list.head;

    if (payload->next) {

	keyexchange->list.head=payload->next;

    } else {

	keyexchange->list.head=NULL;
	keyexchange->list.tail=NULL;

    }

    pthread_mutex_unlock(&keyexchange->mutex);

    return payload;

}

int process_key_exchange(struct ssh_session_s *session, struct ssh_payload_s *payload, unsigned char init)
{
    struct keyexchange_s keyexchange;
    struct ssh_kexinit_algo *algos=NULL;
    struct session_keydata_s *keydata=NULL;
    struct ssh_keyx_s keyx;
    unsigned int sequence=0;
    unsigned int error=0;
    int result=-1;
    struct timespec expire;

    get_session_expire_init(session, &expire);

    pthread_mutex_init(&keyexchange.mutex, NULL);
    pthread_cond_init(&keyexchange.cond, NULL);
    keyexchange.list.head=NULL;
    keyexchange.list.tail=NULL;
    keydata=&keyexchange.keydata;
    init_keydata(keydata);
    algos=&keydata->algos;

    if (init==1) {

	keyexchange.get_payload_kex=get_ssh_payload;

    } else {

	keyexchange.get_payload_kex=get_ssh_payload_kex;

    }

    session->keyexchange=&keyexchange;

    if ((init==1 && payload) || (init==0 && payload==NULL)) {

	goto free_keyexchange;

    }

    keydata->status=0;

    /* send kexinit and wait for server to reply */

    logoutput("process_key_exchange: send kexinit");

    if (send_ssh_message(session, send_kexinit, NULL, &sequence)==-1) {

	keydata->status|=KEYEXCHANGE_STATUS_ERROR;
	error=EIO;
	logoutput("process_key_exchange: error %i sending packet (%s)", error, strerror(error));
	goto free_keyexchange;

    }

    keydata->status|=KEYEXCHANGE_STATUS_KEYINIT_C2S;

    if (init==1) {

	get_session_expire_init(session, &expire);

	/* get/wait for kexinit from server */

	payload=(keyexchange.get_payload_kex)(session, &expire, &sequence, &error);

	if (! payload) {

	    keydata->status|=KEYEXCHANGE_STATUS_ERROR;
	    logoutput("process_key_exchange: error %i waiting for packet (%s)", error, strerror(error));
	    goto free_keyexchange;

	}

    }

    if (payload->type==SSH_MSG_KEXINIT) {

	if (init==1) logoutput_info("process_key_exchange: received server kexinit message");

	/* copy the payload for the computation of the H (RFC4253 8.  Diffie-Hellman Key Exchange) */

	if (store_kexinit_server(session, payload, &error)==0) {

	    logoutput("process_key_exchange: saved server kexinit message");

	} else {

	    keydata->status|=KEYEXCHANGE_STATUS_ERROR;
	    if (error==0) error=EIO;
	    logoutput("process_key_exchange: error storing server kexinit message (%i:%s)", error, strerror(error));
	    goto free_keyexchange;

	}

	keydata->status|=KEYEXCHANGE_STATUS_KEYINIT_S2C;

    } else {

	keydata->status|=KEYEXCHANGE_STATUS_ERROR;
	logoutput("process_key_exchange: received %i message. not expecting it, error", payload->type);
	error=(error>0) ? error : EPROTO;
	goto free_keyexchange;

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

    if (compare_msg_kexinit(session, algos)==0) {

	/* correct mac names for combined cipher/mac algo's */

	if (strcmp(algos->encryption_c2s, "chacha20-poly1305@openssh.com")==0) strcpy(algos->hmac_c2s, algos->encryption_c2s);
	if (strcmp(algos->encryption_s2c, "chacha20-poly1305@openssh.com")==0) strcpy(algos->hmac_s2c, algos->encryption_s2c);

    } else {

	logoutput("process_key_exchange: error finding common methods");
	keydata->status|=KEYEXCHANGE_STATUS_ERROR;
	error=EIO;
	goto free_keyexchange;

    }

    /* key exchange (dh, ecdh, ....) */

    init_keyx(&keyx);

    if (set_keyx(&keyx, algos->keyexchange, algos->hostkey, &error)==0) {

	logoutput("process_key_exchange: set keyx method to %s with hostkey type %s", algos->keyexchange, algos->hostkey);

    } else {

	logoutput("process_key_exchange: error %i setting keyx method %s (%s)", error, algos->keyexchange, strerror(error));
	keydata->status|=KEYEXCHANGE_STATUS_ERROR;
	goto free_keyexchange;

    }

    /* start key exchange */

    logoutput("process_key_exchange: start keyexchange");

    if (start_keyx(session, &keyx, algos)==-1) {

	keydata->status|=KEYEXCHANGE_STATUS_ERROR;
	(* keyx.free)(&keyx);
	goto free_keyexchange;

    }

    (* keyx.free)(&keyx);

    /* send newkeys */

    logoutput("process_key_exchange: send newkeys");

    /* TODO: use the sendproc with cb's
	these cb's will complete the newkeys/algo's while blocking the send process */

    if (sendproc_newkeys_message(session, &sequence)==-1) {

	keydata->status|=KEYEXCHANGE_STATUS_ERROR;
	goto free_keyexchange;

    }

    if (init==1) switch_send_process(session, "session");

    /* get/wait for signal NEWKEYS received from the server */

    pthread_mutex_lock(&keyexchange.mutex);

    while(!(keyexchange.keydata.status & KEYEXCHANGE_STATUS_NEWKEYS_S2C)) {

	pthread_cond_wait(&keyexchange.cond, &keyexchange.mutex);

    }

    pthread_mutex_unlock(&keyexchange.mutex);

    if (keyexchange.keydata.status & KEYEXCHANGE_STATUS_NEWKEYS_S2C) {

	/* switch to new algo's for s2c */

	close_decrypt(session);
	free_decrypt(session);

	if (set_decryption(session, algos->encryption_s2c, &error)==0) {

	    logoutput("process_key_exchange: decryption method s2c set to %s", algos->encryption_s2c);

	} else {

	    logoutput("process_key_exchange: error %i setting decryption method s2c to %s (%s)", error, algos->encryption_s2c, strerror(error));
	    keydata->status|=KEYEXCHANGE_STATUS_ERROR;
	    set_decryption_newkeys_nonwait(session);
	    goto free_keyexchange;

	}

	if (set_hmac_s2c(session, algos->hmac_s2c, &error)==0) {

	    logoutput("process_key_exchange: hmac method s2c %s", algos->hmac_s2c);

	} else {

	    logoutput("process_key_exchange: error %i setting hmac method s2c to %s (%s)", error, algos->hmac_s2c, strerror(error));
	    keydata->status|=KEYEXCHANGE_STATUS_ERROR;
	    set_decryption_newkeys_nonwait(session);
	    goto free_keyexchange;

	}

	if (set_compression_s2c(session, algos->compression_s2c, &error)==0) {

	    logoutput("process_key_exchange: set compression methods s2c to %s", algos->compression_s2c);

	} else {

	    logoutput("process_key_exchange: error %i setting compression methods s2c to %s (%s)", error, algos->compression_s2c, strerror(error));
	    keydata->status|=KEYEXCHANGE_STATUS_ERROR;
	    set_decryption_newkeys_nonwait(session);
	    goto free_keyexchange;

	}

	pthread_mutex_lock(&keyexchange.mutex);
	keyexchange.keydata.status|=KEYEXCHANGE_STATUS_FINISH_S2C;
	pthread_cond_broadcast(&keyexchange.cond);
	pthread_mutex_unlock(&keyexchange.mutex);

	set_decryption_newkeys_nonwait(session);

	/* here a "replace" from the old decrypt/hmac to the new ones */

	// if (init==1) {

	    // switch_process_rawdata_queue(session, "session");

	// } else {

	    /* TODO: unblock the receiving/decrypting process */

	// }

    } else {

	logoutput("process_key_exchange: received %i message. not expecting it, error", payload->type);
	keydata->status|=KEYEXCHANGE_STATUS_ERROR;
	goto free_keyexchange;

    }

    if (keydata->status==(KEYEXCHANGE_STATUS_KEYINIT_C2S | KEYEXCHANGE_STATUS_KEYINIT_S2C |
			    KEYEXCHANGE_STATUS_KEYX_C2S | KEYEXCHANGE_STATUS_KEYX_S2C |
			    KEYEXCHANGE_STATUS_NEWKEYS_C2S | KEYEXCHANGE_STATUS_NEWKEYS_S2C | KEYEXCHANGE_STATUS_FINISH_S2C)) {

	result=0;

    }

    free_keyexchange:

    /* free data and keys not required anymore */

    free_keydata(keydata);

    if (init==1) {

	if (payload) {

	    free(payload);
	    payload=NULL;

	}

    }

    keydata->status=0;
    session->keyexchange=NULL;

    logoutput("process_key_exchange: result %i", result);

    return result;

}
