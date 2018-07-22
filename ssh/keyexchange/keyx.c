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
#include "algo-exchange.h"
#include "key-exchange.h"
#include "dh.h"
#include "ssh-send.h"
#include "ssh-receive.h"
#include "options.h"

extern struct fs_options_s fs_options;

static unsigned int build_hostkey_list(struct ssh_session_s *session, struct algo_list_s *alist, unsigned int start)
{
    struct ssh_pkalgo_s *algo=NULL;
    struct ssh_pkcert_s *cert=NULL;

    /* walk every pkalgo */

    algo=get_next_pkalgo(algo, NULL);

    while (algo) {

	if (algo->flags & SSH_PKALGO_FLAG_SKIP) goto next1;

	if (alist) {

	    alist[start].type=SSH_ALGO_TYPE_HOSTKEY;
	    alist[start].order=(algo->flags & SSH_PKALGO_FLAG_PREFERRED) ? SSH_ALGO_ORDER_HIGH : SSH_ALGO_ORDER_MEDIUM; /**/
	    alist[start].sshname=algo->name;
	    alist[start].libname=algo->libname;
	    alist[start].ptr=NULL;

	}

	start++;

	next1:

	algo=get_next_pkalgo(algo, NULL);

    }

    /* walk every pkcert */

    cert=get_next_pkcert(cert, NULL);

    while (cert) {

	algo=get_pkalgo_byid(cert->pkalgo_id, NULL);

	if (algo==NULL || algo->flags & SSH_PKALGO_FLAG_SKIP) goto next2;

	if (alist) {

	    alist[start].type=SSH_ALGO_TYPE_HOSTKEY;
	    alist[start].order=SSH_ALGO_ORDER_MEDIUM;
	    alist[start].sshname=cert->name;
	    alist[start].libname=cert->libname;
	    alist[start].ptr=NULL;

	}

	start++;

	next2:

	cert=get_next_pkcert(cert, NULL);

    }

    return start;

}

/* get a list of supported key exchange algo's like diffie-hellman */

static unsigned int build_keyx_list(struct ssh_session_s *session, struct algo_list_s *alist, unsigned int start, struct sessionphase_s *sessionphase)
{

    if (sessionphase->phase==SESSION_PHASE_SETUP) {

	if (fs_options.ssh.flags & _OPTIONS_SSH_FLAG_SUPPORT_EXT_INFO) {

	    if (alist) {

		alist[start].type=SSH_ALGO_TYPE_KEX;
		alist[start].order=SSH_ALGO_ORDER_MEDIUM; /* RFC 8380 2.1 Signaling of Extension Negotiation in SSH_MSG_KEXINIT */
		alist[start].sshname="ext-info-c";
		alist[start].libname="ext-info-c";
		alist[start].ptr=NULL;

	    }

	    start++;

	}

    }

    start=populate_keyx_dh(session, alist, start);
    start=populate_keyx_ecdh(session, alist, start);

    return start;

}

static void init_algo_list(struct algo_list_s *algo, unsigned int count)
{
    memset(algo, 0, sizeof(struct algo_list_s) * count);

    for (unsigned int i=0; i<count; i++) {

	algo[i].type=-1;
	algo[i].order=0;
	algo[i].sshname=NULL;
	algo[i].libname=NULL;
	algo[i].ptr=NULL;

    }

}

static unsigned int build_algo_list(struct ssh_session_s *session, struct algo_list_s *algos, struct sessionphase_s *sessionphase)
{
    unsigned int start=0;

    start=build_cipher_list_s2c(session, algos, start);
    start=build_hmac_list_s2c(session, algos, start);
    start=build_compress_list_s2c(session, algos, start);
    start=build_cipher_list_c2s(session, algos, start);
    start=build_hmac_list_c2s(session, algos, start);
    start=build_compress_list_c2s(session, algos, start);
    start=build_hostkey_list(session, algos, start);
    start=build_keyx_list(session, algos, start, sessionphase);

    /* ignore the languages */

    return start;
}

static void free_keyx_dummy(struct ssh_keyx_s *keyx)
{
}

static void init_keyx(struct ssh_keyx_s *keyx)
{

    memset(keyx, 0, sizeof(struct ssh_keyx_s));
    memset(keyx->digestname, '\0', sizeof(keyx->digestname));

    keyx->pkauth.type=0;
    keyx->free=free_keyx_dummy;

}

int key_exchange(struct ssh_session_s *session, struct payload_queue_s *queue, struct sessionphase_s *sessionphase)
{
    struct keyexchange_s keyexchange;
    unsigned int count=build_algo_list(session, NULL, sessionphase) + 1;
    struct algo_list_s algos[count];
    unsigned int error=0;
    int result=-1;

    logoutput("key_exchange (count=%i)", count);

    init_algo_list(algos, count);
    count=build_algo_list(session, algos, sessionphase);

    init_ssh_string(&keyexchange.data.kexinit_client);
    init_ssh_string(&keyexchange.data.kexinit_server);
    keyexchange.data.algos=algos;
    for (unsigned int i=0; i<SSH_ALGO_TYPES_COUNT; i++) keyexchange.data.chosen[i]=-1;
    init_ssh_string(&keyexchange.data.cipher_key_c2s);
    init_ssh_string(&keyexchange.data.cipher_iv_c2s);
    init_ssh_string(&keyexchange.data.hmac_key_c2s);
    init_ssh_string(&keyexchange.data.cipher_key_s2c);
    init_ssh_string(&keyexchange.data.cipher_iv_s2c);
    init_ssh_string(&keyexchange.data.hmac_key_s2c);

    session->keyexchange=&keyexchange;
    keyexchange.queue=queue;

    /* adjust the receive behaviour to the kexinit phase */

    start_receive_kexinit(&session->receive);

    /* start the exchange of algo's
	output is stored in keyexchange.data.chosen[SSH_ALGO_TYPE_...] 
	which are the indices of the algo array */

    if (start_algo_exchange(session, sessionphase)==-1) {

	logoutput("key_exchange: algo exchange failed");
	set_sessionphase_failed(sessionphase);
	goto out;

    }

    if ((sessionphase->status & SESSION_STATUS_GENERIC_FAILED)==0 && compare_sessionphase(session, sessionphase)==0) {
	struct ssh_keyx_s keyx;

	/* start the exchange of keys */

	init_keyx(&keyx);

	if (keyexchange.data.chosen[SSH_ALGO_TYPE_KEX]>=0 && keyexchange.data.chosen[SSH_ALGO_TYPE_HOSTKEY]>=0) {
	    char *algo=algos[keyexchange.data.chosen[SSH_ALGO_TYPE_HOSTKEY]].sshname;
	    char *name=algos[keyexchange.data.chosen[SSH_ALGO_TYPE_KEX]].sshname;
	    struct ssh_pkalgo_s *pkalgo=NULL;

	    pkalgo = get_pkalgo((char *)algo, strlen(algo), NULL);

	    if (pkalgo) {

		logoutput("key_exchange: hostkey pkalgo %s supported", algo);
		keyx.pkauth.type=SSH_PKAUTH_TYPE_PKALGO;
		keyx.pkauth.method.pkalgo=pkalgo;

	    } else {
		struct ssh_pkcert_s *pkcert=NULL;

		pkcert=get_pkcert((char *)algo, strlen(algo), NULL);

		if (pkcert) {

		    logoutput("key_exchange: hostkey pkcert %s supported", algo);
		    keyx.pkauth.type=SSH_PKAUTH_TYPE_PKCERT;
		    keyx.pkauth.method.pkcert=pkcert;

		} else {

		    logoutput("key_exchange: hostkey method %s not supported", algo);
		    set_sessionphase_failed(sessionphase);
		    goto out;

		}

	    }

	    if (set_keyx_dh(&keyx, name, &error)==0) {

		logoutput("key_exchange: keyx method set to %s", name);

	    } else {

		if (error==EINVAL) {

		    logoutput("key_exchange: keyx method %s not supported", name);

		} else {

		    logoutput("key_exchange: error %i keyx method %s not supported (%s)", error, name, strerror(error));

		}

		set_sessionphase_failed(sessionphase);
		goto out;

	    }

	    if (start_key_exchange(session, &keyx, sessionphase)==-1) {

		logoutput("key_exchange: keyx method %s failed", name);
		(* keyx.free)(&keyx);
		set_sessionphase_failed(sessionphase);
		goto out;

	    }

	    (* keyx.free)(&keyx);
	    logoutput("key_exchange: keyx method %s success", name);

	}

    } else {

	logoutput("key_exchange: hostkey algo and/or kex algo not found");
	set_sessionphase_failed(sessionphase);
	goto out;

    }

    if ((sessionphase->status & SESSION_STATUS_GENERIC_FAILED)==0 && compare_sessionphase(session, sessionphase)==0) {

	logoutput("key_exchange: send newkeys");

	/* send newkeys to server */

	if (send_newkeys_message(session)==0) {

	    logoutput("key_exchange: newkeys send");

	} else {

	    logoutput("key_exchange: failed to send newkeys");
	    set_sessionphase_failed(sessionphase);
	    goto out;

	}

    }

    /* wait for newkeys from server */

    if (wait_status_sessionphase(session, sessionphase, SESSION_STATUS_KEYEXCHANGE_NEWKEYS_S2C)==0) {
	int index_compr=keyexchange.data.chosen[SSH_ALGO_TYPE_COMPRESS_S2C];
	int index_cipher=keyexchange.data.chosen[SSH_ALGO_TYPE_CIPHER_S2C];
	int index_hmac=keyexchange.data.chosen[SSH_ALGO_TYPE_HMAC_S2C];
	struct algo_list_s *algo_compr=&algos[index_compr];
	struct algo_list_s *algo_cipher=&algos[index_cipher];
	struct algo_list_s *algo_hmac=(index_hmac>=0) ? &algos[index_hmac] : NULL;
	struct ssh_receive_s *receive=&session->receive;

	get_current_time(&receive->newkeys);
	reset_decompress(session, algo_compr);
	reset_decrypt(session, algo_cipher, algo_hmac);
	finish_receive_newkeys(receive); /* signal the waiting thread which received the newkeys message to continue */

	set_sessionphase_success(sessionphase);

	logoutput("key_exchange: received newkeys, key exchange completed");
	result=0;

    } else {

	logoutput("key_exchange: failed to wait for completion newkeys s2c");
	set_sessionphase_failed(sessionphase);

    }

    out:

    free_ssh_string(&keyexchange.data.cipher_key_c2s);
    free_ssh_string(&keyexchange.data.cipher_iv_c2s);
    free_ssh_string(&keyexchange.data.hmac_key_c2s);
    free_ssh_string(&keyexchange.data.cipher_key_s2c);
    free_ssh_string(&keyexchange.data.cipher_iv_s2c);
    free_ssh_string(&keyexchange.data.hmac_key_s2c);

    session->keyexchange=NULL;

    return result;

}
