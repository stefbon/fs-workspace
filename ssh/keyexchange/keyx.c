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
#include "ssh-connections.h"
#include "ssh-data.h"
#include "ssh-utils.h"
#include "ssh-keyexchange.h"
#include "ssh-send.h"
#include "ssh-receive.h"
#include "options.h"

extern struct fs_options_s fs_options;
static struct list_header_s list_keyex_ops=INIT_LIST_HEADER;

void add_keyex_ops(struct keyex_ops_s *ops)
{
    add_list_element_last(&list_keyex_ops, &ops->list);
}

static unsigned int build_hostkey_list(struct ssh_connection_s *c, struct algo_list_s *alist, unsigned int start)
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
	    alist[start].sshname=(char *) algo->name;
	    alist[start].libname=(char *) algo->libname;
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
	if (algo==NULL || (algo->flags & SSH_PKALGO_FLAG_SKIP)) goto next2;

	if (alist) {

	    alist[start].type=SSH_ALGO_TYPE_HOSTKEY;
	    alist[start].order=SSH_ALGO_ORDER_MEDIUM;
	    alist[start].sshname=(char *) cert->name;
	    alist[start].libname=(char *) cert->libname;
	    alist[start].ptr=NULL;

	}

	start++;

	next2:

	cert=get_next_pkcert(cert, NULL);

    }

    return start;

}

/* get a list of supported key exchange algo's like diffie-hellman */

static unsigned int build_keyex_list(struct ssh_connection_s *c, struct algo_list_s *alist, unsigned int start)
{
    struct list_element_s *list=NULL;

    if ((c->setup.flags & SSH_SETUP_FLAG_TRANSPORT)==0) {

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

    /* add the keyex methods already registered */

    list=get_list_head(&list_keyex_ops, 0);

    while (list) {

	struct keyex_ops_s *ops=((struct keyex_ops_s *)((char *)list - offsetof(struct keyex_ops_s, list)));

	start=(* ops->populate)(c, ops, alist, start);
	list=get_next_element(list);

    }

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

static unsigned int build_algo_list(struct ssh_connection_s *c, struct algo_list_s *algos)
{
    unsigned int start=0;

    start=build_cipher_list_s2c(c, algos, start);
    start=build_hmac_list_s2c(c, algos, start);
    start=build_compress_list_s2c(c, algos, start);
    start=build_cipher_list_c2s(c, algos, start);
    start=build_hmac_list_c2s(c, algos, start);
    start=build_compress_list_c2s(c, algos, start);
    start=build_hostkey_list(c, algos, start);
    start=build_keyex_list(c, algos, start);
    /* ignore the languages */

    return start;
}

static int set_keyex_method(struct ssh_keyex_s *k, struct algo_list_s *algo_kex, struct algo_list_s *algo_pk)
{
    struct keyex_ops_s *ops=(struct keyex_ops_s *) algo_kex->ptr;
    struct ssh_pkalgo_s *pkalgo=NULL;
    char *name=NULL;
    int result=-1;

    memset(k, 0, sizeof(struct ssh_keyex_s));
    k->pkauth.type=0;

    /* check the server hostkey algo is supported  (must be since it's a result of the algo negotiation) */

    name=algo_pk->sshname;
    pkalgo = get_pkalgo((char *)name, strlen(name), NULL);

    if (pkalgo) {

	/* hostkey is like ssh-rsa, ssh-dsa */

	logoutput("set_keyex_method: hostkey pkalgo %s supported", name);
	k->pkauth.type=SSH_PKAUTH_TYPE_PKALGO;
	k->pkauth.method.pkalgo=pkalgo;

    } else {
	struct ssh_pkcert_s *pkcert=NULL;

	/* hostkey is like ssh-ed25519-cert-v01@openssh.com */

	pkcert=get_pkcert((char *)name, strlen(name), NULL);

	if (pkcert) {

	    logoutput("set_keyex_method: hostkey pkcert %s supported", name);
	    k->pkauth.type=SSH_PKAUTH_TYPE_PKCERT;
	    k->pkauth.method.pkcert=pkcert;

	} else {

	    logoutput("set_keyex_method: hostkey method %s not supported", name);
	    goto out;

	}

    }

    /* initialize the keyex calls like generate client k and compute shared key */

    k->ops=ops;

    if ((* ops->init)(k, algo_kex->sshname)==0) {

	logoutput("set_keyex_method: set method %s", algo_kex->sshname);
	result=0;

    } else {

	logoutput("set_keyex_method: failed to set to method %s", algo_kex->sshname);

    }

    out:
    return result;

}

int key_exchange(struct ssh_connection_s *connection)
{
    struct ssh_setup_s *setup=&connection->setup;
    struct ssh_receive_s *receive=&connection->receive;
    struct ssh_keyexchange_s *kex=&setup->phase.transport.type.kex;
    unsigned int count=build_algo_list(connection, NULL) + 1;
    struct algo_list_s algos[count];
    unsigned int error=EIO;
    int result=-1;
    struct ssh_keyex_s keyex;
    struct timespec expire;

    logoutput("key_exchange (algos count=%i)", count);

    /* fill the algo list with supported algorithms for:
	- encryption (aes...)
	- digest (hmac...)
	- publickey (ssh-rsa...)
	- compression (zlib...)
	- key exchange (dh...)
    */

    init_algo_list(algos, count);
    count=build_algo_list(connection, algos);
    kex->algos=algos;

    /* start the exchange of algo's
	output is stored in session->setup.phase.transport.kex.chosen[SSH_ALGO_TYPE_...] 
	which are the indices of the algo array  */

    if (start_algo_exchange(connection)==-1) {

	logoutput("key_exchange: algo exchange failed");
	goto out;

    }

    if (check_ssh_connection_setup(connection, "transport", SSH_TRANSPORT_TYPE_KEX, SSH_KEX_FLAG_KEXINIT_C2S | SSH_KEX_FLAG_KEXINIT_S2C)<1) {

	logoutput("_setup_ssh_session: error: keyexchange failed");
	goto out;

    }

    if (kex->chosen[SSH_ALGO_TYPE_HOSTKEY]==-1) {

	logoutput("key_exchange: hostkey algo not found");
	goto out;

    }


    if (kex->chosen[SSH_ALGO_TYPE_KEX]==-1) {

	logoutput("key_exchange: kex algo not found");
	goto out;

    }

    if (set_keyex_method(&keyex, &algos[kex->chosen[SSH_ALGO_TYPE_KEX]], &algos[kex->chosen[SSH_ALGO_TYPE_HOSTKEY]])==0) {

	logoutput("key_exchange: keyex method set to %s using hostkey type %s", algos[kex->chosen[SSH_ALGO_TYPE_KEX]].sshname, algos[kex->chosen[SSH_ALGO_TYPE_HOSTKEY]].sshname);

    } else {

	goto out;

    }

    if (start_kex_dh(connection, &keyex)==-1) {

	logoutput("key_exchange: keyex method failed");
	goto out;

    }

    logoutput("key_exchange: send newkeys");

    /* send newkeys to server */

    if (send_newkeys_message(connection)==0) {

	logoutput("key_exchange: newkeys send");

    } else {

	logoutput("key_exchange: failed to send newkeys");
	goto out;

    }

    /* wait for all the flags to be set */

    if (wait_ssh_connection_setup_change(connection, "transport", SSH_TRANSPORT_TYPE_KEX, 0, NULL, NULL)==0) {
	int index_compr=kex->chosen[SSH_ALGO_TYPE_COMPRESS_S2C];
	int index_cipher=kex->chosen[SSH_ALGO_TYPE_CIPHER_S2C];
	int index_hmac=kex->chosen[SSH_ALGO_TYPE_HMAC_S2C];
	struct algo_list_s *algo_compr=&algos[index_compr];
	struct algo_list_s *algo_cipher=&algos[index_cipher];
	struct algo_list_s *algo_hmac=(index_hmac>=0) ? &algos[index_hmac] : NULL;

	/* reset cipher, hmac and compression to the one aggreed in kexinit
	    new keys are already computed */

	reset_decompress(connection, algo_compr);
	reset_decrypt(connection, algo_cipher, algo_hmac);
	result=0;
	set_ssh_receive_behaviour(connection, "kexfinish");

    } else {

	logoutput("key_exchange: error witing for newkeys from server");
	error=EPROTO;

    }

    out:
    return result;

}

void init_keyex_once()
{
//     init_keyex_ecdh();
    init_keyex_dh();

}
