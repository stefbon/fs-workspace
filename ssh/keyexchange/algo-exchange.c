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
#include "ssh-send.h"
#include "ssh-receive.h"
#include "compare.h"

static int _store_kexinit_common(struct ssh_string_s *kexinit, struct ssh_payload_s *payload, unsigned int *error)
{

    *error=0;

    if (create_ssh_string(kexinit, payload->len, payload->buffer)==0) {

	*error=ENOMEM;
	kexinit->len=0;
	return -1;

    }

    return 0;

}

int store_kexinit_server(struct ssh_keyexchange_s *kex, struct ssh_payload_s *payload, unsigned int *error)
{
    struct ssh_string_s *kexinit=&kex->kexinit_server;
    return _store_kexinit_common(kexinit, payload, error);
}

int store_kexinit_client(struct ssh_keyexchange_s *kex, struct ssh_payload_s *payload, unsigned int *error)
{
    struct ssh_string_s *kexinit=&kex->kexinit_client;
    return _store_kexinit_common(kexinit, payload, error);
}

void free_kexinit_server(struct ssh_keyexchange_s *kex)
{
    struct ssh_string_s *kexinit=&kex->kexinit_server;
    free_ssh_string(kexinit);
}

void free_kexinit_client(struct ssh_keyexchange_s *kex)
{
    struct ssh_string_s *kexinit=&kex->kexinit_client;
    free_ssh_string(kexinit);
}

static int setup_cb_receive_kexinit(struct ssh_connection_s *connection, void *data)
{
    set_ssh_receive_behaviour(connection, "kexinit");
    return 0;
}

static int handle_kexinit_reply(struct ssh_connection_s *connection, struct ssh_payload_s *payload)
{
    return (payload->type==SSH_MSG_KEXINIT) ? 0 : -1;
}

/* get the SSH_MSG_KEXINIT message from server */

int start_algo_exchange(struct ssh_connection_s *connection)
{
    struct ssh_setup_s *setup=&connection->setup;
    struct ssh_keyexchange_s *kex=&setup->phase.transport.type.kex;
    struct algo_list_s *algos=kex->algos;
    struct ssh_payload_s *payload=NULL;
    unsigned int error=EIO;
    int result=-1;
    int index=0;

    /* send kexinit and wait for server to reply */

    logoutput("start_algo_exchange: send kexinit");

    if (send_kexinit_message(connection)==-1) {

	logoutput("start_algo_exchange: failed sending kexinit packet");
	goto out;

    }

    payload=receive_message_common(connection, handle_kexinit_reply, &error);

    if (payload) {

	/* copy the payload for the computation of the H (RFC4253 8.  Diffie-Hellman Key Exchange) */

	if (store_kexinit_server(kex, payload, &error)==0) {

	    result=change_ssh_connection_setup(connection, "transport", SSH_TRANSPORT_TYPE_KEX, SSH_KEX_FLAG_KEXINIT_S2C, 0, setup_cb_receive_kexinit, NULL);

	} else {

	    logoutput("start_algo_exchange: error %i saving kexinit s2c message (%s)", error, strerror(error));

	}

    } else {

	logoutput("start_algo_exchange: failed receiving kexinit packet");
	goto out;

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

    if (compare_msg_kexinit(connection)==-1) {

	logoutput("start_algo_exchange: compare msg kexinit failed");
	goto out;

    }

    /* correct mac names for combined cipher/mac algo's */

    index=kex->chosen[SSH_ALGO_TYPE_CIPHER_C2S];

    if (strcmp(algos[index].sshname, "chacha20-poly1305@openssh.com")==0) {

	/* disable the mac */
	kex->chosen[SSH_ALGO_TYPE_HMAC_C2S]=-1;

    } else {
	unsigned int index2=kex->chosen[SSH_ALGO_TYPE_HMAC_C2S];

	if (algos[index].ptr != algos[index2].ptr) {

	    logoutput("start_algo_exchange: internal error finding common methods");
	    goto out;

	}

    }

    index=kex->chosen[SSH_ALGO_TYPE_CIPHER_S2C];

    if (strcmp(algos[index].sshname, "chacha20-poly1305@openssh.com")==0) {

	/* disable the mac */
	kex->chosen[SSH_ALGO_TYPE_HMAC_S2C]=-1;

    } else {
	unsigned int index2=kex->chosen[SSH_ALGO_TYPE_HMAC_S2C];

	if (algos[index].ptr != algos[index2].ptr) {

	    logoutput("start_algo_exchange: internal error finding common methods");
	    goto out;

	}

    }

    return 0;

    out:
    return result;

}
