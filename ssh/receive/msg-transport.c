/*
  2010, 2011, 2012, 2103, 2014, 2015, 2016 Stef Bon <stefbon@gmail.com>

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
#include "ssh-common-protocol.h"

#include "ssh-receive.h"
#include "ssh-data.h"
#include "ssh-send.h"
#include "ssh-keyexchange.h"

#include "ssh-utils.h"
#include "extensions/extension.h"

/* various callbacks for SSH transport */

/* disconnect */

static void receive_msg_disconnect(struct ssh_session_s *session, struct ssh_payload_s *payload)
{
    unsigned int reason=0;
    unsigned int len=0;

    if (payload->len>=9) {

	reason=get_uint32(&payload->buffer[1]);
	len=get_uint32(&payload->buffer[5]);

    } else {

	reason=SSH_DISCONNECT_PROTOCOL_ERROR;

    }

    /* server send a disconnect: client must also disconnect immediatly  */

    if (len>0 && (9 + len <= payload->len)) {
	char string[len+1];

	memcpy(&string[0], &payload->buffer[9], len);
	string[len]='\0';

	logoutput("receive_msg_disconnect: received disconnect reason %i:%s", reason, string);

    } else {
	const char *string=get_disconnect_reason(reason);

	if (string) {

	    logoutput("receive_msg_disconnect: received disconnect reason %i:%s", reason, string);

	} else {

	    logoutput("receive_msg_disconnect: received disconnect reason %i", reason);

	}

    }

    free_payload(&payload);
    disconnect_ssh_session(session, 1, reason);

}

/* ignore */

static void receive_msg_ignore(struct ssh_session_s *session, struct ssh_payload_s *payload)
{
    free_payload(&payload);
}

/* not implemented */

static void receive_msg_unimplemented(struct ssh_session_s *session, struct ssh_payload_s *payload)
{

    if (payload->len >= 5) {
	struct ssh_signal_s *signal=&session->receive.signal;
	unsigned int sequence=get_uint32(&payload->buffer[1]);

	logoutput_info("receive_msg_unimplemented: received a unimplemented message for number %i", sequence);

	/* signal any waiting thread */

	pthread_mutex_lock(signal->mutex);
	signal->sequence_number_error=sequence;
	signal->error=EOPNOTSUPP;
	pthread_cond_broadcast(signal->cond);
	pthread_mutex_unlock(signal->mutex);
	free_payload(&payload);

    }

    if (payload) {

	free_payload(&payload);
	disconnect_ssh_session(session, 0, SSH_DISCONNECT_PROTOCOL_ERROR);

    }

}

/* debug */

static void receive_msg_debug(struct ssh_session_s *session, struct ssh_payload_s *payload)
{

    if (payload->len > 6) {
	unsigned int len=0;

	len=get_uint32(&payload->buffer[2]);

	if (len>0 && len<65) {
	    char string[len+1];

	    memcpy(&string, &payload->buffer[6], len);
	    string[len]='\0';

	    if (payload->buffer[1]) {

		logoutput_debug("receive_msg_debug: %s", string);

	    } else {

		logoutput_info("receive_msg_debug: %s", string);

	    }

	}

	free_payload(&payload);

    }

    if (payload) {

	free_payload(&payload);
	disconnect_ssh_session(session, 0, SSH_DISCONNECT_PROTOCOL_ERROR);

    }

}

/* service request */

static void receive_msg_service_request(struct ssh_session_s *session, struct ssh_payload_s *payload)
{

    /* error: receiving a service request from the server in this phase is not ok */

    logoutput_info("receive_msg_service_request: error: received a service request from server....");
    free_payload(&payload);
    disconnect_ssh_session(session, 0, SSH_DISCONNECT_PROTOCOL_ERROR);

}

/* service accept, reply on service request for ssh-userauth or ssh-connection */

static void receive_msg_service_accept(struct ssh_session_s *session, struct ssh_payload_s *payload)
{

    logoutput("receive_msg_service_accept");

    pthread_mutex_lock(&session->status.mutex);

    if (session->status.sessionphase.status & SESSION_STATUS_DISCONNECTING) {

	free_payload(&payload);

    } else if (session->status.sessionphase.phase==SESSION_PHASE_SETUP || session->status.sessionphase.phase==SESSION_PHASE_CONNECTION) {
	struct payload_queue_s *queue = session->queue;

	if (queue) {

	    queue_ssh_payload(queue, payload);
	    payload=NULL;

	}

    }

    pthread_mutex_unlock(&session->status.mutex);

    if (payload) {

	free_payload(&payload);
	disconnect_ssh_session(session, 0, SSH_DISCONNECT_PROTOCOL_ERROR);

    }

}

static void receive_msg_ext_info(struct ssh_session_s *session, struct ssh_payload_s *payload)
{
    struct ssh_status_s *status=&session->status;
    unsigned int error=0;
    int result=-1;

    /*
	start re exchange. See:
	https://tools.ietf.org/html/rfc4253#section-9
    */

    logoutput("receive_msg_ext_info");

    pthread_mutex_lock(&status->mutex);

    if (status->sessionphase.status & SESSION_STATUS_DISCONNECTING) {

	free_payload(&payload);

    } else if (status->sessionphase.phase==SESSION_PHASE_SETUP) {

	/* received:
	    - after SSH_MSG_NEWKEYS or
	    - before SSH_MSG_USERAUTH_SUCCESS */

	process_msg_ext_info(session, payload);

    }

    pthread_mutex_unlock(&status->mutex);

    free_payload(&payload);

}

static void receive_msg_kexinit(struct ssh_session_s *session, struct ssh_payload_s *payload)
{
    struct ssh_status_s *status=&session->status;
    unsigned int error=0;
    int result=-1;

    /*
	start re exchange. See:
	https://tools.ietf.org/html/rfc4253#section-9
    */

    logoutput("receive_msg_kexinit");

    pthread_mutex_lock(&status->mutex);

    if (status->sessionphase.status & SESSION_STATUS_DISCONNECTING) {

	free_payload(&payload);

    } else if (status->sessionphase.phase==SESSION_PHASE_SETUP) {

	if (status->sessionphase.sub==SESSION_SUBPHASE_KEYEXCHANGE) {
	    struct keyexchange_s *keyexchange=session->keyexchange;

	    /* keyexchange in setup phase */

	    if (keyexchange) {

		queue_ssh_payload(keyexchange->queue, payload);
		payload=NULL;

	    }

	}

    } else if (status->sessionphase.phase==SESSION_PHASE_CONNECTION) {

	if (status->sessionphase.sub==0) {
	    struct payload_queue_s queue;
	    struct sessionphase_s sessionphase;

	    /* start key reexchange */

	    init_payload_queue(session, &queue);
	    queue_ssh_payload(&queue, payload);
	    session->status.sessionphase.sub=SESSION_SUBPHASE_KEYEXCHANGE;
	    copy_sessionphase(session, &sessionphase);
	    pthread_mutex_unlock(&session->status.mutex);

	    if (key_exchange(session, &queue, &sessionphase)==0) {

		logoutput("receive_msg_kexinit: key exchange completed");

	    } else {

		disconnect_ssh_session(session, 0, SSH_DISCONNECT_PROTOCOL_ERROR);

	    }

	    return;

	}

    }

    pthread_mutex_unlock(&session->status.mutex);

    if (payload) {

	free_payload(&payload);
	disconnect_ssh_session(session, 0, SSH_DISCONNECT_PROTOCOL_ERROR);

    }

}

static void receive_msg_newkeys(struct ssh_session_s *session, struct ssh_payload_s *payload)
{
    struct ssh_status_s *status=&session->status;

    logoutput("receive_msg_newkeys");

    pthread_mutex_lock(&status->mutex);

    if (status->sessionphase.status & SESSION_STATUS_DISCONNECTING) {

	free_payload(&payload);

    } else if ((status->sessionphase.phase==SESSION_PHASE_CONNECTION || status->sessionphase.phase==SESSION_PHASE_SETUP) &&
		(status->sessionphase.sub==SESSION_SUBPHASE_KEYEXCHANGE)) {
	struct ssh_receive_s *receive=&session->receive;

	free_payload(&payload);

	/* signal keyexchange newkeys from server received */

	status->sessionphase.status |= SESSION_STATUS_KEYEXCHANGE_NEWKEYS_S2C;
	pthread_cond_broadcast(&status->cond);
	pthread_mutex_unlock(&status->mutex);

	/* wait for signal it's safe to comtinue */

	if (wait_for_newkeys_to_complete(receive)==0) {

	    logoutput("receive_msg_newkeys: newkeys s2c completed");

	}

	return;

    }

    pthread_mutex_unlock(&status->mutex);

    if (payload) {

	free_payload(&payload);
	disconnect_ssh_session(session, 0, SSH_DISCONNECT_PROTOCOL_ERROR);

    }

}

static void receive_msg_kexdh_reply(struct ssh_session_s *session, struct ssh_payload_s *payload)
{
    struct ssh_status_s *status=&session->status;

    logoutput("receive_msg_kexdh_reply");

    pthread_mutex_lock(&status->mutex);

    if (status->sessionphase.status & SESSION_STATUS_DISCONNECTING) {

	free_payload(&payload);

    } else if ((status->sessionphase.phase==SESSION_PHASE_SETUP || status->sessionphase.phase==SESSION_PHASE_CONNECTION)) {
	struct keyexchange_s *keyexchange=session->keyexchange;

	if (keyexchange) {

	    /* keyexchange in setup or connection phase */

	    queue_ssh_payload(keyexchange->queue, payload);
	    payload=NULL;

	}

    }

    pthread_mutex_unlock(&status->mutex);

    if (payload) {

	free_payload(&payload);
	disconnect_ssh_session(session, 0, SSH_DISCONNECT_PROTOCOL_ERROR);

    }

}

void register_transport_cb()
{
    register_msg_cb(SSH_MSG_DISCONNECT, receive_msg_disconnect);
    register_msg_cb(SSH_MSG_IGNORE, receive_msg_ignore);
    register_msg_cb(SSH_MSG_UNIMPLEMENTED, receive_msg_unimplemented);
    register_msg_cb(SSH_MSG_DEBUG, receive_msg_debug);
    register_msg_cb(SSH_MSG_SERVICE_REQUEST, receive_msg_service_request);
    register_msg_cb(SSH_MSG_SERVICE_ACCEPT, receive_msg_service_accept);
    register_msg_cb(SSH_MSG_EXT_INFO, receive_msg_ext_info);

    register_msg_cb(SSH_MSG_KEXINIT, receive_msg_kexinit);
    register_msg_cb(SSH_MSG_NEWKEYS, receive_msg_newkeys);

    register_msg_cb(SSH_MSG_KEXDH_REPLY, receive_msg_kexdh_reply);

}
