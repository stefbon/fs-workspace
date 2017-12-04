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

#include "logging.h"
#include "main.h"

#include "utils.h"

#include "ssh-common.h"
#include "ssh-common-protocol.h"

#include "ssh-receive.h"
#include "ssh-receive-waitreply.h"

#include "ssh-utils.h"

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
	unsigned int error=0;

	len=write_disconnect_reason(reason, NULL, 0, &error);

	if (len>0) {
	    char string[len+1];

	    if (len==write_disconnect_reason(reason, &string[0], len+1, &error)) {

		string[len]='\0';
		logoutput("receive_msg_disconnect: received disconnect reason %i:%s", reason, string);

	    } else {

		logoutput("receive_msg_disconnect: received disconnect reason %i", reason);

	    }

	} else {

	    logoutput("receive_msg_disconnect: received disconnect reason %i", reason);

	}

    }

    disconnect_ssh_session(session, 1, reason);
    free(payload);

}

/* ignore */

static void receive_msg_ignore(struct ssh_session_s *session, struct ssh_payload_s *payload)
{
    free(payload);
}

/* debug */

static void receive_msg_debug(struct ssh_session_s *session, struct ssh_payload_s *payload)
{
    unsigned int len=0;

    if (payload->len > 6) {

	len=get_uint32(&payload->buffer[2]);

    }

    /* TODO: split string into multiple parts when too large, with limit */

    if (len>0) {
	char string[len+1];

	memcpy(&string, &payload->buffer[6], len);
	string[len]='\0';

	if (payload->buffer[1]) {

	    logoutput_debug("receive_msg_debug: %s", string);

	} else {

	    logoutput_info("receive_msg_debug: %s", string);

	}

    }

    free(payload);
    return;

    disconnect:

    free(payload);
    disconnect_ssh_session(session, 0, SSH_DISCONNECT_PROTOCOL_ERROR);

}

/* service request */

static void receive_msg_service_request(struct ssh_session_s *session, struct ssh_payload_s *payload)
{

    /* error: receiving a service request from the server in this phase is not ok */

    logoutput_info("receive_msg_service_request: error: received a service request from server....");
    free(payload);
    disconnect_ssh_session(session, 0, SSH_DISCONNECT_PROTOCOL_ERROR);

}

/* service accept */

static void receive_msg_service_accept(struct ssh_session_s *session, struct ssh_payload_s *payload)
{
    unsigned int len=get_uint32(&payload->buffer[1]);

    if (len>0) {

	if (len==strlen("ssh-userauth") && memcmp(&payload->buffer[5], "ssh-userauth", len)==0) {

	    /* TODO */

	} else if (len==strlen("ssh-connection") && memcmp(&payload->buffer[5], "ssh-connection", len)==0) {

	    /* TODO */

	} else {
	    char string[len+1];

	    memcpy(&string, &payload->buffer[5], len);
	    string[len]='\0';

	    logoutput_info("receive_msg_service_accept: not reckognized service %s", string);

	}

    }

    free(payload);

}

/* not implemented */

static void receive_msg_unimplemented(struct ssh_session_s *session, struct ssh_payload_s *payload)
{

    if (payload->len >= 5) {
	struct ssh_receive_s *receive=&session->receive;
	struct payload_queue_s *queue=&receive->payload_queue;
	unsigned int sequence=get_uint32(&payload->buffer[1]);

	logoutput_info("receive_msg_unimplemented: received a unimplemented message for number %i", sequence);

	/* signal any waiting thread */

	pthread_mutex_lock(queue->signal.mutex);
	queue->signal.sequence_number_error=sequence;
	queue->signal.error=EOPNOTSUPP;
	pthread_cond_broadcast(queue->signal.cond);
	pthread_mutex_unlock(queue->signal.mutex);

	free(payload);
	return;

    }

    disconnect_ssh_session(session, 0, SSH_DISCONNECT_PROTOCOL_ERROR);

}


static void receive_msg_kexinit(struct ssh_session_s *session, struct ssh_payload_s *payload)
{
    unsigned int error=0;

    /*
	start re exchange. See:
	https://tools.ietf.org/html/rfc4253#section-9
    */

    logoutput("receive_msg_kexinit");

    /* See:
	Note, however, that during a key re-exchange, after sending a
   SSH_MSG_KEXINIT message, each party MUST be prepared to process an
   arbitrary number of messages that may be in-flight before receiving a
   SSH_MSG_KEXINIT message from the other party.
	(https://tools.ietf.org/html/rfc4253#section-7.1)
    */

    /* start */

    if (store_kexinit_server(session, payload, 0, &error)==0) {

	logoutput("receive_msg_kexinit: received and stored server kexinit message");

    } else {

	logoutput("receive_msg_kexinit: error storing kexinit message (%i:%s)", error, strerror(error));
	free(payload);
	goto error;

    }

    /* test client hash sent kexinit, if not send it here */

    free(payload);
    return;

    error:
    return;

}

static void receive_msg_newkeys(struct ssh_session_s *session, struct ssh_payload_s *payload)
{
    free(payload);
}

void register_transport_cb()
{
    register_msg_cb(SSH_MSG_DISCONNECT, receive_msg_disconnect);
    register_msg_cb(SSH_MSG_IGNORE, receive_msg_ignore);
    register_msg_cb(SSH_MSG_UNIMPLEMENTED, receive_msg_unimplemented);
    register_msg_cb(SSH_MSG_DEBUG, receive_msg_debug);
    register_msg_cb(SSH_MSG_SERVICE_REQUEST, receive_msg_service_request);
    register_msg_cb(SSH_MSG_SERVICE_ACCEPT, receive_msg_service_accept);

    register_msg_cb(SSH_MSG_KEXINIT, receive_msg_kexinit);
    register_msg_cb(SSH_MSG_NEWKEYS, receive_msg_newkeys);
}
