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
#include <sys/stat.h>
#include <poll.h>
#include <sys/epoll.h>

#include "logging.h"
#include "main.h"
#include "workerthreads.h"

#include "utils.h"

#include "ssh-common.h"
#include "ssh-common-protocol.h"

#include "ssh-receive.h"
#include "ssh-receive-greeter.h"
#include "ssh-receive-transport.h"
#include "ssh-receive-userauth.h"
#include "ssh-receive-channel.h"
#include "ssh-receive-waitreply.h"

#include "ssh-queue-rawdata.h"
#include "ssh-queue-payload.h"

#include "ssh-utils.h"

extern unsigned int get_max_data_size(uid_t uid);

static receive_msg_cb_t ssh_msg_cb[256];

static void msg_not_supported(struct ssh_session_s *session, struct ssh_payload_s *payload)
{
    logoutput("msg_not_supported: received %i", payload->type);
    free(payload);
}

void register_msg_cb(unsigned char type, receive_msg_cb_t cb)
{
    ssh_msg_cb[type]=cb;
}

void process_ssh_message(struct ssh_session_s *session, struct ssh_payload_s *payload)
{
    (* ssh_msg_cb[payload->type]) (session, payload);
}

int init_receive(struct ssh_session_s *session, pthread_mutex_t *mutex, pthread_cond_t *cond, unsigned int *error)
{
    struct ssh_receive_s *receive=&session->receive;

    logoutput("init_receive");

    memset(receive, 0, sizeof(struct ssh_receive_s));

    /* rawdata queue */

    init_receive_rawdata_queue(session);

    /* packet queue */

    if (init_receive_payload_queue(session, mutex, cond)==-1) {

	*error=ENOMEM;
	return -1;

    }

    /*
	the maximum size for the buffer
	RFC4253 6.1 Maximum Packet Length
    */

    receive->size=35000;
    receive->buffer=malloc(receive->size);

    if (receive->buffer) {

	memset(receive->buffer, '\0', receive->size);
	*error=0;

    } else {

	receive->size=0;
	*error=ENOMEM;
	return -1;

    }

    for (int i=0; i<256; i++) ssh_msg_cb[i]=msg_not_supported;
    register_transport_cb();
    register_channel_cb();
    register_userauth_cb();

    return 0;

}

void free_receive(struct ssh_session_s *session)
{
    struct ssh_receive_s *receive=&session->receive;

    clean_receive_rawdata_queue(receive);
    clean_receive_payload_queue(receive);

    if (receive->buffer) {

	free(receive->buffer);
	receive->buffer=NULL;

    }

    receive->size=0;

    free_receive_payload_queue(receive);
    free_receive_rawdata_queue(receive);

}

/*
    read the data coming from server after the connection is created
    and queue it
*/

static int read_ssh_data(struct ssh_session_s *session, int fd, uint32_t events)
{
    struct ssh_receive_s *receive=&session->receive;
    int lenread=0;
    unsigned int error=0;

    /* read the first data coming from the remote server */

    readbuffer:

    lenread+=recv(fd, (char *) (receive->buffer + lenread), receive->size - lenread, 0);
    error=errno;

    if (lenread<=0) {

	/* handle error */

	if (lenread==0) {

	    /* peer has performed an orderly shutdown */

	    disconnect_ssh_session(session, 1, 0);
	    return -1;

	} else if (error==EAGAIN || error==EWOULDBLOCK) {

	    goto readbuffer;

	} else if (error==ECONNRESET || error==ENOTCONN || error==EBADF || error==ENOTSOCK) {

	    logoutput_warning("read_ssh_data: socket is not connected? error %i:%s", error, strerror(error));

	} else {

	    logoutput_warning("read_ssh_data: error %i:%s", error, strerror(error));

	}

    } else {

	if (lenread==receive->size) {

	    disconnect_ssh_session(session, 0, 0);

	} else if (lenread<8) {

	    goto readbuffer;

	} else {
	    struct rawdata_queue_s *queue=&receive->rawdata_queue;

	    (* queue->queue_ssh_data)(session, receive->buffer, lenread);
	    return 0;

	}

    }

    return -1;

}

int read_incoming_data(int fd, void *ptr, uint32_t events)
{
    struct ssh_session_s *session=(struct ssh_session_s *) ptr;
    int result=0;

    if ( events & (EPOLLERR | EPOLLHUP) ) {

	/* the remote side disconnected */

        logoutput_notice("read_data: event %i causes connection break", events);

	/* disconnect also this side */

    } else if ( ! (events & EPOLLIN) ) {

	logoutput_notice("read_data: other event %i than incoming data available", events);

	/*
	    ignore futher
	*/

    } else {

	result=read_ssh_data(session, fd, events);

    }

    return result;

}

void switch_receive_process(struct ssh_session_s *session, const char *phase)
{

    if (strcmp(phase, "greeter")==0 || strcmp(phase, "init")==0 || strcmp(phase, "session")==0) {

	switch_process_rawdata_queue(session, phase);

    } else if (strcmp(phase, "none")==0) {

	stop_receive_data(session);

    } else {

	logoutput_warning("switch_receive_process: error phase %s not reckognized", phase);

    }

}
