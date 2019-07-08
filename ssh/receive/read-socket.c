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
#include <sys/epoll.h>

#include "logging.h"
#include "main.h"
#include "workerthreads.h"

#include "utils.h"

#include "ssh-common.h"
#include "ssh-common-protocol.h"
#include "ssh-receive.h"
#include "ssh-utils.h"
#include "ssh-connection.h"

/*
    read the data coming from server after the connection is created
    and queue it
*/

static int read_ssh_data(struct ssh_session_s *session, int fd, uint32_t events)
{
    struct socket_ops_s *sops=session->connection.io.socket.sops;
    struct ssh_receive_s *receive=&session->receive;
    unsigned int error=0;
    int bytesread=0;

    pthread_mutex_lock(&receive->mutex);

    /* read the first data coming from the remote server */

    readbuffer:

    bytesread=(* sops->recv)(&session->connection.io.socket, (void *) (receive->buffer + receive->read), (size_t)(receive->size - receive->read), 0);
    error=errno;

    // logoutput("read_ssh_data: bytesread %i", bytesread);

    if (bytesread<=0) {

	pthread_mutex_unlock(&receive->mutex);

	logoutput_info("read_ssh_data: bytesread %i", bytesread);

	/* handle error */

	if (bytesread==0) {

	    /* peer has performed an orderly shutdown */

	    start_thread_connection_problem(session, 0);
	    return -1;

	} else if (error==EAGAIN || error==EWOULDBLOCK) {

	    return 0;

	} else if (error==ECONNRESET || error==ENOTCONN || error==EBADF || error==ENOTSOCK) {

	    logoutput_warning("read_ssh_data: socket is not connected? error %i:%s", error, strerror(error));
	    start_thread_connection_problem(session, 0);

	} else {
	    logoutput_warning("read_ssh_data: error %i:%s", error, strerror(error));

	}

    } else {

	if (bytesread + receive->read >= receive->size) {

	    pthread_mutex_unlock(&receive->mutex);
	    goto disconnect;

	} else {

	    receive->read+=bytesread;

	    if (receive->threadid==0) {

		/* start a thread to process this data
		    this thread decrypt the first bytes to determine the length of the packet
		    and will set receive->read to zero again */

		logoutput("read_ssh_data: read %i bytes, start thread", bytesread);
		read_ssh_buffer(session);

	    } else {

		logoutput("read_ssh_data: read %i bytes, broadcast", bytesread);
		pthread_cond_broadcast(&receive->cond);

	    }

	    pthread_mutex_unlock(&receive->mutex);

	}

    }

    return 0;

    disconnect:

    disconnect_ssh_session(session, 0, 0);
    return 0;

}

int read_incoming_signal_ssh(int fd, void *ptr, uint32_t events)
{
    struct ssh_session_s *session=(struct ssh_session_s *) ptr;
    int result=0;

    if ( events & (EPOLLERR | EPOLLHUP) ) {

	/* the remote side disconnected */

        logoutput("read_incoming_data: event %i causes connection break", events);
	start_thread_connection_problem(session, 0);

    } else if (events & EPOLLIN) {

	logoutput("read_incoming_data");
	result=read_ssh_data(session, fd, events);

    }

    return result;

}
