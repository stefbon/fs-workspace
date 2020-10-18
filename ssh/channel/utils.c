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

#include "logging.h"
#include "main.h"
#include "common-utils/utils.h"

#include "ssh-common.h"
#include "ssh-channel.h"

#include "ssh-hostinfo.h"
#include "ssh-utils.h"

#include "receive/msg-channel.h"
#include "send/msg-channel.h"

extern struct workerthreads_queue_struct workerthreads_queue;

static const char *openfailure_reasons[] = {
	"Open administratively prohibited.",
	"Open connect failed.", 
	"Open unknown channel type.",
	"Open resource shortage."};

const char *get_openfailure_reason(unsigned int reason)
{
    if (reason > 0 && reason <= (sizeof(openfailure_reasons) / sizeof(openfailure_reasons[0]))) return openfailure_reasons[reason-1];
    return "Open unknown failure.";
}

void get_channel_expire_init(struct ssh_channel_s *channel, struct timespec *expire)
{
    get_current_time(expire);
    expire->tv_sec+=4;
}

/*
    get basic info from server like:
    - time diff between server and this client
    */

void get_timeinfo_ssh_server(struct ssh_session_s *session)
{
    struct ssh_connection_s *connection=session->connections.main;
    struct timespec send_client;
    struct timespec recv_client;
    struct timespec set_server;
    unsigned int error=0;
    struct common_buffer_s buffer;
    int size=0;
    unsigned int done=0;
    char *sep=NULL;

    pthread_mutex_lock(connection->setup.mutex);

    if (connection->setup.flags & SSH_SETUP_FLAG_HOSTINFO) {

	pthread_mutex_unlock(connection->setup.mutex);
	return;

    }

    connection->setup.flags|=SSH_SETUP_FLAG_HOSTINFO;
    pthread_mutex_unlock(connection->setup.mutex);

    set_server.tv_sec=0;
    set_server.tv_nsec=0;

    send_client.tv_sec=0;
    send_client.tv_nsec=0;

    recv_client.tv_sec=0;
    recv_client.tv_nsec=0;

    init_common_buffer(&buffer);
    size=get_timeinfo_server(session, &buffer, &send_client, &recv_client);
    if (size==0) goto finish;

    searchoutput:

    /* output is like:
	remotetime=1524159292.579901450:*/

    sep=memmem(buffer.ptr, size, "remotetime=", 11);

    if (sep) {
	char *start=sep + 11;

	size-=(start - buffer.ptr);
	sep=memchr(start, '.', size);

	if (sep) {

	    *sep='\0';
	    set_server.tv_sec=(time_t) atol(start);
	    *sep='.';
	    sep++;

	    size-=(sep - start);
	    start=sep;

	} else {

	    logoutput("get_timeinfo_ssh_server: error output");
	    goto finish;

	}

	sep=memchr(start, ':', size);

	if (sep) {
	    unsigned int count=(unsigned int) (sep - start);

	    if (count<10) {
		unsigned char nsec[10];

		/* use a special string to do the padding in case the nanosecondsstring does not have 9 decimals */

		memset(nsec, '0', 9);
		nsec[9]='\0';

		memcpy(nsec, start, count);
		set_server.tv_nsec=(unsigned long) atol((char *)nsec);

	    } else {

		logoutput("get_timeinfo_ssh_server: error output");
		goto finish;

	    }

	}

	logoutput("get_timeinfo_ssh_server: received %li.%li", set_server.tv_sec, set_server.tv_nsec);
	set_time_delta(session, &send_client, &recv_client, &set_server);
	done=1;

    }

    finish:

    if (buffer.ptr) free(buffer.ptr);

}

unsigned int get_channel_interface_info(struct ssh_channel_s *channel, char *buffer, unsigned int size)
{
    unsigned int result=0;

    if (size>=4) {

	memset(buffer, '\0', size);

	if (channel->flags & CHANNEL_FLAG_OPENFAILURE) {

	    store_uint32(buffer, EFAULT);
	    result=4;

	} else if (channel->flags & (CHANNEL_FLAG_SERVER_EOF | CHANNEL_FLAG_CLIENT_EOF)) {

	    store_uint32(buffer, ENODEV); /* connected with server but backend on server not */
	    result=4;

	} else if (channel->flags & (CHANNEL_FLAG_SERVER_EOF | CHANNEL_FLAG_CLIENT_EOF)) {

	    store_uint32(buffer, ENOTCONN); /* not connected with server */
	    result=4;

	} else {
	    struct fs_connection_s *connection=&channel->connection->connection;

	    if (connection->status & FS_CONNECTION_FLAG_DISCONNECT ) {

		store_uint32(buffer, ENOTCONN); /* not connected with server */
		result=4;

	    }

	}

    }

    return result;

}

void switch_channel_receive_data(struct ssh_channel_s *channel, const char *name, void (* receive_data_cb)(struct ssh_channel_s *c, struct ssh_payload_s **payload))
{

    logoutput("switch_channel_receive_data: %s", name);

    pthread_mutex_lock(&channel->mutex);

    channel->receive_msg_channel_data=receive_msg_channel_data_down;

    if (strcmp(name, "init")==0) {

	channel->receive_msg_channel_data=receive_msg_channel_data_init;

    } else if (strcmp(name, "subsystem")==0) {

	channel->receive_msg_channel_data=receive_data_cb;

    } else if (strcmp(name, "down")==0) {

	channel->receive_msg_channel_data=receive_msg_channel_data_down;

    }

    pthread_mutex_unlock(&channel->mutex);

}

void switch_channel_send_data(struct ssh_channel_s *channel, const char *what)
{

    pthread_mutex_lock(&channel->mutex);

    if (strcmp(what, "error")==0 || strcmp(what, "eof")==0 || strcmp(what, "close")==0) {

	channel->send_data_message=send_channel_data_message_error;

    } else if (strcmp(what, "default")==0) {

	channel->send_data_message=send_channel_data_message_connected;

    } else {

	logoutput_warning("switch_channel_send_data: status %s not reckognized", what);

    }

    pthread_mutex_unlock(&channel->mutex);

}
