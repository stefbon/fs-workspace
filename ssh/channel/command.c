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

#include "logging.h"
#include "main.h"
#include "common-utils/utils.h"
#include "common-utils/network-utils.h"

#include "ssh-common-protocol.h"
#include "ssh-common.h"

#include "shell.h"
#include "exec.h"

unsigned int _get_result_common(struct ssh_session_s *session, const char *command, struct common_buffer_s *buffer, struct timespec *send, struct timespec *recv)
{
    struct channel_table_s *table=&session->channel_table;
    struct server_reply_s server_reply;
    unsigned int size=0;

    memset(&server_reply, 0, sizeof(struct server_reply_s));
    server_reply.response.data.ptr=NULL;
    server_reply.response.data.size=0;

    if (table->shell) {

	size=start_remote_command_shell(table->shell, command, &server_reply, send, recv);

    } else {

	size=start_remote_command_exec(session, command, &server_reply, send, recv);

    }

    if (size==0 || server_reply.error>0) {

	size=0;
	goto finish;

    }

    size=0;

    if (server_reply.reply==SSH_MSG_CHANNEL_DATA) {
	char *sep=NULL;
	unsigned char *name=NULL;
	unsigned int left=0;

	/* take over the data, do not free it here */
	buffer->ptr=server_reply.response.data.ptr;
	buffer->size=server_reply.response.data.size;
	buffer->len=buffer->size;
	server_reply.response.data.ptr=NULL;
	server_reply.response.data.size=0;
	return buffer->size;

    } else if (server_reply.reply==SSH_MSG_CHANNEL_EXTENDED_DATA) {
	char string[server_reply.response.data.size + 1];

	memcpy(string, server_reply.response.data.ptr, server_reply.response.data.size);
	string[server_reply.response.data.size]='\0';

	logoutput("get_result_common: error output %s", string);

    }

    finish:

    if (server_reply.response.data.ptr) {

	free(server_reply.response.data.ptr);
	server_reply.response.data.ptr=NULL;

    }

    return size;

}

unsigned int get_result_common(struct ssh_session_s *session, const char *command, struct common_buffer_s *buffer)
{
    return _get_result_common(session, command, buffer, NULL, NULL);
}

unsigned int get_result_common_timed(struct ssh_session_s *session, char *command, struct common_buffer_s *buffer, struct timespec *send, struct timespec *recv)
{
    return _get_result_common(session, command, buffer, send, recv);
}

static unsigned int get_timeinfo_command(struct ssh_session_s *session, char *buffer)
{
    unsigned int size=0;

    size=strlen("echo remotetime=$(date +%s:%N):");
    if (buffer) memcpy(buffer, "echo remotetime=$(date +%s.%N):", size);

    return size;

}

static unsigned int get_servername_command(struct ssh_session_s *session, char *buffer)
{
    unsigned int size=0;

    size=strlen("echo $(/usr/lib/fs-workspace/getservername)");
    if (buffer) memcpy(buffer, "echo $(/usr/lib/fs-workspace/getservername)", size);

    return size;

}

static unsigned int get_services_command(struct ssh_session_s *session, char *buffer)
{
    unsigned int size=0;

    /* TODO: */

    size=strlen("echo $(/usr/lib/fs-workspace/getservices)");
    if (buffer) memcpy(buffer, "echo $(/usr/lib/fs-workspace/getservices)", size);

    return size;

}

/* get services supported by server*/

unsigned int get_supported_services(struct ssh_session_s *session, struct common_buffer_s *buffer)
{
    unsigned int size=get_services_command(session, NULL);
    char command[size+1];

    size=get_services_command(session, command);
    command[size]='\0';

    return get_result_common(session, command, buffer);
}

/* get server name (including domainname) */

static unsigned int get_servername(struct ssh_session_s *session, struct common_buffer_s *buffer)
{
    unsigned int size=get_servername_command(session, NULL);
    char command[size+1];

    size=get_servername_command(session, command);
    command[size]='\0';

    logoutput("get_servername: command %s", command);

    return get_result_common(session, command, buffer);

}

/* get time on server as product of command */

unsigned int get_timeinfo_server(struct ssh_session_s *session, struct common_buffer_s *buffer, struct timespec *send, struct timespec *recv)
{
    int size=get_timeinfo_command(session, NULL);
    char command[size+1];
    struct timespec send_client;
    struct timespec recv_client;
    struct timespec set_server;

    size=get_timeinfo_command(session, command);
    command[size]='\0';

    return get_result_common_timed(session, command, buffer, send, recv);

}

static unsigned int get_ssh_interface_status(struct ssh_session_s *session, char *buffer, unsigned int size)
{
    unsigned int result=0;

    if (size>=4) {
	struct ssh_connection_s *connection=session->connections.main;

	memset(buffer, '\0', size);

	if (connection->connection.status & FS_CONNECTION_FLAG_DISCONNECT) {

	    store_uint32(buffer, ENOTCONN); /* not connected with server */
	    result=4;

	}

    }

    return result;

}


unsigned int get_ssh_interface_info(struct context_interface_s *interface, const char *what, void *data, struct common_buffer_s *buffer)
{
    struct ssh_session_s *session=NULL;
    unsigned int result=0;
    unsigned int error=0;

    logoutput("get_ssh_interface_info: what %s", what);

    if (interface->ptr) {

	session=(struct ssh_session_s *) interface->ptr;

    } else {

	session=(struct ssh_session_s *) data;

    }

    if (! session) {

	error=ENOENT;
	return 0;

    }

    if (strcmp(what, "servername")==0) {

	result=get_servername(session, buffer);

    } else if (strcmp(what, "hostname")==0) {
	char *remotename=NULL;
	struct ssh_connection_s *connection=session->connections.main;
	int fd=connection->connection.io.socket.xdata.fd;

	if (fd>0) {

	    buffer->ptr=get_connection_hostname(&connection->connection, fd, 1, &error);
	    if (buffer->ptr==NULL) buffer->ptr=get_connection_ipv4(&connection->connection, fd, 1, &error);

	    if (buffer->ptr) {

		buffer->len=strlen(buffer->ptr);
		buffer->size=buffer->len + 1;

	    } else {

		logoutput("get_ssh_interface_info: error %i getting remote hostname (%s)", error, strerror(error));

	    }

	}

    } else if (strcmp(what, "remoteusername")==0) {

	if (session->identity.remote_user.ptr) {

	    logoutput("get_ssh_interface_info: remoteusername %.*s", session->identity.remote_user.len, session->identity.remote_user.ptr);

	    buffer->ptr=malloc(session->identity.remote_user.len + 1);

	    if (buffer->ptr) {

		memcpy(buffer->ptr, session->identity.remote_user.ptr, session->identity.remote_user.len);
		buffer->ptr[session->identity.remote_user.len + 1]='\0';
		buffer->len=session->identity.remote_user.len;
		buffer->size=buffer->len + 1;
		result=buffer->len;

	    }

	}

    } else if (strcmp(what, "supportedservices")==0) {

	result=get_supported_services(session, buffer);

    } else if (strcmp(what, "status")==0) {

	result=get_ssh_interface_status(session, buffer->ptr, buffer->size);

    } else {

	result=get_result_common(session, what, buffer);

    }

    return result;
}
