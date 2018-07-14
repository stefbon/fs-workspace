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

unsigned int _get_result_common(struct ssh_session_s *session, const char *command, char *buffer, unsigned int len, struct timespec *send, struct timespec *recv, unsigned int *error)
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

	*error=(server_reply.error>0) ? server_reply.error : EIO;
	size=0;
	goto finish;

    }

    size=0;

    if (server_reply.reply==SSH_MSG_CHANNEL_DATA) {
	char *sep=NULL;
	unsigned char *name=NULL;
	unsigned int left=0;

	size=server_reply.response.data.size;
	if (size>len) size=len;
	memcpy(buffer, server_reply.response.data.ptr, size);

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

unsigned int get_result_common(struct ssh_session_s *session, const char *command, char *buffer, unsigned int len, unsigned int *error)
{
    return _get_result_common(session, command, buffer, len, NULL, NULL, error);
}

unsigned int get_result_common_timed(struct ssh_session_s *session, char *command, char *buffer, unsigned int len, struct timespec *send, struct timespec *recv, unsigned int *error)
{
    return _get_result_common(session, command, buffer, len, send, recv, error);
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

    size=strlen("echo $(/usr/lib/fs-workspace/getservices)");
    if (buffer) memcpy(buffer, "echo $(/usr/lib/fs-workspace/getservices)", size);

    return size;

}

/* get services supported by server*/

static unsigned int get_supported_services(struct ssh_session_s *session, unsigned char *buffer, unsigned int len, unsigned int *error)
{
    unsigned int size=get_services_command(session, NULL);
    char command[size+1];

    size=get_services_command(session, command);
    command[size]='\0';

    logoutput("get_supported_services: command %s", command);

    return get_result_common(session, command, buffer, len, error);

}

/* get server name (including domainname) */

static unsigned int get_servername(struct ssh_session_s *session, unsigned char *buffer, unsigned int len, unsigned int *error)
{
    unsigned int size=get_servername_command(session, NULL);
    char command[size+1];

    size=get_servername_command(session, command);
    command[size]='\0';

    logoutput("get_servername: command %s", command);

    return get_result_common(session, command, buffer, len, error);

}

/* get time on server as product of command */

unsigned int get_timeinfo_server(struct ssh_session_s *session, unsigned char *buffer, unsigned int len, struct timespec *send, struct timespec *recv, unsigned int *error)
{
    int size=get_timeinfo_command(session, NULL);
    char command[size+1];
    struct timespec send_client;
    struct timespec recv_client;
    struct timespec set_server;

    size=get_timeinfo_command(session, command);
    command[size]='\0';

    return get_result_common_timed(session, command, buffer, len, send, recv, error);

}

unsigned int get_ssh_interface_info(struct context_interface_s *interface, const char *what, void *data, unsigned char *buffer, unsigned int size, unsigned int *error)
{
    struct ssh_session_s *session=NULL;
    unsigned int result=0;

    logoutput("get_ssh_interface_info: what %s", what);

    if (interface->ptr) {

	session=(struct ssh_session_s *) interface->ptr;

    } else {

	session=(struct ssh_session_s *) data;

    }

    if (! session) {

	*error=ENOENT;
	return 0;

    }

    if (strcmp(what, "servername")==0) {

	result=get_servername(session, buffer, size, error);

    } else if (strcmp(what, "hostname")==0) {
	char *remotename=NULL;

	remotename=get_connection_hostname(session->connection.fd, 1, error);
	if (remotename==NULL) remotename=get_connection_ipv4(session->connection.fd, 1, error);

	if (remotename) {

	    result=strlen(remotename);
	    if (result>size) result=size;
	    memcpy(buffer, remotename, result);
	    free(remotename);

	} else {

	    logoutput("get_ssh_interface_info: error %i getting remote hostname (%s)", *error, strerror(*error));

	}

    } else if (strcmp(what, "status")==0) {
	unsigned int status=1;
	unsigned int *dest=(unsigned int *) buffer;

	status=(session->status.sessionphase.phase==SESSION_PHASE_DISCONNECT || (session->status.sessionphase.status & SESSION_STATUS_DISCONNECTING)) ? -1 : 0;
	memcpy(dest, &status, sizeof(unsigned int));
	result=(sizeof(unsigned int));

    } else if (strcmp(what, "services")==0) {

	result=get_supported_services(session, buffer, size, error);

    } else if (strcmp(what, "remoteusername")==0) {

	if (session->identity.remote_user.ptr) {

	    if (session->identity.remote_user.len < size) {

		memcpy(buffer, session->identity.remote_user.ptr, session->identity.remote_user.len);
		buffer[session->identity.remote_user.len]='\0';
		result=session->identity.remote_user.len;

	    } else {

		result=size;
		memcpy(buffer, session->identity.remote_user.ptr, result - 1);
		buffer[result - 1]='\0';

	    }

	}

    } else {

	result=get_result_common(session, what, buffer, size, error);

    }

    return result;
}
