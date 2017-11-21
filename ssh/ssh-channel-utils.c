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
#include "utils.h"

#include "workerthreads.h"
#include "workspace-interface.h"

#include "ssh-common-protocol.h"
#include "ssh-common.h"
#include "ssh-common-list.h"
#include "ssh-channel.h"
#include "ssh-admin-channel.h"
#include "ssh-send-channel.h"
#include "ssh-hostinfo.h"
#include "ssh-receive-channel.h"
#include "ssh-utils.h"

extern struct workerthreads_queue_struct workerthreads_queue;

static const char *openfailure_reasons[] = {
	"Open administratively prohibited.",
	"Open connect failed.", 
	"Open unknown channel type.",
	"Open resource shortage."};

const char *get_openfailure_reason(unsigned int reason)
{

    if (reason > 0 && reason <= (sizeof(openfailure_reasons) / sizeof(openfailure_reasons[0]))) {

	return openfailure_reasons[reason-1];

    }

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
    struct timespec send_client;
    struct timespec recv_client;
    struct timespec set_server;
    unsigned int error=0;
    unsigned char buffer[1024];
    int size=0;
    unsigned int done=0;

    pthread_mutex_lock(&session->status.mutex);

    if (session->hostinfo.flags & (SSH_HOSTINFO_FLAG_TIMEINIT | SSH_HOSTINFO_FLAG_TIMESET)) {

	pthread_mutex_unlock(&session->status.mutex);
	return;

    }

    session->hostinfo.flags|=SSH_HOSTINFO_FLAG_TIMEINIT;
    pthread_mutex_unlock(&session->status.mutex);

    set_server.tv_sec=0;
    set_server.tv_nsec=0;

    send_client.tv_sec=0;
    send_client.tv_nsec=0;

    recv_client.tv_sec=0;
    recv_client.tv_nsec=0;

    size=get_timeinfo_server(session, buffer, 1024, &send_client, &recv_client, &error);

    if (size>=0) {
	unsigned char *output=buffer;
	unsigned char *sep=NULL;

	searchoutput:

	sep=memchr(output, '=', size);

	if (sep) {

	    /* look for the remotetime= string */

	    if (strncmp((char *)output, "remotetime=", 11)==0) {

		output+=11;
		size-=11;
		sep=memchr(output, '.', size);

		/* first part are the seconds */

		if (sep) {

		    *sep='\0';
		    set_server.tv_sec=(time_t) atol((char *)output);
		    *sep='.';

		    size-=(unsigned int) (sep + 1 - output);
		    output=sep+1;

		} else {

		    logoutput("get_timeinfo_server: error output");
		    return 0;

		}

		sep=memchr(output, ':', size);

		/* second part are the nanoseconds */

		if (sep) {
		    unsigned int count=(unsigned int) (sep - output);

		    if (count<10) {
			unsigned char nsec[10];

			/* use a special string to do the padding in case the nanosecondsstring does not have 9 decimals */

			memset(nsec, '0', 9);
			nsec[9]='\0';

			memcpy(nsec, output, count);
			set_server.tv_nsec=(unsigned long) atol((char *)nsec);

		    } else {

			logoutput("get_timeinfo_server: error output");
			return 0;

		    }

		}

		set_time_delta(session, &send_client, &recv_client, &set_server);

		size-=(unsigned int) (sep + 1 - output);
		output=sep+1;
		done=1;

	    } else {

		sep=memchr(output, ':', size);

		if (sep) {

		    *sep='\0';
		    logoutput("get_timeinfo_server: %s not reckognized", output);

		    size-=(unsigned int) (sep + 1 - output);
		    output=sep+1;

		} else {

		    logoutput("get_timeinfo_server: error output");
		    return;

		}

	    }

	    if (size>0 && done==0) goto searchoutput;

	}

    }

    pthread_mutex_lock(&session->status.mutex);

    if (done==1) {

	session->hostinfo.flags|=SSH_HOSTINFO_FLAG_TIMESET;

    } else if (session->hostinfo.flags & SSH_HOSTINFO_FLAG_TIMEINIT) {

	session->hostinfo.flags-=SSH_HOSTINFO_FLAG_TIMEINIT;

    }

    pthread_mutex_unlock(&session->status.mutex);

    logoutput("get_timeinfo_server: ready");

}

static int reverse_check_uri_socket(char *path, char *uri)
{
    unsigned int len=strlen(path);
    char test[len+10];
    int result=-1;

    snprintf(test, len+10, "socket://%s", path);

    if (strcmp(uri, test)==0) {

	result=0;

    }

    return result;

}

static int reverse_check_uri_tcpip(char *host, unsigned int port, char *uri)
{
    char *sep=strstr(uri, "://"); /* ssh channels don't care about the protocol */
    int result=-1;

    if (sep) {
	unsigned int len=strlen(host);
	char test[len+35]; /* 3 + 32 max for port */

	snprintf(test, len+39, "://%s:%i", host, port);

	/* compare from the sep: the scheme is irrelevant */

	if (strcmp(sep, test)==0) {

	    result=0;

	}

    }

    return result;
}

int reverse_check_channel_uri(struct ssh_channel_s *channel, char *uri)
{
    int result=-1;

    if (channel->type==_CHANNEL_TYPE_DIRECT_STREAMLOCAL) {

	result=reverse_check_uri_socket(channel->target.socket.path, uri);

    } else if (channel->type==_CHANNEL_TYPE_DIRECT_TCPIP) {

	result=reverse_check_uri_tcpip(channel->target.tcpip.host, channel->target.tcpip.port, uri);

    } else {

	logoutput_warning("reverse_check_channel_uri: channel type %i not reckognized", channel->type);

    }

    return result;
}

/* functions to translate an uri in a specific channel
    20170720: only sockets://path and tcp/ip connections to a host:port are supported
*/

int translate_channel_uri(struct ssh_channel_s *channel, char *uri, unsigned int *error)
{
    unsigned int len=strlen(uri);
    int result=-1;

    if (len>9 && strncmp(uri, "socket://", 9)==0) {
	char *path=(char *)(uri + 9);

	channel->target.socket.path=strdup(path);

	if (channel->target.socket.path==NULL) {

	    *error=ENOMEM;
	    goto error;

	}

	channel->type=_CHANNEL_TYPE_DIRECT_STREAMLOCAL;

    } else {
	char *sep=strstr(uri, "://");

	if (sep) {
	    char target[len];
	    unsigned int port=0;
	    unsigned int left=len - (unsigned int)(sep - uri);

	    /* there must be a host and a port in the uri like
	    sftp://192.168.2.10:4400 */

	    sep+=3;
	    left-=3;

	    memcpy(target, sep, left);
	    target[left]='\0';
	    sep=memchr(target, ':', left);

	    if (sep==NULL) {

		*error=EINVAL;
		goto error;

	    }

	    *sep='\0';
	    port=atoi(sep+1);

	    if (port==0) {

		*error=EINVAL;
		goto error;

	    }

	    /* check the uri is just a host and a port, more not supported */

	    if (reverse_check_uri_tcpip(target, port, uri)==-1) goto error;

	    channel->target.tcpip.host=strdup(target);

	    if (channel->target.tcpip.host==NULL) {

		*error=ENOMEM;
		goto error;

	    }

	    channel->target.tcpip.port=port;
	    channel->type=_CHANNEL_TYPE_DIRECT_TCPIP;

	}

    }

    return 0;

    error:

    logoutput_warning("translate_channel_uri: error %i (%s)", *error, strerror(*error));

}

/* simple test on uri: what type of channel is required? */

unsigned char get_channel_type_uri(char *uri)
{
    unsigned int len=strlen(uri);

    if (len>9 && strncmp(uri, "socket://", 9)==0) {
	char *path=(char *)(uri + 9);

	if (reverse_check_uri_socket(path, uri)==0) return _CHANNEL_TYPE_DIRECT_STREAMLOCAL;

    } else if (len>5) {
	char *sep=strstr(uri, "://");

	if (sep) {
	    char target[len];
	    unsigned int port=0;
	    unsigned int left=len - (unsigned int)(sep - uri);

	    sep+=3;
	    left-=3;

	    memcpy(target, sep, left);
	    target[left]='\0';
	    sep=memchr(target, ':', left);

	    if (sep==NULL) goto out;

	    *sep='\0';
	    port=atoi(sep+1);

	    if (port==0) goto out;

	    /* check the uri is just a host and a port, more not supported */

	    if (reverse_check_uri_tcpip(target, port, uri)==0) return _CHANNEL_TYPE_DIRECT_TCPIP;

	}

    }

    out:
    return 0;

}
