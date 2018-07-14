/*
  2018, 2019 Stef Bon <stefbon@gmail.com>

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

#include "ssh-common.h"
#include "ssh-channel.h"
#include "uri.h"

static int reverse_check_uri_socket(char *path, char *uri)
{
    unsigned int len=strlen(path);
    char test[len+10];
    int result=-1;

    snprintf(test, len+10, "socket://%s", path);

    if (strcmp(uri, test)==0) result=0;

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

	if (strcmp(sep, test)==0) result=0;

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
    return -1;

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
