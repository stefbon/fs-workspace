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

#include "main.h"
#include "logging.h"
#include "utils.h"

#include "ssh-common-protocol.h"

extern void store_uint32(char *buff, uint32_t value);

struct disconnect_reasons_s {
    unsigned int 	reason;
    const char		*description;
};

static struct disconnect_reasons_s d_reasons[] = {
    {0							, ""},
    {SSH_DISCONNECT_HOST_NOT_ALLOWED_TO_CONNECT		, "Host is not allowed to connect."},
    {SSH_DISCONNECT_PROTOCOL_ERROR			, "Protocol error."},
    {SSH_DISCONNECT_KEY_EXCHANGE_FAILED			, "Key exchange failed."},
    {SSH_DISCONNECT_RESERVED				, "Reserved."},
    {SSH_DISCONNECT_MAC_ERROR				, "MAC error,"},
    {SSH_DISCONNECT_COMPRESSION_ERROR			, "Compression error."},
    {SSH_DISCONNECT_SERVICE_NOT_AVAILABLE		, "Service not available."},
    {SSH_DISCONNECT_PROTOCOL_VERSION_NOT_SUPPORTED	, "Protocol version is not supported."},
    {SSH_DISCONNECT_HOST_KEY_NOT_VERIFIABLE		, "Host key is not verifiable."},
    {SSH_DISCONNECT_CONNECTION_LOST			, "Connection is lost."},
    {SSH_DISCONNECT_BY_APPLICATION			, "Disconnected by application."},
    {SSH_DISCONNECT_TOO_MANY_CONNECTIONS		, "Too many connections."},
    {SSH_DISCONNECT_AUTH_CANCELLED_BY_USER		, "Authorization cancelled by user."},
    {SSH_DISCONNECT_NO_MORE_AUTH_METHODS_AVAILABLE	, "No more authorization methods are available."},
    {SSH_DISCONNECT_ILLEGAL_USER_NAME			, "Illegal user name."}};

unsigned int write_disconnect_reason(unsigned int reason, char *pos, unsigned int size, unsigned int *error)
{
    unsigned int len=0;

    if (reason>=0 && reason <= SSH_DISCONNECT_ILLEGAL_USER_NAME) {

	len=strlen(d_reasons[reason].description);

	if (pos) {

	    if (4 + len <= size) {

		store_uint32(pos, len);
		memcpy(pos+4, d_reasons[reason].description, len);

	    } else {

		*error=ENAMETOOLONG;
		len=0;

	    }

	}

    } else {

	*error=EINVAL;

    }

    return len+4;

}
