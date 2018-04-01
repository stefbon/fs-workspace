/*
  2010, 2011, 2012, 2103, 2014, 2015, 2016, 2017, 2018 Stef Bon <stefbon@gmail.com>

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
#include <ctype.h>
#include <inttypes.h>

#include <sys/param.h>
#include <sys/types.h>

#include "logging.h"
#include "main.h"
#include "utils.h"

#include "ssh-common.h"
#include "ssh-utils.h"
#include "pk-types.h"

static struct ssh_pkalgo_s ssh_pkalgo_rsa = {
	.id			=	SSH_PKALGO_ID_RSA,
	.name			=	"ssh-rsa",
	.len			=	7,
};

static struct ssh_pkalgo_s ssh_pkalgo_dss = {
	.id			=	SSH_PKALGO_ID_DSS,
	.name			=	"ssh-dss",
	.len			=	7,
};

static struct ssh_pkalgo_s ssh_pkalgo_ed25519 = {
	.id			=	SSH_PKALGO_ID_ED25519,
	.name			=	"ssh-ed25519",
	.len			=	11,
};

struct ssh_pkalgo_s *get_pkalgo(char *algo, unsigned int len)
{

    if (len==ssh_pkalgo_rsa.len && strncmp(algo, ssh_pkalgo_rsa.name, len)==0) {

	return &ssh_pkalgo_rsa;

    } else if (len==ssh_pkalgo_dss.len && strncmp(algo, ssh_pkalgo_dss.name, len)==0) {

	return &ssh_pkalgo_dss;

    } else if (len==ssh_pkalgo_ed25519.len && strncmp(algo, ssh_pkalgo_ed25519.name, len)==0) {

	return &ssh_pkalgo_ed25519;

    }

    return NULL;

}

unsigned int write_pkalgo(char *buffer, struct ssh_pkalgo_s *pkalgo)
{

    if (buffer) {

	store_uint32(buffer, pkalgo->len);
	memcpy(buffer + 4, pkalgo->name, pkalgo->len);

    }

    return (pkalgo->len + 4);

}

struct ssh_pkalgo_s *read_pkalgo(char *buffer, unsigned int size, int *read)
{

    if (read) *read=0;

    if (size>4) {
	unsigned int len=get_uint32(buffer);

	if (read) *read+=4;

	if (len + 4 <= size) {

	    if (read) *read+=len;
	    return get_pkalgo(buffer + 4, len);

	}

    }

    return NULL;
}
