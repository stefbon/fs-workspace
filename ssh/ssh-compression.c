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

#include "ctx-options.h"

#include "ssh-common.h"
#include "ssh-utils.h"
#include "ssh-compression.h"

static int deflate_none(struct ssh_compression_s *compression, struct ssh_payload_s *payload)
{
    return 0;
}

static struct ssh_payload_s *inflate_none(struct ssh_compression_s *compression, struct ssh_payload_s *payload)
{
    return payload;
}

static void close_compression_none(struct ssh_compression_s *compression)
{
}

static int set_compression_s2c_none(struct ssh_compression_s *compression, const char *name, unsigned int *error)
{
    compression->inflate=inflate_none;
    compression->close_inflate=close_compression_none;
    return 0;
}

static int set_compression_c2s_none(struct ssh_compression_s *compression, const char *name, unsigned int *error)
{
    compression->deflate=deflate_none;
    compression->close_deflate=close_compression_none;
    return 0;
}

/* set inflate */
int set_compression_s2c(struct ssh_session_s *session, const char *name, unsigned int *error)
{
    struct ssh_compression_s *compression=&session->crypto.compression;

    logoutput_info("set_compression_s2c: name %s", name);

    if (strcmp(name, "none")==0) {

	return set_compression_s2c_none(compression, name, error);

    }

    return -1;

}

/* set deflate */
int set_compression_c2s(struct ssh_session_s *session, const char *name, unsigned int *error)
{
    struct ssh_compression_s *compression=&session->crypto.compression;

    logoutput_info("set_compression_c2s: name %s", name);

    if (strcmp(name, "none")==0) {

	return set_compression_c2s_none(compression, name, error);

    }

    return -1;

}

void init_compression(struct ssh_session_s *session)
{
    struct ssh_compression_s *compression=&session->crypto.compression;

    logoutput_info("init_compression");

    compression->deflate=deflate_none;
    compression->inflate=inflate_none;
    compression->close_deflate=close_compression_none;
    compression->close_inflate=close_compression_none;
    compression->set_inflate=set_compression_s2c_none;
    compression->set_deflate=set_compression_c2s_none;

    compression->inflatebound=6;

}

int deflate_payload(struct ssh_session_s *session, struct ssh_payload_s *payload)
{
    struct ssh_compression_s *compression=&session->crypto.compression;
    return  (* compression->deflate)(compression, payload);
}

struct ssh_payload_s *inflate_payload(struct ssh_session_s *session, struct ssh_payload_s *payload)
{
    struct ssh_compression_s *compression=&session->crypto.compression;
    return (* compression->inflate)(compression, payload);
}

unsigned int check_add_compressionname(const char *name, struct commalist_s *clist)
{
    return check_add_generic(get_ssh_options("compression"), name, clist);
}

unsigned int ssh_get_compression_list(struct commalist_s *clist)
{
    unsigned int len=0;
    unsigned int error=0;

    len+=add_name_to_commalist("none", clist, &error);
    // len+=check_add_compressionname("zlib", clist);

    return len;

}
