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

#include "logging.h"
#include "main.h"
#include "utils.h"

#include "ssh-common.h"
#include "ssh-utils.h"
#include "ssh-send.h"

static unsigned int populate_compress(struct ssh_connection_s *c, struct compress_ops_s *ops, struct algo_list_s *alist, unsigned int start)
{

    if (alist) {

	alist[start].type=SSH_ALGO_TYPE_COMPRESS_C2S;
	alist[start].order=SSH_ALGO_ORDER_MEDIUM;
	alist[start].sshname="none";
	alist[start].libname="none";
	alist[start].ptr=(void *)ops;

    }

    start++;

    return start;

}

static unsigned int get_handle_size(struct ssh_compress_s *d)
{
    return 0;
}

static int compress_payload(struct ssh_compressor_s *d, struct ssh_payload_s **p_payload, unsigned int *error)
{
    // logoutput("compress_payload (none): len=%i", (*p_payload)->len);
    return 0;
}

static void clear_compressor(struct ssh_compressor_s *d)
{
}

static int init_compressor(struct ssh_compressor_s *d)
{
    // logoutput("init_compressor (none)");
    d->compress_payload		= compress_payload;
    d->clear			= clear_compressor;
    return 0;
}

static struct compress_ops_s none_c_ops = {
    .name			= "none",
    .populate			= populate_compress,
    .get_handle_size		= get_handle_size,
    .init_compressor		= init_compressor,
};

void init_compress_none()
{
    add_compress_ops(&none_c_ops);
}

void set_compress_none(struct ssh_compress_s *compress)
{
    compress->ops=&none_c_ops;
}
