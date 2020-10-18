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

static struct list_header_s list_compress_ops=INIT_LIST_HEADER;

struct compress_ops_s *get_compress_ops_container(struct list_element_s *list)
{
    return (struct compress_ops_s *) (((char *) list) - offsetof(struct compress_ops_s, list));
}

void add_compress_ops(struct compress_ops_s *ops)
{
    add_list_element_last(&list_compress_ops, &ops->list);
}

struct compress_ops_s *get_next_compress_ops(struct compress_ops_s *ops)
{
    if (ops) {
	struct list_element_s *next=ops->list.n;

	return (next) ? get_compress_ops_container(next) : NULL;

    } else {
	struct list_element_s *head=list_compress_ops.head;

	return (head) ? get_compress_ops_container(head) : NULL;

    }

    return NULL;
}


void reset_compress(struct ssh_send_s *send, struct algo_list_s *algo)
{
    logoutput("reset_compress");
}

int build_compress_list_c2s(struct ssh_connection_s *c, struct algo_list_s *alist, unsigned int start)
{
    struct compress_ops_s *ops=NULL;

    ops=get_next_compress_ops(NULL);

    while (ops) {

	start=(* ops->populate)(c, ops, alist, start);
	ops=get_next_compress_ops(ops);

    }

    return start;

}
