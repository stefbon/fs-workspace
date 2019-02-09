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
#include "ssh-receive.h"

static struct list_header_s list_decompress_ops=INIT_LIST_HEADER;

struct decompress_ops_s *get_decompress_ops_container(struct list_element_s *list)
{
    return (struct decompress_ops_s *) (((char *) list) - offsetof(struct decompress_ops_s, list));
}

void add_decompress_ops(struct decompress_ops_s *ops)
{
    add_list_element_last(&list_decompress_ops, &ops->list);
}

struct decompress_ops_s *get_next_decompress_ops(struct decompress_ops_s *ops)
{
    if (ops) {
	struct list_element_s *next=ops->list.n;

	return (next) ? get_decompress_ops_container(next) : NULL;

    } else {
	struct list_element_s *head=list_decompress_ops.head;

	return (head) ? get_decompress_ops_container(head) : NULL;

    }

    return NULL;
}


void reset_decompress(struct ssh_session_s *session, struct algo_list_s *algo_compr)
{
    struct ssh_receive_s *receive=&session->receive;
    struct ssh_decompress_s *decompress=&receive->decompress;
    struct decompress_ops_s *ops=(struct decompress_ops_s *) algo_compr->ptr;

    remove_decompressors(decompress);
    memset(decompress->name, '\0', sizeof(decompress->name));

    decompress->ops=ops;
    strcpy(decompress->name, algo_compr->sshname);

}

unsigned int build_compress_list_s2c(struct ssh_session_s *session, struct algo_list_s *alist, unsigned int start)
{
    struct decompress_ops_s *ops=NULL;

    ops=get_next_decompress_ops(NULL);

    while (ops) {

	start=(* ops->populate)(session, ops, alist, start);
	ops=get_next_decompress_ops(ops);

    }

    return start;

}
