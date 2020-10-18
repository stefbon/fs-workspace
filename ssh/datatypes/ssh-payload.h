/*
  2010, 2011, 2012, 2013, 2014, 2015, 2016, 2017 Stef Bon <stefbon@gmail.com>

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

#ifndef FS_WORKSPACE_SSH_DATATYPES_PAYLOAD_H
#define FS_WORKSPACE_SSH_DATATYPES_PAYLOAD_H

#include "common-utils/simple-list.h"

#define SSH_PAYLOAD_FLAG_ALLOCATED	1

struct ssh_payload_s {
    unsigned int			flags;
    unsigned char			type;
    unsigned int			sequence;
    unsigned int			len;
    struct list_element_s		list;
    struct ssh_payload_s		*(* realloc)(struct ssh_payload_s *p, unsigned int size);
    void				(* free)(struct ssh_payload_s **p);
    char				*(* isolate_buffer)(struct ssh_payload_s **p, unsigned int pos, unsigned int size);
    char				buffer[];
};

/* prototypes */

struct ssh_payload_s *malloc_payload(unsigned int size);
void init_ssh_payload(struct ssh_payload_s *payload, unsigned int size);
char *isolate_payload_buffer(struct ssh_payload_s **payload, unsigned int pos, unsigned int size);
void free_payload(struct ssh_payload_s **p);
struct ssh_payload_s *realloc_payload(struct ssh_payload_s *payload, unsigned int size);

void copy_payload_header(struct ssh_payload_s *a, struct ssh_payload_s *b);
void fill_payload_buffer(struct ssh_payload_s *a, char *buffer, unsigned int len);

void set_alloc_payload_dynamic(struct ssh_payload_s *payload);
void set_alloc_payload_static(struct ssh_payload_s *payload);

#endif
