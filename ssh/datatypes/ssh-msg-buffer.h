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

#ifndef FS_WORKSPACE_SSH_DATATYPES_MSG_BUFFER_H
#define FS_WORKSPACE_SSH_DATATYPES_MSG_BUFFER_H

struct msg_buffer_s {
    char				*data;
    unsigned int			len;
    unsigned int			pos;
    unsigned int			error;
    void				(* write_byte)(struct msg_buffer_s *mb, unsigned char b);
    void				(* write_bytes)(struct msg_buffer_s *mb, unsigned char *bytes, unsigned int len);
    unsigned int			(* start_ssh_string)(struct msg_buffer_s *mb);
    void 				(* write_ssh_string)(struct msg_buffer_s *mb, const unsigned char type, void *ptr);
    void				(* complete_ssh_string)(struct msg_buffer_s *mb, unsigned int pos);
    void				(* store_uint32)(struct msg_buffer_s *mb, uint32_t value);
    void				(* store_uint64)(struct msg_buffer_s *mb, uint64_t value);
    void				(* fill_commalist)(struct msg_buffer_s *mb, void (* cb)(struct msg_buffer_s *mb, void *ptr), void *ptr);
    unsigned int			(* start_count)(struct msg_buffer_s *mb);
    void				(* complete_count)(struct msg_buffer_s *mb, unsigned int pos, unsigned int count);
};

/* prototypes */

extern struct msg_buffer_s init_msg_buffer;

// #define INIT_SSH_MSG_BUFFER		{NULL, 0, 0, 0, nowrite_byte, nowrite_bytes, start_ssh_string, nowrite_ssh_string, nowrite_complete_ssh_string, nostore_uint32, nostore_uint64, nofill_commalist, start_count, nowrite_start_count}

#define INIT_SSH_MSG_BUFFER		init_msg_buffer

/*void nowrite_byte(struct msg_buffer_s *mb, unsigned char b);
void nowrite_bytes(struct msg_buffer_s *mb, unsigned char *bytes, unsigned int len);
unsigned int start_ssh_string(struct msg_buffer_s *mb);
void nowrite_ssh_string(struct msg_buffer_s *mb, const unsigned char type, void *ptr);
void nowrite_complete_ssh_string(struct msg_buffer_s *mb, unsigned int pos);
void nostore_uint32(struct msg_buffer_s *mb, uint32_t value);
void nostore_uint64(struct msg_buffer_s *mb, uint64_t value);
void nofill_commalist(struct msg_buffer_s *mb, void (* cb)(struct msg_buffer_s *mb, void *ptr), void *ptr);
unsigned int start_count(struct msg_buffer_s *mb);
void nowrite_complete_count(struct msg_buffer_s *mb, unsigned int pos, unsigned int count); */

void set_msg_buffer(struct msg_buffer_s *mb, char *data, unsigned int len);
void set_msg_buffer_payload(struct msg_buffer_s *mb, struct ssh_payload_s *p);
void set_msg_buffer_string(struct msg_buffer_s *mb, struct ssh_string_s *s);
void set_msg_buffer_fatal_error(struct msg_buffer_s *mb, unsigned int error);

void msg_write_byte(struct msg_buffer_s *mb, unsigned char byte);
void msg_write_bytes(struct msg_buffer_s *mb, unsigned char *bytes, unsigned int len);
void msg_write_ssh_string(struct msg_buffer_s *mb, const unsigned char type, void *ptr);
void msg_store_uint32(struct msg_buffer_s *mb, uint32_t value);
void msg_store_uint64(struct msg_buffer_s *mb, uint64_t value);
void msg_fill_commalist(struct msg_buffer_s *mb, void (* cb)(struct msg_buffer_s *mb, void *ptr), void *ptr);
unsigned int msg_start_count(struct msg_buffer_s *mb);
void msg_complete_count(struct msg_buffer_s *mb, unsigned int pos, unsigned int count);

void msg_read_byte(struct msg_buffer_s *mb, unsigned char *b);
void msg_read_bytes(struct msg_buffer_s *mb, unsigned char *b, unsigned int *plen);
void msg_read_ssh_string_header(struct msg_buffer_s *mb, unsigned int *len);
void msg_read_ssh_string(struct msg_buffer_s *mb, struct ssh_string_s *s);
void msg_read_uint32(struct msg_buffer_s *mb, unsigned int *result);
void msg_read_uint64(struct msg_buffer_s *mb, uint64_t *result);

unsigned int msg_count_strings(struct msg_buffer_s *mb, unsigned int max);

#endif
