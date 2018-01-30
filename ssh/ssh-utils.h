/*
  2010, 2011, 2012, 2013, 2014, 2015 Stef Bon <stefbon@gmail.com>

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

#ifndef FS_WORKSPACE_SSH_UTILS_H
#define FS_WORKSPACE_SSH_UTILS_H

#define SSH_STRING_FLAG_ALLOCATE				1
#define SSH_STRING_FLAG_NULLTERMINATE				2

/* prototypes */

unsigned int add_name_to_commalist(const char *name, struct commalist_s *clist, unsigned int *error);
void free_list_commalist(struct commalist_s *clist);
unsigned char string_found_commalist(char *commalist, char *name);
unsigned int check_add_generic(char *options, const char *name, struct commalist_s *clist);

void store_uint32(char *buff, uint32_t value);
void store_uint64(unsigned char *buff, uint64_t value);
unsigned int store_ssh_string(char *buff, struct ssh_string_s *string);
unsigned int get_uint32(char *buff);
uint64_t get_uint64(unsigned char *buff);
uint64_t get_int64(unsigned char *buff);
uint16_t get_uint16(unsigned char *buff);

int init_sshlibrary();
void end_sshlibrary();

void init_ssh_payload(struct ssh_payload_s *payload);

unsigned int hash(const char *name, struct common_buffer_s *in, struct common_buffer_s *out, unsigned int *error);
unsigned int get_digest_len(const char *name);
uint64_t ntohll(uint64_t value);
unsigned int fill_random(char *pos, unsigned int len);

unsigned char isvalid_ipv4(char *address);
void replace_cntrl_char(char *buffer, unsigned int size);
void replace_newline_char(char *ptr, unsigned int *size);

char *decode_base64(struct common_buffer_s *buffer, unsigned int *len);
int compare_encoded_base64(char *encoded, struct common_buffer_s *buffer);

void init_ssh_string(struct ssh_string_s *s);
void free_ssh_string(struct ssh_string_s *s);
unsigned int create_ssh_string(struct ssh_string_s *s, unsigned int len);

unsigned int copy_byte_to_buffer(struct common_buffer_s *b, unsigned char s);
unsigned int copy_ssh_string_to_buffer(struct common_buffer_s *b, struct ssh_string_s *s);
unsigned int copy_buffer_to_buffer(struct common_buffer_s *b, struct common_buffer_s *s);
unsigned int copy_char_to_buffer(struct common_buffer_s *b, char *s, unsigned int len);

int get_ssh_string_from_buffer(struct common_buffer_s *b, struct ssh_string_s *s, unsigned int flags);

#endif
