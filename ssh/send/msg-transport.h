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

#ifndef _SSH_SEND_MSG_TRANSPORT_H
#define _SSH_SEND_MSG_TRANSPORT_H

/* prototypes */

int send_disconnect_message(struct ssh_connection_s *c, unsigned int reason);
int send_ignore_message(struct ssh_connection_s *c, struct ssh_string_s *data);
int send_debug_message(struct ssh_connection_s *c, struct ssh_string_s *debug);
int send_unimplemented_message(struct ssh_connection_s *c, unsigned int number);
int send_kexinit_message(struct ssh_connection_s *c);
int send_newkeys_message(struct ssh_connection_s *c);
int send_service_request_message(struct ssh_connection_s *c, const char *service, unsigned int *seq);

#endif
