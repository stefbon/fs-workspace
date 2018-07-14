/*
  2010, 2011, 2012, 2013, 2014, 2015, 2016 Stef Bon <stefbon@gmail.com>

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

#ifndef FS_WORKSPACE_SSH_KEYEXCHANGE_ALGO_EXCHANGE_H
#define FS_WORKSPACE_SSH_KEYEXCHANGE_ALGO_EXCHANGE_H

int store_kexinit_server(struct keyexchange_s *keyexchange, struct ssh_payload_s *payload, unsigned int *error);
int store_kexinit_client(struct keyexchange_s *keyexchange, struct ssh_payload_s *payload, unsigned int *error);
void free_kexinit_server(struct keyexchange_s *keyexchange);
void free_kexinit_client(struct keyexchange_s *keyexchange);

int start_algo_exchange(struct ssh_session_s *session, struct sessionphase_s *sessionphase);

#endif
