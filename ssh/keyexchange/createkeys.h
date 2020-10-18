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

#ifndef _SSH_KEYEXCHANGE_CREATEKEYS_H
#define _SSH_KEYEXCHANGE_CREATEKEYS_H

int create_H(struct ssh_connection_s *c, struct ssh_keyex_s *k, struct ssh_key_s *pkey, struct ssh_hash_s *H);
int create_keyx_hashes(struct ssh_connection_s *c, struct ssh_keyex_s *k, struct ssh_hash_s *H, unsigned int *error);

#endif
