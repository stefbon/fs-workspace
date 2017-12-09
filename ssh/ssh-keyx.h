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

#ifndef FS_WORKSPACE_SSH_KEYX_H
#define FS_WORKSPACE_SSH_KEYX_H

void init_keyx(struct ssh_keyx_s *keyx);
int set_keyx(struct ssh_keyx_s *keyx, const char *name, const char *serverkeyname, unsigned int *error);

int start_keyx(struct ssh_session_s *session, struct ssh_keyx_s *keyx, struct ssh_kexinit_algo *algos);
void free_keyx(struct ssh_keyx_s *keyx);

unsigned int ssh_get_keyx_list(struct commalist_s *clist);

#endif
