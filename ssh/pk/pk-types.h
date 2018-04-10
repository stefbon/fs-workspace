/*
  2010, 2011, 2012, 2013, 2014, 2015, 2016, 2017, 2018 Stef Bon <stefbon@gmail.com>

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

#ifndef FS_WORKSPACE_SSH_PK_TYPES_H
#define FS_WORKSPACE_SSH_PK_TYPES_H

#define SSH_PKALGO_ID_DSS		1
#define SSH_PKALGO_ID_RSA		2
#define SSH_PKALGO_ID_ED25519		3

struct ssh_pkalgo_s {
    unsigned int			id;
    const char				*name;
    unsigned int			len;
};

struct ssh_pkalgo_s *get_pkalgo(char *algo, unsigned int len);
struct ssh_pkalgo_s *get_pkalgo_byid(unsigned int id);

struct ssh_pkalgo_s *get_next_pkalgo(struct ssh_pkalgo_s *algo);
unsigned int write_pkalgo(char *buffer, struct ssh_pkalgo_s *pkalgo);
struct ssh_pkalgo_s *read_pkalgo(char *buffer, unsigned int size, int *read);

#endif
