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

#ifndef FS_WORKSPACE_SSH_DATATYPES_NAMELIST_H
#define FS_WORKSPACE_SSH_DATATYPES_NAMELIST_H

struct commalist_s {
    char 				*list;
    unsigned int 			len;
    unsigned int 			size;
};

/* prototypes */

unsigned int add_name_to_commalist(const char *name, struct commalist_s *clist, unsigned int *error);
void free_list_commalist(struct commalist_s *clist);
unsigned char string_found_commalist(char *list, char *name);
unsigned char name_found_namelist(struct commalist_s *clist, char *name);

#endif
