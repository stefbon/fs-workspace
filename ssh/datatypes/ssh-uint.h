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

#ifndef FS_WORKSPACE_SSH_DATATYPES_UINT_H
#define FS_WORKSPACE_SSH_DATATYPES_UINT_H

/* prototypes */

void store_uint32(char *buff, uint32_t value);
void store_uint64(char *buff, uint64_t value);

unsigned int get_uint32(char *buff);
uint64_t get_uint64(char *buff);
int64_t get_int64(char *buff);
uint16_t get_uint16(char *buff);

#endif
