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

#ifndef CTX_KEYSTORE_OPENSSH_KNOWNHOSTS_H
#define CTX_KEYSTORE_OPENSSH_KNOWNHOSTS_H

#include <pwd.h>

/* prototypes */

void *init_known_hosts_openssh(struct passwd *pwd, unsigned int filter, unsigned int *error);
int get_next_known_host_openssh(void *ptr, unsigned int *error);
void *finish_known_hosts_openssh(void *ptr);

int compare_host_known_host_openssh(void *prt, char *host);
char *get_algo_known_host_openssh(void *ptr);
int match_key_known_host_openssh(void *ptr, char *key, unsigned int len);

#endif
