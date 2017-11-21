/*
  2010, 2011, 2012, 2103, 2014, 2015, 2016, 2017 Stef Bon <stefbon@gmail.com>

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

#include "global-defines.h"

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <errno.h>
#include <err.h>
#include <sys/time.h>
#include <time.h>
#include <pthread.h>
#include <ctype.h>
#include <inttypes.h>

#include <sys/param.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/syscall.h>

#include "logging.h"
#include "main.h"
#include "pathinfo.h"
#include "simple-list.h"

#include "utils.h"
#include "options.h"

#include "ctx-keystore.h"
#include "ctx-keystore-openssh.h"
#include "ctx-keystore-openssh-knownhosts.h"

void *init_identity_records(struct passwd *pwd, struct hostaddress_s *hostaddress, const char *what, unsigned int *error)
{
    return init_identity_records_openssh(pwd, hostaddress, what, error);
}

struct common_identity_s *get_next_identity_record(void *ptr)
{
    return get_next_identity_openssh(ptr);
}

int get_public_key(struct common_identity_s *identity, char *buffer, unsigned int len)
{
    return get_public_key_openssh(identity, buffer, len);
}

int get_private_key(struct common_identity_s *identity, char *buffer, unsigned int len)
{
    return get_private_key_openssh(identity, buffer, len);
}

void free_identity_record(struct common_identity_s *identity)
{
    free_identity_record_openssh(identity);
}

void finish_identity_records(void *ptr)
{
    finish_identity_records_openssh(ptr);
}

void *init_known_hosts(struct passwd *pwd, unsigned int *error)
{
    return init_known_hosts_openssh(pwd, error);
}

struct known_host *get_next_known_host(void *ptr, unsigned int *error)
{
    return get_next_known_host_openssh(ptr, error);
}

void finish_known_hosts(void *ptr)
{
    finish_known_hosts_openssh(ptr);
}