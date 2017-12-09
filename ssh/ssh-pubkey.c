/*
  2010, 2011, 2012, 2103, 2014, 2015, 2016 Stef Bon <stefbon@gmail.com>

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

#include "logging.h"
#include "main.h"
#include "utils.h"

#include "ssh-common.h"
#include "ssh-pubkey-libgcrypt.h"
#include "ssh-pubkey-utils.h"
#include "ssh-utils.h"

#include "ctx-options.h"

const char *get_hashname_pubkey(struct ssh_session_s *session, struct ssh_key_s *key)
{
    /* this gives the oppurtinity for other digests as well for publickey signing and verifying */
    return "sha1";
}

int read_parameters_pubkey(struct ssh_session_s *session, struct ssh_key_s *key, unsigned int *error)
{
    struct ssh_pubkey_s *pubkey=&session->pubkey;
    return (* pubkey->read_parameters)(key, error);
}

int verify_sigH(struct ssh_session_s *session, struct ssh_key_s *key, struct common_buffer_s *data, struct common_buffer_s *sigH)
{
    struct ssh_pubkey_s *pubkey=&session->pubkey;
    const char *hashname=get_hashname_pubkey(session, key);
    return (* pubkey->verify_sigH)(key, data, sigH, hashname);
}

int create_signature(struct ssh_session_s *session, struct ssh_key_s *key, struct common_buffer_s *data, struct ssh_string_s *signature, unsigned int *error)
{
    struct ssh_pubkey_s *pubkey=&session->pubkey;
    const char *hashname=get_hashname_pubkey(session, key);
    return (* pubkey->create_signature)(key, data, signature, hashname, error);
}

void init_pubkey(struct ssh_session_s *session)
{
    struct ssh_pubkey_s *pubkey=&session->pubkey;
    init_pubkey_libgcrypt(pubkey);
}

void free_pubkey(struct ssh_session_s *session)
{
    struct ssh_pubkey_s *pubkey=&session->pubkey;
}

unsigned int check_add_pubkeyname(const char *name, struct commalist_s *clist)
{
    return check_add_generic(get_ssh_options("pubkey"), name, clist);
}

unsigned int ssh_get_pubkey_list(struct commalist_s *clist)
{
    return ssh_get_pubkey_list_libgcrypt(clist);
}
