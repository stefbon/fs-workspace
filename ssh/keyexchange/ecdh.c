/*
  2016, 2017, 2018 Stef Bon <stefbon@gmail.com>

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

#include "logging.h"
#include "main.h"

#include "utils.h"

#include "ssh-common-protocol.h"
#include "ssh-common.h"
#include "ssh-utils.h"
#include "ssh-data.h"

#include "ssh-receive.h"
#include "ssh-send.h"

unsigned int populate_keyx_ecdh(struct ssh_session_s *session, struct algo_list_s *alist, unsigned int start)
{

    if (alist) {

	alist[start].type=SSH_ALGO_TYPE_KEX;
	alist[start].order=SSH_ALGO_ORDER_MEDIUM;
	alist[start].sshname="curve25519-sha256@libssh.org";
	alist[start].libname="curve25519-sha256@libssh.org";
	alist[start].ptr=NULL;

    }

    start++;
    return start;

}

static int dh_create_client_key(struct ssh_keyx_s *keyx)
{
    struct ssh_dh_s *dh=&keyx->method.dh;
    unsigned int bits = get_nbits_ssh_mpint(&dh->p);

    if (create_ssh_mpint(&dh->x)==-1) return -1;
    if (create_ssh_mpint(&dh->e)==-1) return -1;

    /* size of subgroup is (q = (p - 1)/2) which results in a number of (bits(p) - 1) bits
	TODO: is this always the case ??? also with another generator ??? */

    bits--;

    if (randomize_ssh_mpint(&dh->x, bits)==-1) return -1;

    /* TODO: here a check 1 < x < q */

    power_modulo_ssh_mpint(&dh->e, &dh->g, &dh->x, &dh->p);
    return 0;

}

static void dh_msg_write_client_key(struct msg_buffer_s *mb, struct ssh_keyx_s *keyx)
{
    struct ssh_mpint_s *mp=&keyx->method.dh.e;
    unsigned int pos=mb->pos;

    msg_write_ssh_mpint(mb, mp);

    logoutput("dh_msg_write_client_key: len %i", (mb->pos - pos));
}

static void dh_msg_read_server_key(struct msg_buffer_s *mb, struct ssh_keyx_s *keyx)
{
    struct ssh_mpint_s *mp=&keyx->method.dh.f;
    unsigned int pos=mb->pos;

    msg_read_ssh_mpint(mb, mp, NULL);

    logoutput("dh_msg_read_server_key: len %i", (mb->pos - pos));
}

static void dh_msg_write_server_key(struct msg_buffer_s *mb, struct ssh_keyx_s *keyx)
{
    struct ssh_mpint_s *mp=&keyx->method.dh.f;
    msg_write_ssh_mpint(mb, mp);
}

static int dh_calc_shared_K(struct ssh_keyx_s *keyx)
{
    struct ssh_dh_s *dh=&keyx->method.dh;

    if (create_ssh_mpint(&dh->K)==-1) return -1;
    power_modulo_ssh_mpint(&dh->K, &dh->f, &dh->x, &dh->p);
    return 0;

}

static void dh_msg_write_shared_K(struct msg_buffer_s *mb, struct ssh_keyx_s *keyx)
{
    struct ssh_mpint_s *mp=&keyx->method.dh.K;
    msg_write_ssh_mpint(mb, mp);
}

static unsigned int write_kexdh_init_message(struct msg_buffer_s *mb, struct ssh_keyx_s *keyx)
{
    struct ssh_dh_s *dh=&keyx->method.dh;

    msg_write_byte(mb, SSH_MSG_KEXDH_INIT);
    (* keyx->msg_write_client_key)(mb, keyx);

    return mb->pos;

}

void dh_free_keyx(struct ssh_keyx_s *keyx)
{
    struct ssh_dh_s *dh=&keyx->method.dh;

    free_ssh_mpint(&dh->p);
    free_ssh_mpint(&dh->g);
    free_ssh_mpint(&dh->x);
    free_ssh_mpint(&dh->e);
    free_ssh_mpint(&dh->f);
    free_ssh_mpint(&dh->K);

}

static int ecdh_init_keyx(struct ssh_keyx_s *keyx, unsigned int *error)
{
    struct ssh_dh_s *ecdh=&keyx->method.ecdh;

    init_ssh_key(&ecdh->pkey_s, 0, );
    
    init_ssh_mpint(&dh->g);
    init_ssh_mpint(&dh->x);
    init_ssh_mpint(&dh->e);
    init_ssh_mpint(&dh->f);
    init_ssh_mpint(&dh->K);

    if (create_ssh_mpint(&dh->p)==-1) {

	*error=ENOMEM;
	return -1;

    }

    if (read_ssh_mpint(&dh->p, p, lenp, SSH_MPINT_FORMAT_USC, error)==-1) return -1;

    if (create_ssh_mpint(&dh->p)==-1) {

	*error=ENOMEM;
	return -1;

    }

    if (read_ssh_mpint(&dh->g, g, leng, SSH_MPINT_FORMAT_USC, error)==-1) return -1;

    keyx->create_client_key 		= dh_create_client_key;
    keyx->msg_write_client_key		= dh_msg_write_client_key;
    keyx->msg_read_server_key		= dh_msg_read_server_key;
    keyx->msg_write_server_key		= dh_msg_write_server_key;
    keyx->calc_shared_K			= dh_calc_shared_K;
    keyx->msg_write_shared_K		= dh_msg_write_shared_K;
    keyx->free				= dh_free_keyx;
    *error=0;

    return 0;

}

int set_keyx_ecdh(struct ssh_keyx_s *keyx, const char *name, unsigned int *error)
{
    struct ssh_ecdh_s *ecdh=&keyx->method.ecdh;

    memset(ecdh, 0, sizeof(struct ssh_ecdh_s));

    if (strcmp(name, "curve25519-sha256@libssh.org")==0) {

	strcpy(keyx->digestname, "sha256");
	return ecdh_init_keyx(keyx, error);

    }

    *error=EINVAL;
    return -1;

}
