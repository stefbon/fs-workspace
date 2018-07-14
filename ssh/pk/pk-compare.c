/*
  2010, 2011, 2012, 2103, 2014, 2015, 2016, 2017, 2018 Stef Bon <stefbon@gmail.com>

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
#include <ctype.h>
#include <inttypes.h>

#include <sys/param.h>
#include <sys/types.h>

#include "logging.h"
#include "main.h"
#include "utils.h"

#include "ssh-datatypes.h"
#include "pk-types.h"
#include "pk-keys.h"
#include "pk-utils.h"

int compare_ssh_keys(struct ssh_key_s *a, struct ssh_key_s *b)
{

    if (a->algo==NULL || b->algo==NULL) return -1;
    if (a->algo != b->algo) return -1;

    logoutput("compare_ssh_keys");

    if (a->algo->id == SSH_PKALGO_ID_RSA) {

	if (compare_ssh_mpint(&a->param.rsa.n, &b->param.rsa.n)!=0) return -1;
	if (compare_ssh_mpint(&a->param.rsa.e, &b->param.rsa.e)!=0) return -1;

	/* if one of keys is public then ready */
	if (a->secret==0 || b->secret==0) goto ready;

	if (compare_ssh_mpint(&a->param.rsa.d, &b->param.rsa.d)!=0) return -1;
	if (compare_ssh_mpint(&a->param.rsa.p, &b->param.rsa.p)!=0) return -1;
	if (compare_ssh_mpint(&a->param.rsa.q, &b->param.rsa.q)!=0) return -1;
	if (compare_ssh_mpint(&a->param.rsa.u, &b->param.rsa.u)!=0) return -1;

    } else if (a->algo->id == SSH_PKALGO_ID_DSS) {

	if (compare_ssh_mpint(&a->param.dss.p, &b->param.dss.p)!=0) return -1;
	if (compare_ssh_mpint(&a->param.dss.q, &b->param.dss.q)!=0) return -1;
	if (compare_ssh_mpint(&a->param.dss.g, &b->param.dss.g)!=0) return -1;
	if (compare_ssh_mpint(&a->param.dss.y, &b->param.dss.y)!=0) return -1;

	/* if one of keys is public then ready */
	if (a->secret==0 || b->secret==0) goto ready;

	if (compare_ssh_mpint(&a->param.dss.x, &b->param.dss.x)!=0) return -1;

    } else if (a->algo->id == SSH_PKALGO_ID_ED25519) {

	/* q is the public key but is optional for the private key
	    if defined in both test it */

	if (a->secret==0 && a->param.ecc.q.lib.mpi==NULL) return -1;
	if (b->secret==0 && b->param.ecc.q.lib.mpi==NULL) return -1;

	if (a->param.ecc.q.lib.mpi && b->param.ecc.q.lib.mpi) {

	    if (compare_ssh_mpoint(&a->param.ecc.q, &b->param.ecc.q)!=0) return -1;

	}

	if (a->secret==0 || b->secret==0) goto ready;

	/* d is the private key, only found if both are private keys */

	if (compare_ssh_mpint(&a->param.ecc.d, &b->param.ecc.d)!=0) return -1;

    } else {

	return -1;

    }

    ready:

    return 0;

}

/* compare a key with a representation of the (same?) key in another format
    there are more ways to do this:
    - read a temp key from the data and compare that with the original key
    - write the original key to the other format and compare the resulting buffer with the other buffer */

int compare_ssh_key_data(struct ssh_key_s *a, char *buffer, unsigned int len, unsigned int format)
{
    struct msg_buffer_s mb=INIT_SSH_MSG_BUFFER;
    struct ssh_key_s b;
    unsigned int error=0;
    int result=-1;

    if (buffer==NULL || len==0) return -1;

    set_msg_buffer(&mb, buffer, len);
    init_ssh_key(&b, a->secret, a->algo);

    (* b.msg_read_key)(&mb, &b, format);

    if (mb.error>0) {

	logoutput("compare_ssh_key_data: error %i reading parameters (%s)", error, strerror(error));
	goto out;

    }

    result=compare_ssh_keys(a, &b);

    logoutput("compare_ssh_key_data: free");

    out:

    (* b.free_param)(&b);

    logoutput("compare_ssh_key_data: result %i", result);

    return result;

}
