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
#include <pthread.h>
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
#include "pk-readwrite-public.h"
#include "pk-read-private.h"
#include "pk-sign.h"
#include "pk-verify.h"
#include "pk-compare.h"

static void free_param_dummy(struct ssh_key_s *key)
{
    /* does nothing */
}
/* writing private keys is not supported
    not needed anyway, only reading is required
    private/secret keys are required to sign and nothing else
*/

static int write_skey_dummy(struct ssh_key_s *key, char *b, unsigned int s, unsigned int f, unsigned int *e)
{
    *e=EOPNOTSUPP;
    return -1;
}

static void msg_readwrite_key_dummy(struct msg_buffer_s *mb, struct ssh_key_s *key, unsigned int f)
{
    set_msg_buffer_fatal_error(mb, EOPNOTSUPP);
}

static void free_param_rsa(struct ssh_key_s *key)
{
    free_ssh_mpint(&key->param.rsa.n);
    free_ssh_mpint(&key->param.rsa.e);
    free_ssh_mpint(&key->param.rsa.d);
    free_ssh_mpint(&key->param.rsa.p);
    free_ssh_mpint(&key->param.rsa.q);
    free_ssh_mpint(&key->param.rsa.u);
}

static void free_param_dss(struct ssh_key_s *key)
{
    free_ssh_mpint(&key->param.dss.p);
    free_ssh_mpint(&key->param.dss.q);
    free_ssh_mpint(&key->param.dss.g);
    free_ssh_mpint(&key->param.dss.y);
    free_ssh_mpint(&key->param.dss.x);
}

static void free_param_ecc(struct ssh_key_s *key)
{
    free_ssh_mpint(&key->param.ecc.d);
    free_ssh_mpoint(&key->param.ecc.q);
}

/* set the algo for the key */

static void set_algo_common(struct ssh_key_s *key, struct ssh_pkalgo_s *algo)
{

    if (key->algo) {

        if (key->algo == algo) return;
	(* key->free_param)(key);

    }

    key->algo=algo;
    if (algo==NULL) return;

    switch (algo->scheme) {

    case SSH_PKALGO_SCHEME_RSA:

	init_ssh_mpint(&key->param.rsa.n);
	init_ssh_mpint(&key->param.rsa.e);
	init_ssh_mpint(&key->param.rsa.d);
	init_ssh_mpint(&key->param.rsa.p);
	init_ssh_mpint(&key->param.rsa.q);
	init_ssh_mpint(&key->param.rsa.u);

	key->free_param=free_param_rsa;

	if (key->secret==0) {

	    key->read_key=read_pkey_rsa;
	    key->write_key=write_pkey_rsa;
	    key->msg_write_key=msg_write_pkey_rsa;
	    key->msg_read_key=msg_read_pkey_rsa;

	} else {

	    key->read_key=read_skey_rsa;
	    key->write_key=write_skey_dummy;
	    key->msg_write_key=msg_readwrite_key_dummy;
	    key->msg_read_key=msg_read_skey_rsa;

	}

	key->verify=verify_sig_rsa;
	key->sign=create_sig_rsa;

	break;

    case SSH_PKALGO_SCHEME_DSS:

	init_ssh_mpint(&key->param.dss.p);
	init_ssh_mpint(&key->param.dss.q);
	init_ssh_mpint(&key->param.dss.g);
	init_ssh_mpint(&key->param.dss.y);
	init_ssh_mpint(&key->param.dss.x);

	key->free_param=free_param_dss;

	if (key->secret==0) {

	    key->read_key=read_pkey_dss;
	    key->write_key=write_pkey_dss;
	    key->msg_write_key=msg_write_pkey_dss;
	    key->msg_read_key=msg_read_pkey_dss;

	} else {

	    key->read_key=read_skey_dss;
	    key->write_key=write_skey_dummy;
	    key->msg_write_key=msg_readwrite_key_dummy;
	    key->msg_read_key=msg_read_skey_dss;

	}

	key->verify=verify_sig_dss;
	key->sign=create_sig_dss;

	break;

    case SSH_PKALGO_SCHEME_ECC:

	init_ssh_mpoint(&key->param.ecc.q);
	init_ssh_mpint(&key->param.ecc.d);

	key->free_param=free_param_ecc;

	if (key->secret==0) {

	    key->read_key=read_pkey_ecc;
	    key->write_key=write_pkey_ecc;
	    key->msg_write_key=msg_write_pkey_ecc;
	    key->msg_read_key=msg_read_pkey_ecc;

	} else {

	    key->read_key=read_skey_ecc;
	    key->write_key=write_skey_dummy;
	    key->msg_write_key=msg_readwrite_key_dummy;
	    key->msg_read_key=msg_read_skey_ecc;

	}

	key->verify=verify_sig_ecc;
	key->sign=create_sig_ecc;

	break;

    };

}

void init_ssh_key(struct ssh_key_s *key, unsigned char secret, struct ssh_pkalgo_s *algo)
{

    memset(key, 0, sizeof(struct ssh_key_s));

    key->secret=(secret>0) ? 1 : 0;
    key->options.options=0;

    key->free_param=free_param_dummy;
    key->set_algo=set_algo_common;
    key->compare_keys=compare_ssh_keys;
    key->compare_key_data=compare_ssh_key_data;

    set_algo_common(key, algo);

}

void free_ssh_key(struct ssh_key_s *key)
{
    (* key->free_param)(key);
    memset(key, 0, sizeof(struct ssh_key_s));
    key->algo=NULL;
    key->free_param=free_param_dummy;
}

void msg_write_pkey(struct msg_buffer_s *mb, struct ssh_key_s *key, unsigned int format)
{
    if (key->secret==0) {

        (* key->msg_write_key)(mb, key, format);
	return;

    }

    mb->error=EINVAL;
}

void msg_read_pkey(struct msg_buffer_s *mb, struct ssh_key_s *key, unsigned int format)
{

    if (key->secret==0) {

	(* key->msg_read_key)(mb, key, format);
	return;

    }

    mb->error=EINVAL;

}

void msg_read_skey(struct msg_buffer_s *mb, struct ssh_key_s *key, unsigned int format)
{

    if (key->secret>0) {

	(* key->msg_read_key)(mb, key, format);
	return;

    }

    mb->error=EINVAL;

}
