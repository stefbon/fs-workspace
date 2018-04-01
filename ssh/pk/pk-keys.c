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
    not needed anyway
    private/secret keys are required to sign and nothing else */

static int write_skey_dummy(struct ssh_key_s *key, char *b, unsigned int s, unsigned int f, unsigned int *e)
{
    *e=EOPNOTSUPP;
    return -1;
}

static void free_param_rsa(struct ssh_key_s *key)
{
    free_pk_mpint(&key->param.rsa.n);
    free_pk_mpint(&key->param.rsa.e);
    free_pk_mpint(&key->param.rsa.d);
    free_pk_mpint(&key->param.rsa.p);
    free_pk_mpint(&key->param.rsa.q);
    free_pk_mpint(&key->param.rsa.u);
}

static void free_param_dss(struct ssh_key_s *key)
{
    free_pk_mpint(&key->param.dss.p);
    free_pk_mpint(&key->param.dss.q);
    free_pk_mpint(&key->param.dss.g);
    free_pk_mpint(&key->param.dss.y);
    free_pk_mpint(&key->param.dss.x);
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

    switch (algo->id) {

    case SSH_PKALGO_ID_RSA:

	init_pk_mpint(&key->param.rsa.n);
	init_pk_mpint(&key->param.rsa.e);
	init_pk_mpint(&key->param.rsa.d);
	init_pk_mpint(&key->param.rsa.p);
	init_pk_mpint(&key->param.rsa.q);
	init_pk_mpint(&key->param.rsa.u);

	key->free_param=free_param_rsa;

	if (key->secret==0) {

	    key->read_key=read_pkey_rsa;
	    key->write_key=write_pkey_rsa;

	} else {

	    key->read_key=read_skey_rsa;
	    key->write_key=write_skey_dummy;

	}

	key->verify=verify_sig_rsa;
	key->sign=create_sig_rsa;

	break;

    case SSH_PKALGO_ID_DSS:

	init_pk_mpint(&key->param.dss.p);
	init_pk_mpint(&key->param.dss.q);
	init_pk_mpint(&key->param.dss.g);
	init_pk_mpint(&key->param.dss.y);
	init_pk_mpint(&key->param.dss.x);

	key->free_param=free_param_dss;

	if (key->secret==0) {

	    key->read_key=read_pkey_dss;
	    key->write_key=write_pkey_dss;

	} else {

	    key->read_key=read_skey_dss;
	    key->write_key=write_skey_dummy;

	}

	key->verify=verify_sig_dss;
	key->sign=create_sig_dss;

	break;

    };

}

void init_ssh_key(struct ssh_key_s *key, unsigned char secret, struct ssh_pkalgo_s *algo)
{

    memset(key, 0, sizeof(struct ssh_key_s));

    key->secret=(secret>0) ? 1 : 0;

    key->free_param=free_param_dummy;
    key->set_algo=set_algo_common;
    key->compare_keys=compare_ssh_keys;
    key->compare_key_data=compare_ssh_key_data;

    set_algo_common(key, algo);

}

void free_ssh_key(struct ssh_key_s *key)
{
    free_common_buffer(&key->data);
    (* key->free_param)(key);
    memset(key, 0, sizeof(struct ssh_key_s));
    key->algo=NULL;
    key->free_param=free_param_dummy;
}
