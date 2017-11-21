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
#include <gcrypt.h>

#include "logging.h"
#include "main.h"

#include "utils.h"
#include "ctx-keystore.h"
#include "ssh-common.h"
#include "ssh-utils.h"
#include "ssh-pubkey-utils.h"
#include "ssh-pubkey-utils-libgcrypt.h"

static void free_mpi_helper(struct gcry_mpi **x)
{
    if (*x) {
	gcry_mpi_release(*x);
	*x=NULL;
    }
}

static void _free_rsa_public_key(struct _rsa_public_key_s *rsa)
{
    free_mpi_helper(&rsa->e);
    free_mpi_helper(&rsa->n);
}

void _init_rsa_public_key(struct _rsa_public_key_s *rsa)
{
    rsa->e=NULL;
    rsa->n=NULL;
}

void free_rsa_public_key(struct ssh_key_s *key)
{
    struct _rsa_public_key_s *rsa=(struct _rsa_public_key_s *) key->ptr;

    if (rsa) {

	_free_rsa_public_key(rsa);
	free(rsa);
	key->ptr=NULL;

    }
}


void _free_rsa_private_key(struct _rsa_private_key_s *rsa)
{
    free_mpi_helper(&rsa->e);
    free_mpi_helper(&rsa->n);
    free_mpi_helper(&rsa->d);
    free_mpi_helper(&rsa->p);
    free_mpi_helper(&rsa->q);
    free_mpi_helper(&rsa->exp1);
    free_mpi_helper(&rsa->exp2);
    free_mpi_helper(&rsa->u);

}

void _init_rsa_private_key(struct _rsa_private_key_s *rsa)
{
    rsa->e=NULL;
    rsa->n=NULL;
    rsa->d=NULL;
    rsa->p=NULL;
    rsa->q=NULL;
    rsa->exp1=NULL;
    rsa->exp2=NULL;
    rsa->u=NULL;

}

void free_rsa_private_key(struct ssh_key_s *key)
{
    struct _rsa_private_key_s *rsa=(struct _rsa_private_key_s *) key->ptr;

    if (rsa) {

	_free_rsa_private_key(rsa);
	free(rsa);
	key->ptr=NULL;

    }
}

void _free_dss_public_key(struct _dss_public_key_s *dss)
{
    free_mpi_helper(&dss->p);
    free_mpi_helper(&dss->q);
    free_mpi_helper(&dss->g);
    free_mpi_helper(&dss->y);
}

void _init_dss_public_key(struct _dss_public_key_s *dss)
{
    dss->p=NULL;
    dss->q=NULL;
    dss->g=NULL;
    dss->y=NULL;
}

void free_dss_public_key(struct ssh_key_s *key)
{
    struct _dss_public_key_s *dss=(struct _dss_public_key_s *) key->ptr;

    if (dss) {

	_free_dss_public_key(dss);
	free(dss);
	key->ptr=NULL;

    }
}

void _free_dss_private_key(struct _dss_private_key_s *dss)
{
    free_mpi_helper(&dss->p);
    free_mpi_helper(&dss->q);
    free_mpi_helper(&dss->g);
    free_mpi_helper(&dss->y);
    free_mpi_helper(&dss->x);
}

void _init_dss_private_key(struct _dss_private_key_s *dss)
{
    dss->p=NULL;
    dss->q=NULL;
    dss->g=NULL;
    dss->y=NULL;
    dss->x=NULL;
}

void free_dss_private_key(struct ssh_key_s *key)
{
    struct _dss_private_key_s *dss=(struct _dss_private_key_s *) key->ptr;

    if (dss) {

	_free_dss_private_key(dss);
	free(dss);
	key->ptr=NULL;

    }
}

void _free_ecc_public_key(struct _ecc_public_key_s *ecc)
{
    free_mpi_helper(&ecc->q);
}

void _init_ecc_public_key(struct _ecc_public_key_s *ecc)
{
    ecc->q=NULL;
}

void free_ecc_public_key(struct ssh_key_s *key)
{
    struct _ecc_public_key_s *ecc=(struct _ecc_public_key_s *) key->ptr;

    if (ecc) {

	_free_ecc_public_key(ecc);
	free(ecc);
	key->ptr=NULL;

    }
}

void _free_ecc_private_key(struct _ecc_private_key_s *ecc)
{
    free_mpi_helper(&ecc->q);
    free_mpi_helper(&ecc->d);
}

void _init_ecc_private_key(struct _ecc_private_key_s *ecc)
{
    ecc->q=NULL;
    ecc->d=NULL;
}

void free_ecc_private_key(struct ssh_key_s *key)
{
    struct _ecc_private_key_s *ecc=(struct _ecc_private_key_s *) key->ptr;

    if (ecc) {

	_free_ecc_private_key(ecc);
	free(ecc);
	key->ptr=NULL;

    }

}
