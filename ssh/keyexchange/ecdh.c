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
#include "keyx.h"

static struct keyex_ops_s ecdh_ops;

static unsigned int populate_keyex_ecdh(struct ssh_connection_s *c, struct keyex_ops_s *ops, struct algo_list_s *alist, unsigned int start)
{

    if (alist) {

	alist[start].type=SSH_ALGO_TYPE_KEX;
	alist[start].order=SSH_ALGO_ORDER_MEDIUM;
	alist[start].sshname="curve25519-sha256@libssh.org";
	alist[start].libname="curve25519-sha256@libssh.org";
	alist[start].ptr=(void *) ops;

    }

    start++;
    return start;

}

static int ecdh_create_client_key(struct ssh_keyex_s *k)
{
    struct ssh_ecdh_s *ecdh=&k->method.ecdh;
    struct ssh_pkalgo_s *pkalgo=NULL;

    /* create a secret key using curve25519 */

    pkalgo=get_pkalgo_byid(SSH_PKALGO_ID_CURVE25519, NULL);
    if (pkalgo==NULL) return -1;
    if (create_ssh_key(pkalgo, NULL, &ecdh->skey_c)==-1) return -1;
    return 0;
}

static void ecdh_msg_write_client_key(struct msg_buffer_s *mb, struct ssh_keyex_s *k)
{
    struct ssh_key_s *skey_c=&k->method.ecdh.skey_c;
    struct ssh_mpoint_s *q=&skey_c->param.ecc.q;
    msg_write_ssh_mpoint(mb, q);
}

static void ecdh_msg_read_server_key(struct msg_buffer_s *mb, struct ssh_keyex_s *k)
{
    struct ssh_key_s *pkey_s=&k->method.ecdh.pkey_s;
    struct ssh_pkalgo_s *pkalgo=NULL;
    struct ssh_mpoint_s *q=&pkey_s->param.ecc.q;

    pkalgo=get_pkalgo_byid(SSH_PKALGO_ID_CURVE25519, NULL);
    if (pkalgo==NULL) return;
    init_ssh_key(pkey_s, 1, pkalgo);
    msg_read_ssh_mpoint(mb, q, NULL);
}

static void ecdh_msg_write_server_key(struct msg_buffer_s *mb, struct ssh_keyex_s *k)
{
    struct ssh_key_s *pkey_s=&k->method.ecdh.pkey_s;
    struct ssh_mpoint_s *q=&pkey_s->param.ecc.q;
    msg_write_ssh_mpoint(mb, q);
}

void ReverseBuffer(char *buffer, unsigned int size)
{
    char tmp[size];

    memcpy(tmp, buffer, size);
    for (unsigned int i=0; i<size; i++) buffer[i] = tmp[size - i];

}

    /* HOW do scalar multiplication? see:
    https://git.libssh.org/projects/libssh.git/tree/doc/curve25519-sha256@libssh.org.txt */

    /* use gcry_pk_encrypt like:

	gcry_error_t gcry_pk_encrypt(gcry_sexp_t *r_ciph, gcry_sexp_t data, gcry_sexp_t pkey)
	where gcry_sexp_t data is the private key like:
	gcry_sexp_t data=NULL;
	gcry_error_t gcry_sexp_build(&data, NULL, "%b", length secret key, secret key reversed)
	where secret key is the d of the local curve25519

	and gcry_sexp_build(&pkey, NULL, "(public key (ecc (curve Curve25519 (flags djb-tweak) (q%m))))" using remote public key->d


	the result in r_ciph is the shared key and compressed (?)
	extract the "s" value:

	gcry_mpi_t mpi_comp=NULL;
	gcry_sexp_extract_param(r_ciph, NULL, "s", &mpi_comp, NULL);

	gcry_mpi_t k=CurveDecompress(mpi_comp);

	gcry_mpi_aprint(GCRYMPI_FMT_USG, **buffer, *size, k);

	reversebuffer(*buffer, size)

	result is on buffer with size
	and see:
	https://code.videolan.org/GSoC2018/arlyon/vlc/blob/airplay-auth/modules/stream_out/airplay/airplay.c#L911


    */

#if HAVE_LIBGCRYPT

#include <gcrypt.h>

static gcry_mpi_t CurveDecompress(gcry_mpi_t mpi_sharedkey_comp)
{
    gcry_mpi_t mpi_sharedkey=NULL;
    gcry_ctx_t ctx;
    gcry_mpi_point_t mpoint_sharedkey=gcry_mpi_point_new(0);
    gcry_mpi_t mpi_sharedkey_x=gcry_mpi_new(0);

    gcry_mpi_ec_new(&ctx, NULL, "Curve25519");
    gcry_mpi_ec_decode_point(mpoint_sharedkey, mpi_sharedkey_comp, ctx);

    gcry_mpi_point_snatch_get(mpi_sharedkey_x, NULL, NULL, mpoint_sharedkey);

    gcry_ctx_release(ctx);

    return mpi_sharedkey_x;
}

static int ecdh_calc_sharedkey(struct ssh_keyex_s *k)
{
    struct ssh_ecdh_s *ecdh=&k->method.ecdh;
    gcry_sexp_t sexp_pk=NULL;
    gcry_sexp_t sexp_sk=NULL;
    gcry_sexp_t sexp_sharedkey=NULL;
    gcry_error_t err = 0;
    struct ssh_key_s *pkey_s=&ecdh->pkey_s;
    struct ssh_mpoint_s *q=&pkey_s->param.ecc.q;
    struct ssh_key_s *skey_c=&ecdh->skey_c;
    struct ssh_mpint_s *d=&skey_c->param.ecc.d;
    unsigned int len=0;
    void *ptr=gcry_mpi_get_opaque(q->lib.mpi, &len);
    unsigned int size=gcry_mpi_get_nbits(d->lib.mpi);
    char buffer[size/8];
    size_t written=0;
    gcry_mpi_t mpi_sharedkey_comp=NULL;
    gcry_mpi_t mpi_sharedkey=NULL;
    int result=-1;

    size=size/8;

    /* build data sexp from the private key (d) of the local key*/

    gcry_mpi_print(GCRYMPI_FMT_USG, (unsigned char *)buffer, size, &written, d->lib.mpi);
    ReverseBuffer(buffer, size);

    err=gcry_sexp_build(&sexp_sk, NULL, "%b", size, buffer);

    if (err) {

	logoutput("ecdh_calc_sharedkey: error creating sk s-exp (%s/%s)", gcry_strsource(err), gcry_strerror(err));
	goto out;

    }

    err=gcry_sexp_build(&sexp_pk, NULL, "(public-key (ecc (curve Curve25519) (flags djb-tweak) (q %b)))", len/8, ptr);

    if (err) {

	logoutput("ecdh_calc_sharedkey: error creating pk s-exp (%s/%s)", gcry_strsource(err), gcry_strerror(err));
	goto out;

    }

    err=gcry_pk_encrypt(&sexp_sharedkey, sexp_sk, sexp_pk);

    if (err) {

	logoutput("ecdh_calc_sharedkey: error encrypting shared K (%s/%s)", gcry_strsource(err), gcry_strerror(err));
	goto out;

    }

    /* get the s value */

    gcry_sexp_extract_param( sexp_sharedkey, NULL, "s", &mpi_sharedkey_comp, NULL);

    if (mpi_sharedkey_comp) {

	ecdh->sharedkey.lib.mpi=CurveDecompress(mpi_sharedkey_comp);
	result=0;

    }

    out:

    if (mpi_sharedkey_comp) gcry_mpi_release(mpi_sharedkey_comp);
    if (sexp_sharedkey) gcry_sexp_release(sexp_sharedkey);
    if (sexp_sk) gcry_sexp_release(sexp_sk);
    if (sexp_pk) gcry_sexp_release(sexp_pk);

    return result;

}

#else

static int ecdh_calc_sharedkey(struct ssh_keyex_s *k)
{
    return -1;
}

#endif

#if HAVE_LIBGCRYPT

#include <gcrypt.h>

static void ecdh_msg_write_sharedkey(struct msg_buffer_s *mb, struct ssh_keyex_s *k)
{
    struct ssh_mpint_s *mp=&k->method.ecdh.sharedkey;
    unsigned int size=gcry_mpi_get_nbits(mp->lib.mpi);
    unsigned char buffer[size/8];
    size_t written=0;

    size=size/8;

    gcry_mpi_print(GCRYMPI_FMT_USG, buffer, size, &written, mp->lib.mpi);
    ReverseBuffer((char *)buffer, size);

    msg_write_bytes(mb, buffer, size);
}

#else

static void ecdh_msg_write_sharedkey(struct msg_buffer_s *mb, struct ssh_keyex_s *k)
{
}

#endif

static void ecdh_free_keyex(struct ssh_keyex_s *k)
{
    struct ssh_ecdh_s *ecdh=&k->method.ecdh;

    free_ssh_key(&ecdh->skey_c);
    free_ssh_key(&ecdh->pkey_s);
    free_ssh_mpint(&ecdh->sharedkey);

}

static int ecdh_init_keyex(struct ssh_keyex_s *k, char *name)
{
    struct ssh_ecdh_s *ecdh=&k->method.ecdh;
    struct ssh_pkalgo_s *pkalgo=NULL;

    if (strcmp(name, "curve25519-sha256@libssh.org")==0) {

	pkalgo=get_pkalgo_byid(SSH_PKALGO_ID_CURVE25519, NULL);
	if (pkalgo==NULL) return -1; /* huh? */

    } else {

	logoutput("ecdh_init_keyex: %s not supported", name);
	return -1;

    }

    init_ssh_key(&ecdh->pkey_s, 0, pkalgo);
    init_ssh_key(&ecdh->skey_c, 1, pkalgo);
    init_ssh_mpint(&ecdh->sharedkey);
    return 0;

}

static struct keyex_ops_s ecdh_ops = {
    .name				=	"ecdh",
    .populate				=	populate_keyex_ecdh,
    .init				=	ecdh_init_keyex,
    .create_client_key			=	ecdh_create_client_key,
    .msg_write_client_key		=	ecdh_msg_write_client_key,
    .msg_read_server_key		=	ecdh_msg_read_server_key,
    .msg_write_server_key		=	ecdh_msg_write_server_key,
    .calc_sharedkey			=	ecdh_calc_sharedkey,
    .msg_write_sharedkey		=	ecdh_msg_write_sharedkey,
    .free				=	ecdh_free_keyex,
};

void init_keyex_ecdh()
{
    add_keyex_ops(&ecdh_ops);
}
