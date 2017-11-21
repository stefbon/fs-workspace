/*
  2010, 2011, 2012, 2013, 2014, 2015, 2016 Stef Bon <stefbon@gmail.com>

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

#ifndef FS_WORKSPACE_SSH_PUBKEY_UTILS_LIBGCRYPT_H
#define FS_WORKSPACE_SSH_PUBKEY_UTILS_LIBGCRYPT_H

struct _rsa_public_key_s {
    gcry_mpi_t 		e;
    gcry_mpi_t 		n;
};

struct _rsa_private_key_s {
    gcry_mpi_t 		n;
    gcry_mpi_t 		e;
    gcry_mpi_t 		d;
    gcry_mpi_t 		p;
    gcry_mpi_t 		q;
    gcry_mpi_t 		exp1;
    gcry_mpi_t 		exp2;
    gcry_mpi_t 		u;
};

struct _dss_public_key_s {
    gcry_mpi_t 		p;
    gcry_mpi_t 		q;
    gcry_mpi_t 		g;
    gcry_mpi_t 		y;
};

struct _dss_private_key_s {
    gcry_mpi_t 		p;
    gcry_mpi_t 		q;
    gcry_mpi_t 		g;
    gcry_mpi_t 		y;
    gcry_mpi_t 		x;
};

struct _ecc_public_key_s {
    gcry_mpi_t		q;
};

struct _ecc_private_key_s {
    gcry_mpi_t		q;
    gcry_mpi_t		d;
};

struct _generic_public_key_s {
    unsigned char			type;
    union _public_key {
	struct _rsa_public_key_s	rsa;
	struct _dss_public_key_s	dss;
	struct _ecc_public_key_s	ecc;
    } format;
};

struct _generic_private_key_s {
    unsigned char			type;
    union _private_key {
	struct _rsa_private_key_s	rsa;
	struct _dss_private_key_s	dss;
	struct _ecc_private_key_s	ecc;
    } format;
};

void _init_rsa_public_key(struct _rsa_public_key_s *rsa);
void free_rsa_public_key(struct ssh_key_s *key);
void _init_rsa_private_key(struct _rsa_private_key_s *rsa);
void _free_rsa_private_key(struct _rsa_private_key_s *rsa);
void free_rsa_private_key(struct ssh_key_s *key);

void _init_dss_public_key(struct _dss_public_key_s *dss);
void free_dss_public_key(struct ssh_key_s *key);
void _init_dss_private_key(struct _dss_private_key_s *dss);
void _free_dss_private_key(struct _dss_private_key_s *dss);
void free_dss_private_key(struct ssh_key_s *key);

void _init_ecc_public_key(struct _ecc_public_key_s *ecc);
void free_ecc_public_key(struct ssh_key_s *key);
void _init_ecc_private_key(struct _ecc_private_key_s *ecc);
void _free_ecc_private_key(struct _ecc_private_key_s *ecc);
void free_ecc_private_key(struct ssh_key_s *key);

#endif
