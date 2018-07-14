/*
  2018 Stef Bon <stefbon@gmail.com>

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

#include "ssh-uint.h"

void store_uint32(char *buff, uint32_t value)
{
    unsigned char *tmp=(unsigned char *) buff;

    tmp[0] = (value >> 24) & 0xFF;
    tmp[1] = (value >> 16) & 0xFF;
    tmp[2] = (value >> 8) & 0xFF;
    tmp[3] = value & 0xFF;

}

void store_uint64(char *buff, uint64_t value)
{
    unsigned char *tmp=(unsigned char *) buff;

    tmp[0] = (value >> 56) & 0xFF;
    tmp[1] = (value >> 48) & 0xFF;
    tmp[2] = (value >> 40) & 0xFF;
    tmp[3] = (value >> 32) & 0xFF;
    tmp[4] = (value >> 24) & 0xFF;
    tmp[5] = (value >> 16) & 0xFF;
    tmp[6] = (value >> 8) & 0xFF;
    tmp[7] = value & 0xFF;

}

uint32_t get_uint32(char *buf)
{
    unsigned char *tmp=(unsigned char *) buf;
    return (uint32_t) (((uint32_t) tmp[0] << 24) | ((uint32_t) tmp[1] << 16) | ((uint32_t) tmp[2] << 8) | (uint32_t) tmp[3]);
}

uint16_t get_uint16(char *buf)
{
    unsigned char *tmp=(unsigned char *) buf;
    return (uint16_t) ((tmp[0] << 8) | tmp[1]);
}

uint64_t get_uint64(char *buf)
{
    unsigned char *tmp=(unsigned char *) buf;
    uint64_t a;
    uint32_t b;

    a = (uint64_t) (((uint64_t) tmp[0] << 56) | ((uint64_t) tmp[1] << 48) | ((uint64_t) tmp[2] << 40) | ((uint64_t) tmp[3] << 32));
    b = (uint32_t) (((uint32_t) tmp[4] << 24) | ((uint32_t) tmp[5] << 16) | ((uint32_t) tmp[6] << 8) | (uint32_t) tmp[7]);

    return (uint64_t)(a | b);
}

int64_t get_int64(char *buf)
{
    unsigned char *tmp=(unsigned char *) buf;
    uint64_t a;
    uint32_t b;

    a = (uint64_t) (((uint64_t) tmp[0] << 56) | ((uint64_t) tmp[1] << 48) | ((uint64_t) tmp[2] << 40) | ((uint64_t) tmp[3] << 32));
    b = (uint32_t) (((uint32_t) tmp[4] << 24) | ((uint32_t) tmp[5] << 16) | ((uint32_t) tmp[6] << 8) | ((uint32_t) tmp[7]));

    return (int64_t)(a | b);
}

