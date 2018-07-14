/*
  2017, 2018 Stef Bon <stefbon@gmail.com>

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

#ifndef FS_WORKSPACE_SSH_RECEIVE_H
#define FS_WORKSPACE_SSH_RECEIVE_H

#include "receive/decompress.h"
#include "receive/decompress-none.h"
#include "receive/decompressors.h"
#include "receive/decrypt-chacha20-poly1305.h"
#include "receive/decrypt-generic.h"
#include "receive/decrypt.h"
#include "receive/decryptors.h"
#include "receive/greeter.h"
#include "receive/init.h"
#include "receive/msg-channel.h"
#include "receive/msg-transport.h"
#include "receive/msg-userauth.h"
#include "receive/payload.h"
#include "receive/read-buffer.h"
#include "receive/read-socket.h"

#endif
