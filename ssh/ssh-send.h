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

#ifndef FS_WORKSPACE_SSH_SEND_H
#define FS_WORKSPACE_SSH_SEND_H

#include "send/compress.h"
#include "send/compress-none.h"
#include "send/compressors.h"
#include "send/encrypt-chacha20-poly1305.h"
#include "send/encrypt-generic.h"
#include "send/encrypt.h"
#include "send/encryptors.h"
#include "send/greeter.h"
#include "send/init.h"
#include "send/msg-channel.h"
#include "send/msg-transport.h"
#include "send/msg-userauth.h"
#include "send/send.h"
#include "send/write-socket.h"

#endif
