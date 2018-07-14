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

#ifndef FS_WORKSPACE_SSH_SEND_COMPRESS_H
#define FS_WORKSPACE_SSH_SEND_COMPRESS_H

void add_compress_ops(struct compress_ops_s *ops);
void reset_compress(struct ssh_send_s *send, struct algo_list_s *algo);
int build_compress_list_c2s(struct ssh_session_s *session, struct algo_list_s *alist, unsigned int start);

#endif
