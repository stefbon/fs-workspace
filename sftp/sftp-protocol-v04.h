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

#ifndef FS_WORKSPACE_SFTP_PROTOCOL_V04_H
#define FS_WORKSPACE_SFTP_PROTOCOL_V04_H

/*
    Definitions as described in:
    https://tools.ietf.org/html/draft-ietf-secsh-filexfer-04
*/

/* attributes valid */

#define SSH_FILEXFER_ATTR_SIZE 			0x00000001
#define SSH_FILEXFER_INDEX_SIZE			0
#define SSH_FILEXFER_ATTR_PERMISSIONS 		0x00000004
#define SSH_FILEXFER_INDEX_PERMISSIONS		2
#define SSH_FILEXFER_ATTR_ACCESSTIME 		0x00000008
#define SSH_FILEXFER_INDEX_ACCESSTIME		3
#define SSH_FILEXFER_ATTR_CREATETIME 		0x00000010
#define SSH_FILEXFER_INDEX_CREATETIME		4
#define SSH_FILEXFER_ATTR_MODIFYTIME 		0x00000020
#define SSH_FILEXFER_INDEX_MODIFYTIME		5
#define SSH_FILEXFER_ATTR_ACL 			0x00000040
#define SSH_FILEXFER_INDEX_ACL			6
#define SSH_FILEXFER_ATTR_OWNERGROUP 		0x00000080
#define SSH_FILEXFER_INDEX_OWNERGROUP		7
#define SSH_FILEXFER_ATTR_SUBSECOND_TIMES 	0x00000100
#define SSH_FILEXFER_INDEX_SUBSECOND_TIMES	8
#define SSH_FILEXFER_ATTR_EXTENDED	 	0x80000000
#define SSH_FILEXFER_INDEX_EXTENDED		31

#define SSH_FILEXFER_STAT_VALUE			( SSH_FILEXFER_ATTR_SIZE | SSH_FILEXFER_ATTR_PERMISSIONS | SSH_FILEXFER_ATTR_ACCESSTIME | SSH_FILEXFER_ATTR_MODIFYTIME | SSH_FILEXFER_ATTR_OWNERGROUP | SSH_FILEXFER_ATTR_SUBSECOND_TIMES )

/* error codes */

#define SSH_FX_OK 				0
#define SSH_FX_EOF 				1
#define SSH_FX_NO_SUCH_FILE 			2
#define SSH_FX_PERMISSION_DENIED 		3
#define SSH_FX_FAILURE 				4
#define SSH_FX_BAD_MESSAGE 			5
#define SSH_FX_NO_CONNECTION 			6
#define SSH_FX_CONNECTION_LOST 			7
#define SSH_FX_OP_UNSUPPORTED 			8
#define SSH_FX_INVALID_HANDLE 			9
#define SSH_FX_NO_SUCH_PATH 			10
#define SSH_FX_FILE_ALREADY_EXISTS 		11
#define SSH_FX_WRITE_PROTECT	 		12
#define SSH_FX_NO_MEDIA 			13

/* file types */

#define SSH_FILEXFER_TYPE_REGULAR		1
#define SSH_FILEXFER_TYPE_DIRECTORY		2
#define SSH_FILEXFER_TYPE_SYMLINK		3
#define SSH_FILEXFER_TYPE_SPECIAL		4
#define SSH_FILEXFER_TYPE_UNKNOWN		5

/* ace type */

#define ACE4_ACCESS_ALLOWED_ACE_TYPE 		0x00000000
#define ACE4_ACCESS_DENIED_ACE_TYPE  		0x00000001
#define ACE4_SYSTEM_AUDIT_ACE_TYPE   		0x00000002
#define ACE4_SYSTEM_ALARM_ACE_TYPE   		0x00000003

/* ace flag */

#define ACE4_FILE_INHERIT_ACE           	0x00000001
#define ACE4_DIRECTORY_INHERIT_ACE      	0x00000002
#define ACE4_NO_PROPAGATE_INHERIT_ACE   	0x00000004
#define ACE4_INHERIT_ONLY_ACE           	0x00000008
#define ACE4_SUCCESSFUL_ACCESS_ACE_FLAG 	0x00000010
#define ACE4_FAILED_ACCESS_ACE_FLAG     	0x00000020
#define ACE4_IDENTIFIER_GROUP           	0x00000040

/* ace mask */

#define ACE4_READ_DATA				0x00000001
#define ACE4_LIST_DIRECTORY			ACE4_READ_DATA
#define ACE4_WRITE_DATA				0x00000002
#define ACE4_ADD_FILE				ACE4_WRITE_DATA
#define ACE4_APPEND_DATA			0x00000004
#define ACE4_ADD_SUBDIRECTORY			ACE4_APPEND_DATA
#define ACE4_READ_NAMED_ATTRS			0x00000008
#define ACE4_WRITE_NAMED_ATTRS			0x00000010
#define ACE4_EXECUTE				0x00000020
#define ACE4_DELETE_CHILD			0x00000040
#define ACE4_READ_ATTRIBUTES			0x00000080
#define ACE4_WRITE_ATTRIBUTES			0x00000100
#define ACE4_DELETE				0x00010000
#define ACE4_READ_ACL				0x00020000
#define ACE4_WRITE_ACL				0x00040000
#define ACE4_WRITE_OWNER			0x00080000
#define ACE4_SYNCHRONIZE			0x00100000

/* open pflags */

#define SSH_FXF_READ     			0x00000001
#define SSH_FXF_WRITE       			0x00000002
#define SSH_FXF_APPEND      			0x00000004
#define SSH_FXF_CREAT   			0x00000008
#define SSH_FXF_TRUNC         			0x00000010
#define SSH_FXF_EXCL				0x00000020
#define SSH_FXF_TEXT               		0x00000040

#endif
