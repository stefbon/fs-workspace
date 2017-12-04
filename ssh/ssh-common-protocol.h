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

#ifndef FS_WORKSPACE_SSH_COMMON_PROTOCOL_H
#define FS_WORKSPACE_SSH_COMMON_PROTOCOL_H

#define SSH_CHANNEL_WINDOW_DEFAULT 				(2*1024*1024)
#define SSH_CHANNEL_PACKET_DEFAULT				32768

/* SSH Packet Types -- Defined by internet draft */

#define SSH_MSG_DISCONNECT                          		1
#define SSH_MSG_IGNORE                              		2
#define SSH_MSG_UNIMPLEMENTED                       		3
#define SSH_MSG_DEBUG                               		4
#define SSH_MSG_SERVICE_REQUEST                     		5
#define SSH_MSG_SERVICE_ACCEPT                      		6

#define SSH_MSG_KEXINIT                             		20
#define SSH_MSG_NEWKEYS                             		21

/* diffie-hellman-group1-sha1 */
#define SSH_MSG_KEXDH_INIT                          		30
#define SSH_MSG_KEXDH_REPLY                         		31

/* diffie-hellman-group-exchange-sha1 and diffie-hellman-group-exchange-sha256 */
#define SSH_MSG_KEX_DH_GEX_REQUEST_OLD              		30
#define SSH_MSG_KEX_DH_GEX_REQUEST                  		34
#define SSH_MSG_KEX_DH_GEX_GROUP                    		31
#define SSH_MSG_KEX_DH_GEX_INIT                     		32
#define SSH_MSG_KEX_DH_GEX_REPLY                    		33

/* User Authentication */
#define SSH_MSG_USERAUTH_REQUEST                    		50
#define SSH_MSG_USERAUTH_FAILURE                    		51
#define SSH_MSG_USERAUTH_SUCCESS                    		52
#define SSH_MSG_USERAUTH_BANNER                     		53

#define SSH_MSG_USERAUTH_PK_OK                      		60
#define SSH_MSG_USERAUTH_PASSWD_CHANGEREQ           		60
#define SSH_MSG_USERAUTH_INFO_REQUEST               		60
#define SSH_MSG_USERAUTH_INFO_RESPONSE              		61

/* Channels */
#define SSH_MSG_GLOBAL_REQUEST                      		80
#define SSH_MSG_REQUEST_SUCCESS                     		81
#define SSH_MSG_REQUEST_FAILURE                     		82

#define SSH_MSG_CHANNEL_OPEN                        		90
#define SSH_MSG_CHANNEL_OPEN_CONFIRMATION           		91
#define SSH_MSG_CHANNEL_OPEN_FAILURE                		92
#define SSH_MSG_CHANNEL_WINDOW_ADJUST               		93
#define SSH_MSG_CHANNEL_DATA                        		94
#define SSH_MSG_CHANNEL_EXTENDED_DATA               		95
#define SSH_MSG_CHANNEL_EOF                         		96
#define SSH_MSG_CHANNEL_CLOSE                       		97
#define SSH_MSG_CHANNEL_REQUEST                     		98
#define SSH_MSG_CHANNEL_SUCCESS                     		99
#define SSH_MSG_CHANNEL_FAILURE                     		100

#define _SSH_MSG_MAX						100

#define SSH_EXTENDED_DATA_STDERR		    		1

/* Error codes returned in SSH_MSG_CHANNEL_OPEN_FAILURE message
   (see RFC4254) */
#define SSH_OPEN_ADMINISTRATIVELY_PROHIBITED 			1
#define SSH_OPEN_CONNECT_FAILED              			2
#define SSH_OPEN_UNKNOWN_CHANNELTYPE         			3
#define SSH_OPEN_RESOURCE_SHORTAGE           			4

#define SSH_DISCONNECT_HOST_NOT_ALLOWED_TO_CONNECT             	1
#define SSH_DISCONNECT_PROTOCOL_ERROR                          	2
#define SSH_DISCONNECT_KEY_EXCHANGE_FAILED                     	3
#define SSH_DISCONNECT_RESERVED                                	4
#define SSH_DISCONNECT_MAC_ERROR                               	5
#define SSH_DISCONNECT_COMPRESSION_ERROR                       	6
#define SSH_DISCONNECT_SERVICE_NOT_AVAILABLE                   	7
#define SSH_DISCONNECT_PROTOCOL_VERSION_NOT_SUPPORTED          	8
#define SSH_DISCONNECT_HOST_KEY_NOT_VERIFIABLE                 	9
#define SSH_DISCONNECT_CONNECTION_LOST                        	10
#define SSH_DISCONNECT_BY_APPLICATION                         	11
#define SSH_DISCONNECT_TOO_MANY_CONNECTIONS                   	12
#define SSH_DISCONNECT_AUTH_CANCELLED_BY_USER                 	13
#define SSH_DISCONNECT_NO_MORE_AUTH_METHODS_AVAILABLE         	14
#define SSH_DISCONNECT_ILLEGAL_USER_NAME                      	15

/* prototypes */

unsigned int write_disconnect_reason(unsigned int reason, char *pos, unsigned int size, unsigned int *error);

#endif
