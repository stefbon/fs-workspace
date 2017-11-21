/*
  2010, 2011, 2012, 2013, 2014, 2015, 2016, 2017 Stef Bon <stefbon@gmail.com>

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

#ifndef FS_WORKSPACE_SSH_COMMON_H
#define FS_WORKSPACE_SSH_COMMON_H

#include <sys/socket.h>
#include <sys/un.h>
#include <arpa/inet.h>

#include "workspace-interface.h"
#include "ctx-keystore.h"
#include "simple-list.h"

#define _PUBKEY_METHOD_NONE		0
#define _PUBKEY_METHOD_PRIVATE		1
#define _PUBKEY_METHOD_SSH_DSS		2
#define _PUBKEY_METHOD_SSH_RSA		4
#define _PUBKEY_METHOD_SSH_ED25519	8

#define _PUBKEY_FORMAT_NONE		0
#define _PUBKEY_FORMAT_OPENSSH_KEY	1
#define _PUBKEY_FORMAT_SSH		2
#define _PUBKEY_FORMAT_DER		3

struct ssh_string_s {
    unsigned int			len;
    unsigned char			*ptr;
};

struct commalist_s {
    unsigned char *list;
    unsigned int len;
    unsigned int size;
};

#define _LIBRARY_NONE			0
#define _LIBRARY_ZLIB			1
#define _LIBRARY_OPENSSL		2
#define _LIBRARY_LIBGCRYPT		3

struct library_s {
    unsigned char 			type;
    void				*ptr;
};

struct ssh_payload_s {
    unsigned char			type;
    unsigned int			sequence;
    unsigned int			len;
    struct ssh_payload_s		*next;
    struct ssh_payload_s		*prev;
    unsigned char			buffer[];
};

struct ssh_packet_s {
    unsigned int 			len;
    unsigned char			padding;
    unsigned int 			error;
    unsigned int			sequence;
    unsigned char 			*buffer;
};

struct rawdata_s {
    struct ssh_session_s		*session;
    struct rawdata_s			*next;
    unsigned int			size;
    unsigned int 			len;
    unsigned int			maclen;
    unsigned int			decrypted;
    unsigned int			sequence;
    unsigned char 			buffer[];
};

struct ssh_init_algo {
    char				keyexchange[64];
    char				hostkey[32];
    char				encryption_c2s[64];
    char				encryption_s2c[64];
    char				hmac_c2s[64];
    char				hmac_s2c[64];
    char				compression_c2s[32];
    char				compression_s2c[32];
};

#define _SSH_SERVICE_USERAUTH		1
#define _SSH_SERVICE_CONNECTION		2

#define SERVER_REPLY_TYPE_PK		1
#define SERVER_REPLY_TYPE_SERVICE	2
#define SERVER_REPLY_TYPE_PAYLOAD	3

struct server_reply_s {
    unsigned char 			reply;
    unsigned int			sequence;
    unsigned int			error;
    union {
	struct common_buffer_s		data;
	unsigned int			code;
    } response;
};

#define SESSION_STATUS_INIT				0
#define SESSION_STATUS_KEXINIT				1
#define SESSION_STATUS_KEYEXCHANGE			2
#define SESSION_STATUS_NEWKEYS				3
#define SESSION_STATUS_SWITCH				4
#define SESSION_STATUS_HOSTINFO				5
#define SESSION_STATUS_USERAUTH				6
#define SESSION_STATUS_USERAUTH_NONE			7
#define SESSION_STATUS_USERAUTH_PK			8
#define SESSION_STATUS_DISCONNECT			99
#define SESSION_STATUS_COMPLETE				100

#define SUBSTATUS_KEXINIT_STARTED			1
#define SUBSTATUS_KEXINIT_SEND				2
#define SUBSTATUS_KEXINIT_RECEIVED			4
#define SUBSTATUS_KEXINIT_ERROR				8

#define SUBSTATUS_KEYEXCHANGE_STARTED			1
#define SUBSTATUS_KEYEXCHANGE_FINISHED			2
#define SUBSTATUS_KEYEXCHANGE_ERROR			4

#define SUBSTATUS_NEWKEYS_SEND				1
#define SUBSTATUS_NEWKEYS_RECEIVED			2
#define SUBSTATUS_NEWKEYS_ERROR				4

#define SUBSTATUS_USERAUTH_STARTED			1
#define SUBSTATUS_USERAUTH_SEND				2
#define SUBSTATUS_USERAUTH_RECEIVED			4
#define SUBSTATUS_USERAUTH_OK				8
#define SUBSTATUS_USERAUTH_FAILURE			16
#define SUBSTATUS_USERAUTH_ERROR			32

#define SUBSTATUS_COMPLETE_OK				1
#define SUBSTATUS_COMPLETE_COMMAND			2
#define SUBSTATUS_COMPLETE_ERROR			8

#define CHANNEL_STATUS_INIT				1
#define CHANNEL_STATUS_UP				2
#define CHANNEL_STATUS_DOWN				3

#define CHANNEL_SUBSTATUS_OPEN				1
#define CHANNEL_SUBSTATUS_C_CLOSE			2
#define CHANNEL_SUBSTATUS_S_CLOSE			4
#define CHANNEL_SUBSTATUS_C_EOF				8
#define CHANNEL_SUBSTATUS_S_EOF				16

#define SFTP_STATUS_INIT				1
#define SFTP_STATUS_FULL				2

#define TABLE_LOCK_OPENCHANNEL				1
#define TABLE_LOCK_CLOSECHANNEL				2
#define TABLE_LOCK_LOCKED				( TABLE_LOCK_OPENCHANNEL | TABLE_LOCK_CLOSECHANNEL )

#define CHANNELS_TABLE_SIZE				8

#define SSH_USERAUTH_NONE				1
#define SSH_USERAUTH_PUBLICKEY				2
#define SSH_USERAUTH_PASSWORD				4
#define SSH_USERAUTH_HOSTBASED				8
#define SSH_USERAUTH_SUCCESS				16

struct ssh_status_s {
    uint64_t				unique;
    unsigned int 			remote_version_major;
    unsigned int 			remote_version_minor;
    unsigned int			status;
    unsigned int			substatus;
    pthread_mutex_t			mutex;
    pthread_cond_t			cond;
    unsigned int 			error;
    unsigned int			max_packet_size;
};

struct list_head_s {
    struct list_element_s		*head;
    struct list_element_s		*tail;
};

struct channel_table_s {
    unsigned int			latest_channel;
    unsigned int 			count;
    unsigned int			table_size;
    struct ssh_channel_s		*admin;
    struct ssh_channel_s		*sftp;
    struct list_head_s			hash[CHANNELS_TABLE_SIZE];
    pthread_mutex_t			mutex;
    pthread_cond_t			cond;
    unsigned int			lock;
};

struct ssh_signal_s {
    unsigned char			signal_allocated;
    pthread_mutex_t			*mutex;
    pthread_cond_t			*cond;
    unsigned int			sequence_number_error;
    unsigned int			error;
};

#define _CHANNEL_TYPE_ADMIN					1
#define _CHANNEL_TYPE_SFTP_SUBSYSTEM				2
#define _CHANNEL_TYPE_DIRECT_STREAMLOCAL			3
#define _CHANNEL_TYPE_DIRECT_TCPIP				4

#define _CHANNEL_TARGET_PROTOCOL_BFILESERVER			1

struct ssh_channel_s {
    struct ssh_session_s 		*session;
    unsigned char			type;
    unsigned int 			local_channel;
    unsigned int			remote_channel;
    unsigned int			status;
    unsigned int			substatus;
    unsigned int			max_packet_size;
    unsigned int			actors;
    uint64_t				local_window;
    struct ssh_signal_s			*signal;
    struct ssh_payload_s 		*first;
    struct ssh_payload_s 		*last;
    pthread_mutex_t			mutex;
    void				(* free)(struct ssh_channel_s *c);
    struct list_element_s		list;
    void				(* receive_msg_channel_data)(struct ssh_channel_s *channel, struct ssh_payload_s *payload);
    int 				(* send_data_message)(struct ssh_channel_s *channel, unsigned int len, unsigned char *data, unsigned int *seq);
    union {
	struct serversocket_s {
	    char			*path;
	    unsigned int		protocol;
	} socket;
	struct tcpip_s {
	    char			*host;
	    unsigned int		port;
	    unsigned int		protocol;
	} tcpip;
    } target;
};

struct ssh_key_s {
    unsigned int			type;
    unsigned int			format;
    struct common_buffer_s		data;
    void				*ptr;
    void				(* free_ptr)(struct ssh_key_s *key);
};

struct ssh_pubkey_s {
    int 				(* read_parameters)(struct ssh_key_s *key, unsigned int *error);
    int					(* verify_sigH)(struct ssh_key_s *key, struct common_buffer_s *data, struct common_buffer_s *sigH, const char *hashname);
    int 				(* create_signature)(struct ssh_key_s *key, struct common_buffer_s *data, struct ssh_string_s *signature, const char *hashname, unsigned int *error);
    struct ssh_key_s			server_hostkey;
};

#define _COMPRESSION_LIBRARY_NONE	0
#define _COMPRESSION_LIBRARY_ZLIB	1

struct ssh_compression_s {
    struct library_s			library_c2s;
    struct library_s			library_s2c;
    unsigned int			inflatebound;
    int					(*set_deflate)(struct ssh_compression_s *compression, const char *name, unsigned int *error);
    int					(*set_inflate)(struct ssh_compression_s *compression, const char *name, unsigned int *error);
    struct ssh_payload_s 		*(*inflate)(struct ssh_compression_s *compression, struct ssh_payload_s *payload);
    int					(*deflate)(struct ssh_compression_s *compression, struct ssh_payload_s *payload);
    void				(*close_deflate)(struct ssh_compression_s *compression);
    void				(*close_inflate)(struct ssh_compression_s *compression);
};

struct ssh_encryption_s {
    struct library_s			library_c2s;
    struct library_s			library_s2c;
    int					(*set_encrypt)(struct ssh_encryption_s *encryption, const char *name, unsigned int *error);
    int					(*set_decrypt)(struct ssh_encryption_s *encryption, const char *name, unsigned int *error);
    int 				(*decrypt_length)(struct rawdata_s *data, unsigned char *buffer, unsigned int len);
    int 				(*decrypt_packet)(struct rawdata_s *data);
    int 				(*encrypt)(struct ssh_encryption_s *encryption, struct ssh_packet_s *packet);
    void				(*reset_decrypt)(struct ssh_encryption_s *encryption);
    void				(*reset_encrypt)(struct ssh_encryption_s *encryption);
    void				(*close_decrypt)(struct ssh_encryption_s *encryption);
    void				(*close_encrypt)(struct ssh_encryption_s *encryption);
    void				(*free_decrypt)(struct ssh_encryption_s *encryption);
    void				(*free_encrypt)(struct ssh_encryption_s *encryption);
    unsigned int 			(*get_cipher_keysize)(const char *name);
    unsigned int 			(*get_cipher_blocksize)(const char *name);
    unsigned int 			(*get_cipher_ivsize)(const char *name);
    unsigned int			blocksize_c2s;
    unsigned int			blocksize_s2c;
    int					(*setkey_c2s)(struct ssh_string_s *old, char *name, struct ssh_string_s *key);
    int					(*setkey_s2c)(struct ssh_string_s *old, char *name, struct ssh_string_s *key);
    int					(*setiv_c2s)(struct ssh_string_s *old, char *name, struct ssh_string_s *key);
    int					(*setiv_s2c)(struct ssh_string_s *old, char *name, struct ssh_string_s *key);
    struct ssh_string_s 		key_s2c;
    struct ssh_string_s 		key_c2s;
    struct ssh_string_s 		*iv_s2c;
    struct ssh_string_s 		*iv_c2s;
    unsigned char			(*get_message_padding)(unsigned int len, unsigned int blocksize);
    unsigned int			size_firstbytes;
};

struct ssh_hmac_s {
    struct library_s			library_c2s;
    struct library_s			library_s2c;
    int					(*set_mac_s2c)(struct ssh_hmac_s *hmac, const char *name, unsigned int *error);
    int 				(*verify_mac_pre)(struct rawdata_s *data);
    int 				(*verify_mac_post)(struct rawdata_s *data);
    void				(*reset_s2c)(struct ssh_hmac_s *hmac);
    void				(*free_s2c)(struct ssh_hmac_s *hmac);
    int					(*set_mac_c2s)(struct ssh_hmac_s *hmac, const char *name, unsigned int *error);
    void				(*reset_c2s)(struct ssh_hmac_s *hmac);
    void 				(*write_mac_pre)(struct ssh_hmac_s *hmac, struct ssh_packet_s *packet);
    void 				(*write_mac_post)(struct ssh_hmac_s *hmac, struct ssh_packet_s *packet);
    ssize_t				(*send_c2s)(struct ssh_session_s *session, struct ssh_packet_s *packet);
    void				(*free_c2s)(struct ssh_hmac_s *hmac);
    unsigned int 			(*get_mac_keylen)(char *name);
    int					(*setkey_c2s)(struct ssh_string_s *old, char *name, struct ssh_string_s *key);
    int					(*setkey_s2c)(struct ssh_string_s *old, char *name, struct ssh_string_s *key);
    struct ssh_string_s 		key_s2c;
    struct ssh_string_s 		key_c2s;
    unsigned int 			maclen_c2s;
    unsigned int 			maclen_s2c;
};

/*
    struct for key exchange
    for now (201608) only dh (static simple diffie-hellman) is supported
*/

#define _DH_STATUS_INIT			1
#define _DH_STATUS_MINMAXSEND		2
#define _DH_STATUS_GOTP			3
#define _DH_STATUS_ESEND		4
#define _DH_STATUS_FRECEIVED		5
#define _DH_STATUS_COMPLETE		99

struct ssh_dh_s {
    unsigned char			status;
    struct library_s			library;
    void				(* free)(struct ssh_dh_s *dh);
    unsigned int			(* get_size_modgroup)(struct ssh_dh_s *dh);
    void				(* calc_e)(struct ssh_dh_s *dh);
    unsigned int			(* write_e)(struct ssh_dh_s *dh, unsigned char *pos, unsigned int len);
    unsigned int			(* read_f)(struct ssh_dh_s *dh, unsigned char *pos, unsigned int len);
    unsigned int			(* write_f)(struct ssh_dh_s *dh, unsigned char *pos, unsigned int len);
    void				(* calc_K)(struct ssh_dh_s *dh);
    unsigned int			(* write_K)(struct ssh_dh_s *dh, unsigned char *pos, unsigned int len);
};

struct ssh_keyx_s {
    char 				digestname[32];
    int					(* start_keyx)(struct ssh_session_s *session, struct ssh_init_algo *algos);
    void				(* free)(struct ssh_session_s *ssh_session);
    union {
	struct ssh_dh_s			dh;
    } method;
};

struct ssh_utils_s {
    int					(* init_library)(unsigned int *error);
    unsigned int 			(* hash)(const char *name, struct common_buffer_s *in, struct common_buffer_s *out, unsigned int *error);
    unsigned int 			(* get_digest_len)(const char *name);
    uint64_t 				(* ntohll)(uint64_t value);
    unsigned int			(* fill_random)(unsigned char *pos, unsigned int len);
};

#define _SSH_CONNECTION_TYPE_IPV4	1
#define _SSH_CONNECTION_TYPE_IPV6	2

struct ssh_connection_s {
    unsigned char			type;
    union {
	struct sockaddr_in 		inet;
	struct sockaddr_in6 		inet6;
    } socket;
    unsigned int 			fd;
    struct bevent_xdata_s 		*xdata;
};

/*
    payload queue for ssh messages
    payload may not be uncompressed
    the mutex and cond is not only used for the session only, but also for the channel payload queue and server reply
    this to make it possible to process the SSH_MSG_UNIMPLEMENTED
    waiting threads for channel related messages must also wait
*/

struct payload_queue_s {
    struct ssh_payload_s 		*first;
    struct ssh_payload_s 		*last;
    struct ssh_signal_s			signal;
    unsigned int 			sequence_number;
    void				(* process_payload_queue)(struct ssh_session_s *session);
};

struct rawdata_queue_s {
    struct rawdata_s			*first;
    struct rawdata_s			*last;
    pthread_mutex_t			mutex;
    pthread_cond_t			cond;
    void				(* queue_ssh_data)(struct ssh_session_s *session, unsigned char *buffer, unsigned int len);
    void 				(* process_rawdata)(struct rawdata_s *data);
};

struct ssh_receive_s {
    struct payload_queue_s		payload_queue;
    struct rawdata_queue_s		rawdata_queue;
    unsigned int 			size;
    unsigned char			*buffer;
};

struct ssh_senddata_s {
    unsigned int			(* get_payload_len)(struct ssh_session_s *s, void *ptr);
    unsigned int			(* fill_payload)(struct ssh_session_s *s, void *ptr);
    int					(* pre_send)(struct ssh_session_s *s, struct ssh_payload_s *p, void *ptr);
    int					(* post_send)(struct ssh_session_s *s, struct ssh_payload_s *p, void *ptr);
};

struct ssh_send_s {
    int 				(* send_message)(struct ssh_session_s *session, int (*fill_raw_message)(struct ssh_session_s *s, struct ssh_payload_s *p, void *ptr), void *ptr, unsigned int *seq);
    pthread_mutex_t			mutex;
    unsigned int 			sequence_number;
};

#define SSH_HOSTINFO_FLAG_TIMEINIT	1
#define SSH_HOSTINFO_FLAG_TIMESET	2

struct ssh_hostinfo_s {
    unsigned int			flags;
    struct timespec			delta;
    void				(* correct_time_s2c)(struct ssh_session_s *session, struct timespec *time);
    void				(* correct_time_c2s)(struct ssh_session_s *session, struct timespec *time);
};

struct ssh_identity_s {
    struct passwd			pwd;
    char				*buffer;
    unsigned int			size;
    struct ssh_string_s			remote_user;
    char				*identity_file;
};

/*
    data used per session:
    - greeter send by server
    - sessionid calculated during kexinit
    - kexinit message send by server
    - kexinit message send by client
    - common keys
*/

#define		SESSION_KEYDATA_STATUS_INIT			1
#define		SESSION_KEYDATA_STATUS_KEYINITC			2
#define		SESSION_KEYDATA_STATUS_KEYINITS			4
#define		SESSION_KEYDATA_STATUS_KEYEXCHANGE		8
#define		SESSION_KEYDATA_STATUS_NEWKEYSS			16
#define		SESSION_KEYDATA_STATUS_NEWKEYSC			32

struct session_keydata_s {
    unsigned int			status;
    struct ssh_string_s			kexinit_server;
    struct ssh_string_s			kexinit_client;
    struct ssh_string_s			iv_c2s;
    struct ssh_string_s			iv_s2c;
};

struct session_data_s {
    struct ssh_string_s			sessionid;
    struct ssh_string_s			greeter_server;
};

struct session_crypto_s {
    struct session_keydata_s		keydata;
    struct ssh_encryption_s 		encryption;
    struct ssh_hmac_s 			hmac;
    struct ssh_compression_s		compression;
    struct ssh_pubkey_s			pubkey;
    struct ssh_keyx_s			keyx;
};

struct session_list_s {
    struct ssh_session_s		*next;
    struct ssh_session_s		*prev;
};

/* main session per user */

struct ssh_session_s {
    struct ssh_status_s			status;
    struct ssh_identity_s		identity;
    struct channel_table_s		channel_table;
    struct session_data_s		data;
    struct session_crypto_s		crypto;
    struct ssh_connection_s		connection;
    struct ssh_receive_s		receive;
    struct ssh_send_s			send;
    struct ssh_hostinfo_s		hostinfo;
    struct session_list_s		list;
};

/* prototypes */

struct ssh_session_s *get_full_session(uid_t uid, struct context_interface_s *interface, char *address, unsigned int port);
void remove_full_session(struct ssh_session_s *session);
void umount_ssh_session(struct context_interface_s *interface);

unsigned int get_window_size(struct ssh_session_s *session);

unsigned int get_max_packet_size(struct ssh_session_s *session);
void set_max_packet_size(struct ssh_session_s *session, unsigned int size);

void get_session_expire_init(struct ssh_session_s *session, struct timespec *expire);
void get_session_expire_session(struct ssh_session_s *session, struct timespec *expire);

void disconnect_ssh_session(struct ssh_session_s *session, unsigned char server, unsigned int reason);

#endif
