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
    unsigned int			flags;
    unsigned int			len;
    char				*ptr;
};

struct commalist_s {
    char 				*list;
    unsigned int 			len;
    unsigned int 			size;
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
    char				buffer[];
};

struct payload_list_s {
    struct ssh_payload_s		*head;
    struct ssh_payload_s		*tail;
};

struct ssh_packet_s {
    unsigned int 			len;
    unsigned char			padding;
    unsigned int 			error;
    unsigned int			sequence;
    char 				*buffer;
};

struct rawdata_s {
    struct ssh_session_s		*session;
    struct rawdata_s			*next;
    unsigned int			size;
    unsigned int 			len;
    unsigned int			maclen;
    unsigned int			decrypted;
    unsigned int			sequence;
    char 				buffer[];
};

struct server_reply_s {
    unsigned char 			reply;
    unsigned int			sequence;
    unsigned int			error;
    union {
	struct common_buffer_s		data;
	unsigned int			code;
    } response;
};

#define SESSION_STATUS_SETUP					1

#define SESSION_SUBSTATUS_GREETER				1
#define SESSION_SUBSTATUS_KEYEXCHANGE				2
#define SESSION_SUBSTATUS_REQUEST_USERAUTH			4
#define SESSION_SUBSTATUS_USERAUTH				8

#define SESSION_STATUS_CONNECTION				2
#define SESSION_STATUS_REEXCHANGE				3

#define SESSION_SUBSTATUS_DISCONNECTING				128

#define SESSION_STATUS_DISCONNECT				99

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
#define SSH_USERAUTH_UNKNOWN				16
#define SSH_USERAUTH_SUCCESS				32

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

struct ssh_pkalgo_s {
    unsigned int			type;
    const char				*name;
    unsigned int			len;
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

struct ssh_encryption_s;

struct ssh_encrypt_s {
    struct library_s			library;
    int					(*init)(struct ssh_encryption_s *encryption, char *name, unsigned int *error);
    int 				(*encrypt)(struct ssh_encryption_s *encryption, struct ssh_packet_s *packet);
    void				(*reset_encrypt)(struct ssh_encryption_s *encryption);
    void				(*close_encrypt)(struct ssh_encryption_s *encryption);
    void				(*free_encrypt)(struct ssh_encryption_s *encryption);
    unsigned int			blocksize;
    int					(*setkey_cipher)(struct ssh_string_s *old, char *name, struct ssh_string_s *key);
    int					(*setiv_cipher)(struct ssh_string_s *old, char *name, struct ssh_string_s *iv);
    struct ssh_string_s 		key_cipher;
    struct ssh_string_s 		iv_cipher;
    /* RFC 4253 defines default padding but some ciphers use their own (like chacha20-poly1305)*/
    unsigned char			(*get_message_padding)(unsigned int len, unsigned int blocksize);
};

#define DECRYPT_NEWKEYS_WAIT		1

struct ssh_decrypt_s {
    struct library_s			library;
    unsigned char			status;
    pthread_mutex_t			mutex;
    pthread_cond_t			cond;
    void				(* wait_newkeys_complete)(struct ssh_decrypt_s *d);
    int					(*init)(struct ssh_encryption_s *encryption, char *name_cipher, unsigned int *error);
    /* decrypt the first block to get the length to determine the whole packet is received */
    int 				(*decrypt_length)(struct rawdata_s *data, unsigned char *buffer, unsigned int len);
    int 				(*decrypt_packet)(struct rawdata_s *data);
    void				(*reset_decrypt)(struct ssh_encryption_s *encryption);
    void				(*close_decrypt)(struct ssh_encryption_s *encryption);
    void				(*free_decrypt)(struct ssh_encryption_s *encryption);
    unsigned int			blocksize;
    int					(*setkey_cipher)(struct ssh_string_s *old, char *name, struct ssh_string_s *key);
    int					(*setiv_cipher)(struct ssh_string_s *old, char *name, struct ssh_string_s *iv);
    struct ssh_string_s 		key_cipher;
    struct ssh_string_s 		iv_cipher;
    unsigned int			size_firstbytes;
};

struct ssh_encryption_s {
    struct ssh_decrypt_s		decrypt;
    struct ssh_encrypt_s		encrypt;
    unsigned int 			(*get_cipher_keysize)(const char *name);
    unsigned int 			(*get_cipher_blocksize)(const char *name);
    unsigned int 			(*get_cipher_ivsize)(const char *name);
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

struct ssh_dh_s {
    unsigned char			status;
    struct library_s			library;
    void				(* free)(struct ssh_dh_s *dh);
    unsigned int			(* get_size_modgroup)(struct ssh_dh_s *dh);
    void				(* calc_e)(struct ssh_dh_s *dh);
    unsigned int			(* write_e)(struct ssh_dh_s *dh, char *pos, unsigned int len);
    unsigned int			(* read_f)(struct ssh_dh_s *dh, char *pos, unsigned int len);
    unsigned int			(* write_f)(struct ssh_dh_s *dh, char *pos, unsigned int len);
    void				(* calc_K)(struct ssh_dh_s *dh);
    unsigned int			(* write_K)(struct ssh_dh_s *dh, char *pos, unsigned int len);
};

/*
    TODO:
    struct ssh_ecdh_s {
	free
	void				(calc q_c)
	unsigned int			(write q_c)
	unsigned int			(read q_s)
	unsigned int			(write q_s)
	void				(calc K)
	unsigned int			(write K)
    }
*/
struct ssh_kexinit_algo;

struct ssh_keyx_s {
    unsigned char			type_hostkey;
    char 				digestname[32];
    int					(* start_keyx)(struct ssh_session_s *session, struct ssh_keyx_s *keyx, struct ssh_kexinit_algo *algos);
    void				(* free)(struct ssh_keyx_s *keyx);
    union {
	struct ssh_dh_s			dh;
    } method;
};

struct ssh_utils_s {
    int					(* init_library)(unsigned int *error);
    unsigned int 			(* hash)(const char *name, struct common_buffer_s *in, struct common_buffer_s *out, unsigned int *error);
    unsigned int 			(* get_digest_len)(const char *name);
    uint64_t 				(* ntohll)(uint64_t value);
    unsigned int			(* fill_random)(char *pos, unsigned int len);
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

struct payload_queue_s {
    struct payload_list_s 		list;
    struct ssh_signal_s			signal;
    unsigned int 			sequence_number;
    void				(* process_payload_queue)(struct ssh_session_s *session);
};

struct rawdata_queue_s {
    struct rawdata_s			*first;
    struct rawdata_s			*last;
    pthread_mutex_t			mutex;
    pthread_cond_t			cond;
    void				(* queue_ssh_data)(struct ssh_session_s *session, char *buffer, unsigned int len);
    void 				(* process_rawdata)(struct rawdata_s *data);
};

struct ssh_receive_s {
    struct payload_queue_s		payload_queue;
    struct rawdata_queue_s		rawdata_queue;
    unsigned int 			size;
    char				*buffer;
};

/* TODO use */

struct ssh_sendproc_s {
    int					(* get_payload)(struct ssh_session_s *s, struct ssh_payload_s *p, void *ptr);
    void				(* post_send)(struct ssh_session_s *s, struct ssh_payload_s *p, void *ptr);
    void				(* post_send_error)(struct ssh_session_s *s, struct ssh_payload_s *p, void *ptr, unsigned int error);
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
    data per session:
    - greeter send by server
    - sessionid calculated during kexinit
*/

struct session_data_s {
    struct ssh_string_s			sessionid;
    struct ssh_string_s			greeter_server;
};

struct ssh_kexinit_algo {
    char				keyexchange[64];
    char				hostkey[32];
    char				encryption_c2s[64];
    char				encryption_s2c[64];
    char				hmac_c2s[64];
    char				hmac_s2c[64];
    char				compression_c2s[32];
    char				compression_s2c[32];
};

/*
    data per crypto session:
    - kexinit message send by server
    - kexinit message send by client
    - initialization vectors
*/

#define		KEYEXCHANGE_STATUS_KEYINIT_C2S			1
#define		KEYEXCHANGE_STATUS_KEYINIT_S2C			2
#define		KEYEXCHANGE_STATUS_KEYX_C2S			4
#define		KEYEXCHANGE_STATUS_KEYX_S2C			8
#define		KEYEXCHANGE_STATUS_NEWKEYS_C2S			16
#define		KEYEXCHANGE_STATUS_NEWKEYS_S2C			32
#define		KEYEXCHANGE_STATUS_FINISH_S2C			64

#define		KEYEXCHANGE_STATUS_ERROR			256

struct session_keydata_s {
    unsigned int			status;
    struct ssh_string_s			kexinit_server;
    struct ssh_string_s			kexinit_client;
    struct ssh_string_s			iv_c2s;
    struct ssh_string_s			iv_s2c;
    struct ssh_string_s 		hmac_key_s2c;
    struct ssh_string_s 		hmac_key_c2s;
    struct ssh_string_s 		cipher_key_s2c;
    struct ssh_string_s 		cipher_key_c2s;
    struct ssh_kexinit_algo		algos;
};

struct session_crypto_s {
    struct ssh_encryption_s 		encryption;
    struct ssh_hmac_s 			hmac;
    struct ssh_compression_s		compression;
};

struct keyexchange_s {
    struct session_keydata_s		keydata;
    struct payload_list_s 		list;
    pthread_mutex_t			mutex;
    pthread_cond_t			cond;
    struct ssh_payload_s 		*(* get_payload_kex)(struct ssh_session_s *s, struct timespec *expire, unsigned int *seq, unsigned int *error);
};

#define		SESSION_USERAUTH_STATUS_REQUEST			1
#define		SESSION_USERAUTH_STATUS_ACCEPT			2
#define		SESSION_USERAUTH_STATUS_SUCCESS			32
#define		SESSION_USERAUTH_STATUS_ERROR			64

struct ssh_userauth_s {
    unsigned int			status;
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
    struct ssh_pubkey_s			pubkey;
    struct keyexchange_s		*keyexchange;
    struct ssh_userauth_s		userauth;
    struct ssh_connection_s		connection;
    struct ssh_receive_s		receive;
    struct ssh_send_s			send;
    struct ssh_hostinfo_s		hostinfo;
    struct session_list_s		list;
};

/* prototypes */

void change_session_status(struct ssh_session_s *session, unsigned int status);
int check_session_status(struct ssh_session_s *session, unsigned int status, unsigned int substatus);
int check_change_session_substatus(struct ssh_session_s *session, unsigned int status, unsigned int substatus, unsigned int subnew);

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
