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
#include <pwd.h>

#include "workspace-interface.h"
#include "workspace-address.h"
#include "simple-list.h"
#include "simple-locking.h"
#include "localsocket.h"
#include "ssh-datatypes.h"
#include "ssh-pk.h"

struct ssh_session_s;
struct ssh_connection_s;

#include "ssh-pubkey.h"

struct ssh_packet_s {
    unsigned int 			len;
    unsigned int 			size;
    unsigned char			padding;
    unsigned int 			error;
    unsigned int			sequence;
    unsigned char			type;
    unsigned int			decrypted;
    char 				*buffer;
};

typedef void (* receive_msg_cb_t)(struct ssh_connection_s *connection, struct ssh_payload_s *p);

struct server_reply_s {
    unsigned char 			reply;
    unsigned int			sequence;
    unsigned int			error;
    union {
	struct common_buffer_s		data;
	unsigned int			code;
    } response;
};

#define CHANNEL_FLAG_INIT				(1 << 0)
#define CHANNEL_FLAG_TABLE				(1 << 1)
#define CHANNEL_FLAG_OPEN				(1 << 2)
#define CHANNEL_FLAG_OPENFAILURE			(1 << 3)
#define CHANNEL_FLAG_SERVER_EOF				(1 << 4)
#define CHANNEL_FLAG_SERVER_CLOSE			(1 << 5)
#define CHANNEL_FLAG_CLIENT_EOF				(1 << 6)
#define CHANNEL_FLAG_CLIENT_CLOSE			(1 << 7)
#define CHANNEL_FLAG_NODATA				( CHANNEL_FLAG_CLIENT_CLOSE | CHANNEL_FLAG_CLIENT_EOF | CHANNEL_FLAG_SERVER_CLOSE | CHANNEL_FLAG_SERVER_EOF )
#define CHANNEL_FLAG_UDP				(1 << 8)
#define CHANNEL_FLAG_CONNECTION_REFCOUNT		(1 << 9)

#define TABLE_LOCK_OPENCHANNEL				1
#define TABLE_LOCK_CLOSECHANNEL				2
#define TABLE_LOCK_LOCKED				( TABLE_LOCK_OPENCHANNEL | TABLE_LOCK_CLOSECHANNEL )

#define CHANNELS_TABLE_SIZE				8

#define SSH_CONFIG_MAX_PACKET_SIZE			32768
#define SSH_CONFIG_RECEIVE_BUFFER_SIZE			35000
#define SSH_CONFIG_CONNECTION_EXPIRE			5
#define SSH_CONFIG_MAX_RECEIVING_THREADS		4
#define SSH_CONFIG_MAX_SENDING_THREADS			4

#define SSH_CONFIG_FLAG_CORRECT_CLOCKSKEW		(1 << 0)

struct ssh_config_s {
    unsigned int			flags;
    uint64_t				unique;
    unsigned int			max_packet_size;
    unsigned int			max_receive_size;
    unsigned int			port;
    unsigned int			connection_expire;
    unsigned char			max_receiving_threads;
    unsigned char			max_sending_threads;
    // unsigned int			channels_table_size;
};

struct ssh_channel_s;

struct channellist_head_s {
    struct ssh_channel_s		*head;
    struct ssh_channel_s		*tail;
};

struct channellist_element_s {
    struct ssh_channel_s		*next;
    struct ssh_channel_s		*prev;
};

struct channel_table_s {
    unsigned int			latest_channel;
    unsigned int 			count;
    struct ssh_channel_s		*shell;
    unsigned int			table_size;
    struct list_header_s		hash[CHANNELS_TABLE_SIZE];
    struct simple_locking_s		locking;
    unsigned int			lock;
};

#define SSH_SIGNAL_FLAG_ALLOCATED	1
#define SSH_SIGNAL_FLAG_MUTEX_INIT	2
#define SSH_SIGNAL_FLAG_COND_INIT	4

struct ssh_signal_s {
    unsigned char			flags;
    pthread_mutex_t			*mutex;
    pthread_cond_t			*cond;
    unsigned int			sequence_number_error;
    unsigned int			error;
};

struct payload_queue_s {
    struct list_header_s 		header;
    struct ssh_signal_s			*signal;
    void				*ptr;
};

#define _CHANNEL_TYPE_SHELL					1
#define _CHANNEL_TYPE_EXEC					2
#define _CHANNEL_TYPE_SFTP_SUBSYSTEM				3
#define _CHANNEL_TYPE_DIRECT_STREAMLOCAL			4
#define _CHANNEL_TYPE_DIRECT_TCPIP				5
#define _CHANNEL_TYPE_FORWARDED_STREAMLOCAL			6
#define _CHANNEL_TYPE_STREAMLOCAL_FORWARD			7

struct ssh_channel_s {
    struct ssh_connection_s 		*connection;
    struct ssh_session_s		*session;
    unsigned char			type;
    unsigned int 			local_channel;
    unsigned int			remote_channel;
    uint32_t				flags;
    unsigned int			max_packet_size;
    unsigned int			actors;
    uint32_t				local_window;
    void				(* process_incoming_bytes)(struct ssh_channel_s *c, unsigned int size);
    uint32_t				remote_window;
    void				(* process_outgoing_bytes)(struct ssh_channel_s *c, unsigned int size);
    pthread_mutex_t			mutex;
    struct list_element_s		list;
    struct payload_queue_s		queue;
    int					(* start)(struct ssh_channel_s *c, unsigned int *error);
    void				(* receive_msg_channel_data)(struct ssh_channel_s *c, struct ssh_payload_s **payload);
    int 				(* send_data_message)(struct ssh_channel_s *c, unsigned int len, char *data, unsigned int *seq);
    void				(* close)(struct ssh_channel_s *c, unsigned int flags);
    void				(* free)(struct ssh_channel_s *c);
    union {

	    /* used when DIRECT_STREAMLOCAL */

	struct serversocket_s {
	    char			*path;
	    unsigned int		protocol;
	} socket;

	    /* used for any network target, UDP, DIRECT_TCPIP, FORWARD, ..
	    NOTE: the type (tcp, udp, ..) follows from the channel->type*/

	struct network_s {
	    unsigned int		port;
	    struct host_address_s	host;
	} network;

	    /* when data is done via special channel this points to that channel */

	void				*ptr;

    } target;
};

#define SSH_ALGO_TYPE_KEX				0
#define SSH_ALGO_TYPE_HOSTKEY				1
#define SSH_ALGO_TYPE_CIPHER_C2S			2
#define SSH_ALGO_TYPE_CIPHER_S2C			3
#define SSH_ALGO_TYPE_HMAC_C2S				4
#define SSH_ALGO_TYPE_HMAC_S2C				5
#define SSH_ALGO_TYPE_COMPRESS_C2S			6
#define SSH_ALGO_TYPE_COMPRESS_S2C			7
#define SSH_ALGO_TYPE_LANG_C2S				8
#define SSH_ALGO_TYPE_LANG_S2C				9

#define SSH_ALGO_TYPES_COUNT				10

/* for most algos's some are recommended (high order), some required (medium) and some optional (low) */

#define SSH_ALGO_ORDER_LOW				1
#define SSH_ALGO_ORDER_MEDIUM				2
#define SSH_ALGO_ORDER_HIGH				3

struct algo_list_s {
    int					type;
    unsigned int			order;
    char				*sshname;
    char				*libname;
    void				*ptr;
};

#define SSH_ALGO_HASH_SHA1_160				1
#define SSH_ALGO_HASH_SHA2_256				2
#define SSH_ALGO_HASH_SHA2_512				3

struct ssh_dh_s {
    unsigned char			status;
    void				(* free)(struct ssh_dh_s *dh);
    unsigned int			(* get_size_modgroup)(struct ssh_dh_s *dh);
    struct ssh_mpint_s			p;
    struct ssh_mpint_s			g;
    struct ssh_mpint_s			x;
    struct ssh_mpint_s			e;
    struct ssh_mpint_s			f;
    struct ssh_mpint_s			sharedkey;
};

struct ssh_ecdh_s {
    unsigned int			status;
    void				(* free)(struct ssh_ecdh_s *ecdh);
    struct ssh_key_s			skey_c;
    struct ssh_key_s			pkey_s;
    struct ssh_mpint_s			sharedkey;
};

struct ssh_keyex_s;

struct keyex_ops_s {
    char				*name;
    unsigned int			(* populate)(struct ssh_connection_s *c, struct keyex_ops_s *ops, struct algo_list_s *alist, unsigned int start);
    int					(* init)(struct ssh_keyex_s *k, char *name);
    int					(* create_client_key)(struct ssh_keyex_s *k);
    void				(* msg_write_client_key)(struct msg_buffer_s *mb, struct ssh_keyex_s *k);
    void				(* msg_read_server_key)(struct msg_buffer_s *mb, struct ssh_keyex_s *k);
    void				(* msg_write_server_key)(struct msg_buffer_s *mb, struct ssh_keyex_s *k);
    int					(* calc_sharedkey)(struct ssh_keyex_s *k);
    void				(* msg_write_sharedkey)(struct msg_buffer_s *mb, struct ssh_keyex_s *k);
    void				(* free)(struct ssh_keyex_s *k);
    struct list_element_s		list;
};

struct ssh_keyex_s {
    struct ssh_pkauth_s			pkauth;
    char 				digestname[32];
    struct keyex_ops_s			*ops;
    union {
	struct ssh_dh_s			dh;
	struct ssh_ecdh_s		ecdh;
    } method;
};

struct ssh_utils_s {
    uint64_t 				(* ntohll)(uint64_t value);
};

struct ssh_decompressor_s {
    struct ssh_decompress_s		*decompress;
    struct timespec			created;
    unsigned int			nr;
    int					(* decompress_packet)(struct ssh_decompressor_s *d, struct ssh_packet_s *packet, struct ssh_payload_s **payload, unsigned int *error);
    void				(* clear)(struct ssh_decompressor_s *d);
    void				(* queue)(struct ssh_decompressor_s *d);
    struct list_element_s		list;
    unsigned int			size;
    char				buffer[];
};

struct decompress_ops_s {
    char				*name;
    unsigned int			(* populate)(struct ssh_connection_s *c, struct decompress_ops_s *ops, struct algo_list_s *alist, unsigned int start);
    unsigned int			(* get_handle_size)(struct ssh_decompress_s *decompress);
    int					(* init_decompressor)(struct ssh_decompressor_s *d);
    struct list_element_s		list;
};

struct ssh_decompress_s {
    unsigned int			flags;
    char				name[64];
    unsigned int			count;
    unsigned int			max_count;
    struct list_header_s		header;
    struct decompress_ops_s		*ops;
};

struct ssh_decryptor_s {
    struct ssh_decrypt_s		*decrypt;
    struct timespec			created;
    unsigned int			nr;
    int					(* verify_hmac_pre)(struct ssh_decryptor_s *d, struct ssh_packet_s *packet);
    int					(* decrypt_length)(struct ssh_decryptor_s *d, struct ssh_packet_s *packet, char *buffer, unsigned int len);
    int					(* decrypt_packet)(struct ssh_decryptor_s *d, struct ssh_packet_s *packet);
    int					(* verify_hmac_post)(struct ssh_decryptor_s *d, struct ssh_packet_s *packet);
    void				(* clear)(struct ssh_decryptor_s *d);
    void				(* queue)(struct ssh_decryptor_s *d);
    unsigned int			cipher_blocksize;
    unsigned int			cipher_headersize;
    unsigned int			hmac_maclen;
    struct list_element_s		list;
    unsigned int			size;
    char				buffer[];
};

struct decrypt_ops_s {
    char				*name;
    unsigned int			(* populate_cipher)(struct ssh_connection_s *s, struct decrypt_ops_s *ops, struct algo_list_s *alist, unsigned int start);
    unsigned int			(* populate_hmac)(struct ssh_connection_s *s, struct decrypt_ops_s *ops, struct algo_list_s *alist, unsigned int start);
    unsigned int			(* get_handle_size)(struct ssh_decrypt_s *d);
    int					(* init_decryptor)(struct ssh_decryptor_s *decryptor);
    unsigned int			(* get_cipher_blocksize)(const char *name);
    unsigned int			(* get_cipher_keysize)(const char *name);
    unsigned int			(* get_cipher_ivsize)(const char *name);
    unsigned int			(* get_hmac_keysize)(const char *name);
    unsigned int			(* get_decrypt_flag)(const char *ciphername, const char *hmacname, const char *what);
    struct list_element_s		list;
};

#define SSH_DECRYPT_FLAG_PARALLEL			(1 << 1)

struct ssh_decrypt_s {
    unsigned int			flags;
    char 				ciphername[64];
    char				hmacname[64];
    unsigned int			count;			/* total number decryptors in use */
    unsigned int			max_count;		/* maximum number of decryptors, when set to 1 parallel is disabled */
    struct list_header_s		header;			/* linked list of decryptors (possibly one) */
    struct decrypt_ops_s		*ops;			/* decrypt ops used */
    struct ssh_string_s			cipher_key;
    struct ssh_string_s			cipher_iv;
    struct ssh_string_s			hmac_key;
};

/* receive in init phase y/n */

#define SSH_RECEIVE_STATUS_INIT				(1 << 0)

/* receiving received y/n */

#define SSH_RECEIVE_STATUS_GREETER			(1 << 1)

/* in session phase y/n */

#define SSH_RECEIVE_STATUS_SESSION			(1 << 2)

/* in kexinit phase */

#define SSH_RECEIVE_STATUS_KEXINIT			(1 << 3)

/* new keys received */

#define SSH_RECEIVE_STATUS_NEWKEYS			(1 << 4)

/* is the receiving done in serial y/n (alternative is parallel) */

#define SSH_RECEIVE_STATUS_SERIAL			(1 << 9)

/* is there a thread processing a packet ? */

#define SSH_RECEIVE_STATUS_PACKET			(1 << 10)

/* is there a thread waiting for enough data to read the header (4 or 8 bytes mostly)*/

#define SSH_RECEIVE_STATUS_WAITING1			(1 << 11)

/* is there a thread waiting for data to complete a packet ? */

#define SSH_RECEIVE_STATUS_WAITING2			(1 << 12)

#define SSH_RECEIVE_STATUS_WAIT				( SSH_RECEIVE_STATUS_WAITING2 | SSH_RECEIVE_STATUS_WAITING1 )

#define SSH_RECEIVE_STATUS_ERROR			(1 << 30)
#define SSH_RECEIVE_STATUS_DISCONNECT			(1 << 31)

struct ssh_receive_s {
    unsigned int			status;
    struct timespec			newkeys;
    struct ssh_signal_s			signal;
    struct ssh_decrypt_s		decrypt;
    struct ssh_decompress_s		decompress;
    pthread_mutex_t			mutex;
    pthread_cond_t			cond;
    unsigned int			threads;
    unsigned int 			sequence_number;
    void				(* process_ssh_packet)(struct ssh_connection_s *c, struct ssh_packet_s *packet);
    void				(* read_ssh_buffer)(void *ptr);
    unsigned int			read;
    unsigned int 			size;
    char				*buffer;
};

/*
    struct for the sending site
				    */

struct ssh_encrypt_s;
struct ssh_compress_s;

/* struct to do the compressing of the payload
    in the buffer handles and backend library data are 
    the backend library determines how this looks like */

struct ssh_compressor_s {
    struct ssh_compress_s		*compress;
    struct timespec			created;
    unsigned int			nr;
    int					(* compress_payload)(struct ssh_compressor_s *c, struct ssh_payload_s **payload, unsigned int *error);
    void				(* clear)(struct ssh_compressor_s *c);
    void				(* queue)(struct ssh_compressor_s *c);
    struct list_element_s		list;
    unsigned int			size;
    char				buffer[];
};

/* struct with calls to:
    - populate this compressor to the kexinit list
    - get the size to allocate before initializing
    - initialize the compressor*/

struct compress_ops_s {
    char				*name;
    unsigned int			(* populate)(struct ssh_connection_s *c, struct compress_ops_s *ops, struct algo_list_s *alist, unsigned int start);
    unsigned int			(* get_handle_size)(struct ssh_compress_s *compress);
    int					(* init_compressor)(struct ssh_compressor_s *d);
    struct list_element_s		list;
};

/* holds the waiters list with compressors, and the compress_ops used at that time to create a new compressor */

struct ssh_compress_s {
    unsigned int			flags;
    char				name[64];
    unsigned int			count;
    unsigned int			max_count;
    struct list_header_s		header;
    struct compress_ops_s		*ops;
};

/* struct to do the encryption (is a cipher and a digest):
    - write hmac pre when pre encryption digest is used
    - encrypt the packet
    - write hmac post when post encryption digest is used
    - get message padding determines the padding of the message
    - clear clears the encrypt data in buffer */

struct ssh_encryptor_s {
    struct ssh_encrypt_s		*encrypt;
    struct timespec			created;
    unsigned int			nr;
    int					(* write_hmac_pre)(struct ssh_encryptor_s *e, struct ssh_packet_s *packet);
    int					(* encrypt_packet)(struct ssh_encryptor_s *e, struct ssh_packet_s *packet);
    int					(* write_hmac_post)(struct ssh_encryptor_s *e, struct ssh_packet_s *packet);
    unsigned char			(* get_message_padding)(struct ssh_encryptor_s *e, unsigned int len);
    void				(* clear)(struct ssh_encryptor_s *e);
    void				(* queue)(struct ssh_encryptor_s *e);
    unsigned int			cipher_blocksize;
    unsigned int			cipher_headersize;
    unsigned int			hmac_maclen;
    struct list_element_s		list;
    unsigned int			size;
    char				buffer[];
};

/* struct to
    - populate this encrypt (cipher and hmac) to the kexinit list
    - get the size to allocate before initializing
    - initialize the compressor
    - get various sizes required to allocate buffers*/

struct encrypt_ops_s {
    char				*name;
    unsigned int			(* populate_cipher)(struct ssh_connection_s *c, struct encrypt_ops_s *ops, struct algo_list_s *alist, unsigned int start);
    unsigned int			(* populate_hmac)(struct ssh_connection_s *s, struct encrypt_ops_s *ops, struct algo_list_s *alist, unsigned int start);
    unsigned int			(* get_handle_size)(struct ssh_encrypt_s *encrypt);
    int					(* init_encryptor)(struct ssh_encryptor_s *encryptor);
    unsigned int			(* get_cipher_blocksize)(const char *name);
    unsigned int			(* get_cipher_keysize)(const char *name);
    unsigned int			(* get_cipher_ivsize)(const char *name);
    unsigned int			(* get_hmac_keysize)(const char *name);
    unsigned int			(* get_encrypt_flag)(const char *ciphername, const char *hmacname, const char *what);
    struct list_element_s		list;
};

/* holds the waiters list with encryptors, and the ops to create a new encryptor
    additional key data*/

struct ssh_encrypt_s {
    unsigned int			flags;
    char				ciphername[64];
    char				hmacname[64];
    unsigned int			count;
    unsigned int			max_count;
    struct list_header_s		header;				/* linked list of encryptors (possibly one) */
    struct encrypt_ops_s		*ops;				/* encrypt ops used */
    struct ssh_string_s			cipher_key;
    struct ssh_string_s			cipher_iv;
    struct ssh_string_s			hmac_key;
};

struct ssh_sender_s {
    struct list_element_s		list;
    unsigned int			sequence;
};

#define SSH_SEND_FLAG_SESSION				(1 << 0)
#define SSH_SEND_FLAG_KEXINIT				(1 << 1)
#define SSH_SEND_FLAG_NEWKEYS				(1 << 2)
#define SSH_SEND_FLAG_ERROR				(1 << 3)
#define SSH_SEND_FLAG_DISCONNECT			(1 << 4)

struct ssh_send_s {
    unsigned int			flags;
    pthread_mutex_t			mutex;
    pthread_cond_t			cond;
    struct list_header_s		senders;
    struct timespec			newkeys;
    int					(* queue_sender)(struct ssh_send_s *send, struct ssh_sender_s *sender, unsigned int *error);
    unsigned int 			sequence_number;
    struct ssh_encrypt_s		encrypt;
    struct ssh_compress_s		compress;
};

struct ssh_pubkey_s {
    unsigned int 			ids_pkalgo;
    unsigned int			ids_pksign;
};

#define SSH_HOSTINFO_FLAG_TIMEINIT	1
#define SSH_HOSTINFO_FLAG_TIMESET	2

struct ssh_hostinfo_s {
    unsigned int			flags;
    struct ssh_string_s 		fp;
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

/*	data per session:
	- greeters send by server and client
	- sessionid (H) calculated during kexinit in setup phase
*/

struct session_data_s {
    unsigned int 			remote_version_major;
    unsigned int 			remote_version_minor;
    struct ssh_string_s			sessionid;
    struct ssh_string_s			greeter_server;
    struct ssh_string_s			greeter_client;
};

#define SSH_ERROR_TYPE_SYSTEMERROR	1
#define SSH_ERROR_TYPE_INTERNAL		2
#define SSH_ERROR_TYPE_LIBRARY		3

struct ssh_error_s {
    unsigned int			type;
    char				description[128];
    union {
	unsigned int			systemerror;
    } error;
};

#define SSH_GREETER_FLAG_C2S						1
#define SSH_GREETER_FLAG_S2C						2

struct ssh_greeter_s {
    unsigned int			flags;
};

#define SSH_KEX_STATUS_OK				(1 << 0)
#define SSH_KEX_STATUS_ERROR				(1 << 1)

#define SSH_KEX_STATUS_KEXINIT				(1 << 2)
#define SSH_KEX_STATUS_KEX				(1 << 3)
#define SSH_KEX_STATUS_NEWKEYS				(1 << 4)
#define SSH_KEX_STATUS_COMPLETED			(1 << 5)

#define SSH_KEX_FLAG_KEXINIT_C2S			(1 << 0)
#define SSH_KEX_FLAG_KEXINIT_S2C			(1 << 1)
#define SSH_KEX_FLAG_KEXDH_C2S				(1 << 2)
#define SSH_KEX_FLAG_KEXDH_S2C				(1 << 3)
#define SSH_KEX_FLAG_NEWKEYS_C2S			(1 << 4)
#define SSH_KEX_FLAG_NEWKEYS_S2C			(1 << 5)
#define SSH_KEX_FLAG_COMPLETED				(1 << 6)

/*	data per keyexchange
	- algos available
	- kexinit messages server and client
	- algos chosen
	- keys and iv generated
*/

struct ssh_keyexchange_s {
    unsigned int			status;
    unsigned int			flags;
    struct ssh_string_s			kexinit_server;
    struct ssh_string_s			kexinit_client;
    struct algo_list_s			*algos;
    int					chosen[SSH_ALGO_TYPES_COUNT];
    struct ssh_string_s			cipher_key_c2s;
    struct ssh_string_s			cipher_iv_c2s;
    struct ssh_string_s			hmac_key_c2s;
    struct ssh_string_s			cipher_key_s2c;
    struct ssh_string_s			cipher_iv_s2c;
    struct ssh_string_s			hmac_key_s2c;
};

#define SSH_AUTH_METHOD_NONE						1
#define SSH_AUTH_METHOD_PUBLICKEY					2
#define SSH_AUTH_METHOD_PASSWORD					4
#define SSH_AUTH_METHOD_HOSTBASED					8
#define SSH_AUTH_METHOD_UNKNOWN						16

struct ssh_auth_s {
    unsigned int			required;
    unsigned int			done;
    char				*l_hostname;
    char				*l_ipv4;
    char				*r_hostname;
    char				*r_ipv4;
};

#define SSH_TRANSPORT_TYPE_GREETER					1
#define SSH_TRANSPORT_TYPE_KEX						2

struct ssh_transport_s {
    unsigned int			status;
    union {
	struct ssh_keyexchange_s	kex;
	struct ssh_greeter_s		greeter;
    } type;
};

#define SSH_SERVICE_TYPE_AUTH						1

struct ssh_service_s {
    unsigned int			status;
    union {
	struct ssh_auth_s		auth;
    } type;
};

#define SSH_SETUP_PHASE_TRANSPORT					1
#define SSH_SETUP_PHASE_SERVICE						2

/* greeter phase success */
#define SSH_SETUP_FLAG_GREETER						(1 << 0)
/* kex phase success (also rekex) */
#define SSH_SETUP_FLAG_KEX						(1 << 1)
/* transport is setup */
#define SSH_SETUP_FLAG_TRANSPORT					(1 << 2)
/* service authentication success */
#define SSH_SETUP_FLAG_SERVICE_AUTH					(1 << 3)
/* service connection */
#define SSH_SETUP_FLAG_SERVICE_CONNECTION				(1 << 4)
/* service rekex active */
#define SSH_SETUP_FLAG_REKEX						(1 << 5)

#define SSH_SETUP_FLAG_SETUPTHREAD					(1 << 27)
#define SSH_SETUP_FLAG_HOSTINFO						(1 << 28)
#define SSH_SETUP_FLAG_ANALYZETHREAD					(1 << 29)
#define SSH_SETUP_FLAG_DISCONNECTING					(1 << 30)
#define SSH_SETUP_FLAG_DISCONNECTED					(1 << 31)
#define SSH_SETUP_FLAG_DISCONNECT					( SSH_SETUP_FLAG_DISCONNECTING | SSH_SETUP_FLAG_DISCONNECTED )

#define SSH_SETUP_OPTION_XOR						1
#define SSH_SETUP_OPTION_UNDO						2

struct ssh_setup_s {
    unsigned int			status;
    unsigned int 			flags;
    union {
	struct ssh_transport_s		transport;
	struct ssh_service_s		service;
    } phase;
    pthread_mutex_t			*mutex;
    pthread_cond_t			*cond;
    pthread_t				thread;
    struct payload_queue_s 		queue;
};

#define SSH_EXTENSION_SOURCE_EXT_INFO					1

#define SSH_EXTENSION_SERVER_SIG_ALGS					1
#define SSH_EXTENSION_DELAY_COMPRESSION					2
#define SSH_EXTENSION_NO_FLOW_CONTROL					3
#define SSH_EXTENSION_ELEVATION						4

#define SSH_EXTENSIONS_COUNT						4

#define SSH_EXTENSION_SUPPORTED_UNKNOWN					1
#define SSH_EXTENSION_SUPPORTED_TRUE					2
#define SSH_EXTENSION_SUPPORTED_FALSE					3

struct ssh_extension_s {
    char				*name;
    unsigned int			code;
};

struct ssh_extensions_s {
    unsigned int			supported;
    unsigned int			received;
};

#define SSH_CONNECTION_FLAG_MAIN					1
#define SSH_CONNECTION_FLAG_DISCONNECT_SEND				2

struct ssh_connection_s {
    unsigned char			unique;
    unsigned char			flags;
    unsigned char			refcount;
    struct ssh_setup_s			setup;
    struct fs_connection_s		connection;
    struct ssh_receive_s		receive;
    struct ssh_send_s			send;
    struct list_element_s		list;
};

#define SSH_CONNECTIONS_FLAG_SIGNAL_ALLOCATED				1
#define SSH_CONNECTIONS_FLAG_DISCONNECTING				2
#define SSH_CONNECTIONS_FLAG_DISCONNECTED				4
#define SSH_CONNECTIONS_FLAG_DISCONNECT					( SSH_CONNECTIONS_FLAG_DISCONNECTED | SSH_CONNECTIONS_FLAG_DISCONNECTING )

struct ssh_connections_s {
    unsigned char			unique;
    unsigned char			flags;
    pthread_mutex_t			*mutex;
    pthread_cond_t			*cond;
    struct ssh_connection_s		*main;
    struct list_header_s		header;
};

/* main session per user */

struct ssh_session_s {
    struct context_interface_s 		*interface;
    struct ssh_config_s			config;
    struct ssh_identity_s		identity;
    struct channel_table_s		channel_table;
    struct session_data_s		data;
    struct ssh_pubkey_s			pubkey;
    struct ssh_hostinfo_s		hostinfo;
    struct ssh_connections_s		connections;
    struct ssh_extensions_s		extensions;
    struct list_element_s		list;
};

/* prototypes */

int create_ssh_connection(uid_t uid, struct context_interface_s *interface, struct context_address_s *address, unsigned int *error);
void disconnect_ssh_session(struct ssh_session_s *session, unsigned char server, unsigned int reason);
void signal_ssh_interface(struct context_interface_s *interface, const char *what);

unsigned int get_window_size(struct ssh_session_s *session);
unsigned int get_max_packet_size(struct ssh_session_s *session);
void set_max_packet_size(struct ssh_session_s *session, unsigned int size);

int start_thread_connection_problem(struct ssh_connection_s *connection);

#endif
