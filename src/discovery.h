#ifndef __DISCOVERY_H__
#define __DISCOVERY_H__

#include <netinet/udp.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <linux/if_packet.h>
#include <linux/filter.h>
#include <libubox/list.h>
#include <libubox/blobmsg_json.h>

#define DISC_LOG_SIZE       100
#define DISC_LOG_FILE       "/tmp/discovery/disc.log"
#define DISC_DEVINFO_FILE   "/tmp/discovery/dev_info.json"

#define DISC_PORT_DEFAULT   36521
#define VERISON_DEFAULT     1
#define DISC_IP_LEN         16

#define NETWORKID_LEN       32
#define NETWORKNAME_LEN     64




/* ��ɫ���� */
typedef enum role_e {
    ROLE_UNKNOWN = 0,       /* δ֪��ɫ */
    ROLE_MASTER = 10,       /* master��ɫ,����ɫ */
    ROLE_SLAVER = 20        /* slaver��ɫ,�ӽ�ɫ */
}role_t;


/* ��Ϣ���� */
typedef enum msg_type_e {
    MSG_TYPE_DECLARE    = 10,
    MSG_TYPE_REJECT     = 20,
    MSG_TYPE_MERGE      = 30,
    MSG_TYPE_HELLO      = 40,
    MSG_TYPE_REQUEST    = 50,
    MSG_TYPE_RESPONSE   = 60,
    MSG_TYPE_SHELL      = 70,
    MSG_TYPE_MAX        = 99
}msg_type_t;


/* ��Ϣ�������� */
typedef enum enc_type_e {
    ENC_TYPE_NONE       = 0,    /* δ���� */
    ENC_TYPE_BASE64     = 10    /* base64���� */
}enc_type_t;

/* �豸��Ϣ */
typedef struct dev_cfg_s {
    role_t  role;               /* �豸��ɫ */
    int     port;               /* �Է��ֶ˿� */
    bool    hello_enable;       /* hello�������ڷ��Ϳ��� */
    int     bcast_period;       /* �㲥���ķ������ڣ���λ�� */
    char*   networkId;
    char*   networkName;
    char*   ifname; 
}dev_cfg_t;


/* �豸��Ϣ */
typedef struct dev_info_s {
    role_t* role;
    char*   ip;
    char*   mac;
    char*   sn;
    char*   productModel;
    char*   networkId;
    char*   networkName;
    char*   software;
    char*   hardware;
}dev_info_t;


/*�豸�б�*/
typedef struct dev_node_s {
    dev_info_t          devInfo; 
    int                 outTime;
    struct list_head    list;
}dev_node_t;


typedef struct disc_msg_hdr_s {
    int         version;            /* ��Ϣ�汾�� */
    msg_type_t  msgType;            /* ��Ϣ���� */
    enc_type_t  encType;            /* �������� */
    int         payloadLen;         /* ��Ϣ���ݳ��� */
}disc_msg_hdr_t;
    

/* ��Ϣ�� */
typedef struct disc_msg_s {
    disc_msg_hdr_t  msgHdr;        /* ��Ϣ���� */
    char*           payload;       /* ��Ϣ���ݣ�json��ʽ�ַ��� */
}disc_msg_t;


typedef struct ip_udp_packet {
     struct iphdr   ip;             /* IP��ͷ�� */
     struct udphdr  udp;            /* UDP��ͷ�� */
}packet_hdr_t;



#endif /* __DISCOVERY_H__ */
