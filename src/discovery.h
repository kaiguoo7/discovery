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




/* 角色定义 */
typedef enum role_e {
    ROLE_UNKNOWN = 0,       /* 未知角色 */
    ROLE_MASTER = 10,       /* master角色,主角色 */
    ROLE_SLAVER = 20        /* slaver角色,从角色 */
}role_t;


/* 消息类型 */
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


/* 消息加密类型 */
typedef enum enc_type_e {
    ENC_TYPE_NONE       = 0,    /* 未加密 */
    ENC_TYPE_BASE64     = 10    /* base64加密 */
}enc_type_t;

/* 设备信息 */
typedef struct dev_cfg_s {
    role_t  role;               /* 设备角色 */
    int     port;               /* 自发现端口 */
    bool    hello_enable;       /* hello报文周期发送开关 */
    int     bcast_period;       /* 广播报文发送周期，单位秒 */
    char*   networkId;
    char*   networkName;
    char*   ifname; 
}dev_cfg_t;


/* 设备信息 */
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


/*设备列表*/
typedef struct dev_node_s {
    dev_info_t          devInfo; 
    int                 outTime;
    struct list_head    list;
}dev_node_t;


typedef struct disc_msg_hdr_s {
    int         version;            /* 消息版本号 */
    msg_type_t  msgType;            /* 消息类型 */
    enc_type_t  encType;            /* 加密类型 */
    int         payloadLen;         /* 消息内容长度 */
}disc_msg_hdr_t;
    

/* 消息体 */
typedef struct disc_msg_s {
    disc_msg_hdr_t  msgHdr;        /* 消息类型 */
    char*           payload;       /* 消息内容，json格式字符串 */
}disc_msg_t;


typedef struct ip_udp_packet {
     struct iphdr   ip;             /* IP层头部 */
     struct udphdr  udp;            /* UDP层头部 */
}packet_hdr_t;



#endif /* __DISCOVERY_H__ */
