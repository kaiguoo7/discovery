#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <uci.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/prctl.h>
#include <net/if.h>
#include <netinet/if_ether.h>
#include <netinet/ether.h> 
#include <netinet/udp.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <linux/if_packet.h>
#include <linux/filter.h>
#include <libdebug/libdebug.h>
#include <libubox/list.h>
#include <libubox/blobmsg_json.h>
#include <libubus.h>
#include "discovery.h"


#define DISC_PKT_NAME               "discovery"
#define DISC_SCT_NAME               "discovery"
#define PRINT_INTERVAL              5
#define QUEUE_LEN                   512     /* 队列长度 */
#define BUF_LEN                     2048
#define OUT_TIMES                   2
#define SN_BROADCAST                "FFFFFFFFFFFFF" /* SN广播，与正常的SN长度一样，13位 */
#define MASTER_CHANGE_HOOK_SCRIPT   "/lib/discovery/master_change_hook.script" /* master变更时，hook脚本 */

/* debug宏定义 */
#define DISC_FILE(fmt, arg...) do { \
    dbg_logfile(g_md_id, fmt, ##arg);\
} while (0)

#define DISC_DEBUG(fmt, arg...) do { \
    dbg_printf(g_md_id, DBG_LV_DEBUG, fmt, ##arg);\
} while (0)

#define DISC_WARNING(fmt, arg...) do { \
    dbg_printf(g_md_id, DBG_LV_WARNING, "WARNING in %s [%d]: "fmt, __FILE__, __LINE__, ##arg);\
} while (0)

#define DISC_ERROR(fmt, arg...) do { \
    dbg_printf(g_md_id, DBG_LV_ERROR, "ERROR in %s [%d]: "fmt, __FILE__, __LINE__, ##arg);\
} while (0)


static int g_md_id = -1;
static struct list_head g_neighbor_list;
static struct uloop_timeout* g_send_timer = NULL;
static struct uloop_timeout* g_age_timer = NULL;
static struct uloop_fd* g_fd = NULL;
static struct ubus_context* g_ubus_ctx;
static dev_info_t* g_dev_info = NULL;
static dev_cfg_t* g_dev_cfg = NULL;
static disc_msg_t* g_msg_queue[QUEUE_LEN];  /* 接收消息队列 */
static int g_queue_head, g_queue_tail;      /* 接收队列指针头、尾 */
static pthread_mutex_t g_proc_mutex;        /* process线程互斥量 */
static pthread_cond_t  g_proc_cond;         /* process线程条件变量 */
static int g_declare_count = 0;             /* declare次数 */
static pthread_mutex_t g_role_mutex;        /* role信息互斥量 */
static pthread_mutex_t g_master_mutex;      /* master信息互斥量 */
static pthread_mutex_t g_list_mutex;        /* neighbor list信息互斥量 */
static dev_node_t* g_master_info;



static int disc_merge_network(struct ubus_context* ctx, struct ubus_object* obj,
    struct ubus_request_data* req, const char* method, struct blob_attr* msg);
static int disc_show_neighbor(struct ubus_context* ctx, struct ubus_object* obj,
    struct ubus_request_data* req, const char* method, struct blob_attr* msg);
static int disc_exec_shell(struct ubus_context* ctx, struct ubus_object* obj,
    struct ubus_request_data* req, const char* method, struct blob_attr* msg);
static int disc_show_cfg(struct ubus_context* ctx, struct ubus_object* obj,
    struct ubus_request_data* req, const char* method, struct blob_attr* msg);
static int disc_show_status(struct ubus_context* ctx, struct ubus_object* obj,
    struct ubus_request_data* req, const char* method, struct blob_attr* msg);
static int disc_show_role(struct ubus_context* ctx, struct ubus_object* obj,
    struct ubus_request_data* req, const char* method, struct blob_attr* msg);
static int disc_show_master(struct ubus_context* ctx, struct ubus_object* obj,
    struct ubus_request_data* req, const char* method, struct blob_attr* msg);
static int disc_neighbor_detect(struct ubus_context* ctx, struct ubus_object* obj,
    struct ubus_request_data* req, const char* method, struct blob_attr* msg);
static char* disc_role_to_string(role_t role);
static int disc_send_raw_packet(char* data, int data_len, uint32_t source_nip, int source_port,
		uint32_t dest_nip, int dest_port, const uint8_t *dest_arp, int ifindex);
static int disc_send_broadcast_msg(disc_msg_t* msg, const char* destSn);
static int disc_send_unicast_msg(disc_msg_t* msg, const char* destIp);
static int disc_send_msg(msg_type_t msgType, enc_type_t encType, const char* destSn);
static int disc_get_role(void);
static void disc_free_neighbor_list(void);
static int disc_send_declare(const char* destSn);
static int disc_send_reject(const char* destSn);
static int disc_send_merge(const char* destSn);
static int disc_send_hello(const char* destSn);
static int disc_send_request(const char* destSn);
static int disc_send_response(const char* destIp,const char* destSn);
static int disc_send_shell(const char* cmds, const char* destSn);




/* ubus 相关 */
enum {
    DISC_NETWORKID,
    DISC_PRODUCTMODEL,
    DISC_SOFTWARE,
    DISC_HARDWARE,
    DISC_SN,
    DISC_CMDS,
    DISC_MAX
};

static const struct blobmsg_policy disc_policy[DISC_MAX] = {
    [DISC_NETWORKID] = { .name = "networkId", .type = BLOBMSG_TYPE_STRING },
    [DISC_PRODUCTMODEL] = { .name = "productModel", .type = BLOBMSG_TYPE_STRING },
    [DISC_SOFTWARE] = { .name = "software", .type = BLOBMSG_TYPE_STRING },
    [DISC_HARDWARE] = { .name = "hardware", .type = BLOBMSG_TYPE_STRING },
    [DISC_SN] = { .name = "sn", .type = BLOBMSG_TYPE_STRING },
    [DISC_CMDS] = { .name = "cmds", .type = BLOBMSG_TYPE_STRING },
};

static const struct ubus_method disc_methods[] = {
    UBUS_METHOD("merge", disc_merge_network, disc_policy),
    UBUS_METHOD("neighbor", disc_show_neighbor, disc_policy),
    UBUS_METHOD("shell", disc_exec_shell, disc_policy),
    { .name = "cfg", .handler = disc_show_cfg },
    { .name = "status", .handler = disc_show_status },
    { .name = "role", .handler = disc_show_role },
    { .name = "master", .handler = disc_show_master },
    { .name = "detect", .handler = disc_neighbor_detect },
};

static struct ubus_object_type disc_obj_type = UBUS_OBJECT_TYPE("discovery", disc_methods);

static struct ubus_object disc_object = {
    .name = "discovery",
    .type = &disc_obj_type,
    .methods = disc_methods,
    .n_methods = ARRAY_SIZE(disc_methods)
};

static int disc_merge_network(struct ubus_context* ctx, struct ubus_object* obj,
    struct ubus_request_data* req, const char* method, struct blob_attr* msg)
{
    dev_node_t *tmp, *n;
    struct blob_attr* tb[DISC_MAX];
    char* destNetworkId = NULL;
    char* destSn = NULL;
    
    blobmsg_parse(disc_policy, DISC_MAX, tb, blob_data(msg), blob_len(msg));
    
    if(tb[DISC_NETWORKID]) {
        destNetworkId = blobmsg_data(tb[DISC_NETWORKID]);
    }

    if(tb[DISC_SN]) {
        destSn = blobmsg_data(tb[DISC_SN]);
    }

    pthread_mutex_lock(&g_list_mutex);

    list_for_each_entry_safe(tmp, n, &g_neighbor_list, list) {
        if (destNetworkId != NULL && strcmp(tmp->devInfo.networkId, destNetworkId) != 0) {
            continue;
        }

        if (destSn != NULL && strcmp(tmp->devInfo.sn, destSn) != 0) {
            continue;
        }

        (void)disc_send_merge(tmp->devInfo.sn);
    }

    pthread_mutex_unlock(&g_list_mutex);
    
    
    return 0;
}

static int disc_show_neighbor(struct ubus_context* ctx, struct ubus_object* obj,
    struct ubus_request_data* req, const char* method, struct blob_attr* msg)
{
    void *array, *t;
    dev_node_t *tmp, *n;
    struct blob_buf b;
    int count = 0;
    
    memset(&b, 0, sizeof(struct blob_buf));
    blob_buf_init(&b, 0);

    array = blobmsg_open_array(&b, "list");
    
    pthread_mutex_lock(&g_list_mutex);

    if (list_empty(&g_neighbor_list)) {
        goto end;
    }

    list_for_each_entry_safe(tmp, n, &g_neighbor_list, list) {
        t = blobmsg_open_table(&b, NULL);
        
        /* sn */
        blobmsg_add_string(&b, "sn", tmp->devInfo.sn);

        /* mac */
        blobmsg_add_string(&b, "mac", tmp->devInfo.mac);

        /* ip */
        blobmsg_add_string(&b, "ip", tmp->devInfo.ip);

        /* role */
        blobmsg_add_string(&b, "role", disc_role_to_string(*(tmp->devInfo.role)));

        /* productModel */
        blobmsg_add_string(&b, "productModel", tmp->devInfo.productModel);

        /* networkId */
        blobmsg_add_string(&b, "networkId", tmp->devInfo.networkId);

        /* networkName */
        blobmsg_add_string(&b, "networkName", tmp->devInfo.networkName);

        /* software */
        blobmsg_add_string(&b, "software", tmp->devInfo.software);

        /* software */
        blobmsg_add_string(&b, "hardware", tmp->devInfo.hardware);

        blobmsg_close_table(&b, t);
        count ++;
    }

end:
    pthread_mutex_unlock(&g_list_mutex);
    blobmsg_close_array(&b, array);
    blobmsg_add_u32(&b, "count", count);
    
    ubus_send_reply(ctx, req, b.head);
    
    blob_buf_free(&b);
    
    return 0;
}

static int disc_exec_shell(struct ubus_context* ctx, struct ubus_object* obj,
    struct ubus_request_data* req, const char* method, struct blob_attr* msg)
{
    struct blob_attr* tb[DISC_MAX];
    char* cmds = NULL;
    char* destSn = NULL;
    struct blob_buf b;
    
    memset(&b, 0, sizeof(struct blob_buf));
    blobmsg_parse(disc_policy, DISC_MAX, tb, blob_data(msg), blob_len(msg));
    
    if(tb[DISC_CMDS]) {
        cmds = blobmsg_data(tb[DISC_CMDS]);
    }

    if(tb[DISC_SN]) {
        destSn = blobmsg_data(tb[DISC_SN]);
    } 

    if (cmds == NULL) {
        memset(&b, 0, sizeof(struct blob_buf));
        blob_buf_init(&b, 0);
        blobmsg_add_string(&b, "msg", "Error: Not find cmds");
        ubus_send_reply(ctx, req, b.head);
        blob_buf_free(&b);
        return -1;
    }

    if(tb[DISC_SN] == NULL) {
        destSn = SN_BROADCAST;
    } 

    if(disc_send_shell(cmds, destSn) != 0) {
        DISC_ERROR("Send shell message failed\n");
    }

    
    return 0;
}

static int disc_show_cfg(struct ubus_context* ctx, struct ubus_object* obj,
    struct ubus_request_data* req, const char* method, struct blob_attr* msg)
{
    struct blob_buf b;

    memset(&b, 0, sizeof(struct blob_buf));
    
    blob_buf_init(&b, 0);
        
    /* port */
    blobmsg_add_u32(&b, "port", g_dev_cfg->port);

    /* hello_enable */
    blobmsg_add_u8(&b, "hello_enable", g_dev_cfg->hello_enable);

    /* bcast_period */
    blobmsg_add_u32(&b, "bcast_period", g_dev_cfg->bcast_period);

    /* networkId */
    blobmsg_add_string(&b, "networkId", g_dev_cfg->networkId);

    /* networkName */
    blobmsg_add_string(&b, "networkName", g_dev_cfg->networkName);

    /* ifname */
    blobmsg_add_string(&b, "ifname", g_dev_cfg->ifname);

    ubus_send_reply(ctx, req, b.head);

    blob_buf_free(&b);
    
    return 0;
}

static int disc_show_status(struct ubus_context* ctx, struct ubus_object* obj,
    struct ubus_request_data* req, const char* method, struct blob_attr* msg)
{
    struct blob_buf b;

    memset(&b, 0, sizeof(struct blob_buf));
    
    blob_buf_init(&b, 0);

    if (disc_get_role() == ROLE_UNKNOWN) {
        /* status */
        blobmsg_add_string(&b, "status", "discovering");
        goto end;
    }

    /* status */
    blobmsg_add_string(&b, "status", "done");
    
    /* role */
    blobmsg_add_string(&b, "role", disc_role_to_string(disc_get_role()));
    
    /* ip */
    blobmsg_add_string(&b, "ip", g_dev_info->ip);

    /* mac */
    blobmsg_add_string(&b, "mac", g_dev_info->mac);

    /* sn */
    blobmsg_add_string(&b, "sn", g_dev_info->sn);

    /* productModel */
    blobmsg_add_string(&b, "productModel", g_dev_info->productModel);

    /* networkId */
    blobmsg_add_string(&b, "networkId", g_dev_info->networkId);

    /* networkName */
    blobmsg_add_string(&b, "networkName", g_dev_info->networkName);

    /* software */
    blobmsg_add_string(&b, "software", g_dev_info->software);

    /* hardware */
    blobmsg_add_string(&b, "hardware", g_dev_info->hardware);

end:
    ubus_send_reply(ctx, req, b.head);
    
    blob_buf_free(&b);
    
    return 0;
}

static int disc_show_role(struct ubus_context* ctx, struct ubus_object* obj,
    struct ubus_request_data* req, const char* method, struct blob_attr* msg)
{
    struct blob_buf b;
    
    memset(&b, 0, sizeof(struct blob_buf));

    blob_buf_init(&b, 0);

    /* role */
    blobmsg_add_string(&b, "role", disc_role_to_string(*(g_dev_info->role)));

    ubus_send_reply(ctx, req, b.head);
    
    blob_buf_free(&b);
    
    return 0;
}

static int disc_show_master(struct ubus_context* ctx, struct ubus_object* obj,
    struct ubus_request_data* req, const char* method, struct blob_attr* msg)
{
    struct blob_buf b;
   
    memset(&b, 0, sizeof(struct blob_buf));

    blob_buf_init(&b, 0);
    
    pthread_mutex_lock(&g_master_mutex);
    
    /* role */
    blobmsg_add_string(&b, "role", g_master_info->devInfo.role?disc_role_to_string(*(g_master_info->devInfo.role)):"");

    /* ip */
    blobmsg_add_string(&b, "ip", g_master_info->devInfo.ip?g_master_info->devInfo.ip:"");

    /* mac */
    blobmsg_add_string(&b, "mac", g_master_info->devInfo.mac?g_master_info->devInfo.mac:"");

    /* sn */
    blobmsg_add_string(&b, "sn", g_master_info->devInfo.sn?g_master_info->devInfo.sn:"");

    /* productModel */
    blobmsg_add_string(&b, "productModel", g_master_info->devInfo.productModel?g_master_info->devInfo.productModel:"");

    /* networkId */
    blobmsg_add_string(&b, "networkId", g_master_info->devInfo.networkId?g_master_info->devInfo.networkId:"");

    /* networkName */
    blobmsg_add_string(&b, "networkName", g_master_info->devInfo.networkName?g_master_info->devInfo.networkName:"");

    /* software */
    blobmsg_add_string(&b, "software", g_master_info->devInfo.software?g_master_info->devInfo.software:"");

    /* hardware */
    blobmsg_add_string(&b, "hardware", g_master_info->devInfo.hardware? g_master_info->devInfo.hardware:"");

    /* outTime */
    blobmsg_add_u32(&b, "outTime", g_master_info->outTime);

    pthread_mutex_unlock(&g_master_mutex);

    ubus_send_reply(ctx, req, b.head);
        
    blob_buf_free(&b);

    return 0;
}

static int disc_neighbor_detect(struct ubus_context* ctx, struct ubus_object* obj,
    struct ubus_request_data* req, const char* method, struct blob_attr* msg)
{
    (void) disc_free_neighbor_list();

    if (disc_send_request(SN_BROADCAST) != 0 ) {
        DISC_ERROR("Send request message failed\n");
    }

    return 0;
}

static int disc_free_node(dev_node_t* node)
{
    if (node == NULL) {
        return 0;
    }

    if (node->devInfo.role) {
        free(node->devInfo.role);
        node->devInfo.role = NULL;
    }

    if (node->devInfo.ip) {
        free(node->devInfo.ip);
        node->devInfo.ip = NULL;
    }

    if (node->devInfo.mac) {
        free(node->devInfo.mac);
        node->devInfo.mac = NULL;
    }

    if (node->devInfo.sn) {
        free(node->devInfo.sn);
        node->devInfo.ip = NULL;
    }

    if (node->devInfo.productModel) {
        free(node->devInfo.productModel);
        node->devInfo.productModel = NULL;
    }

    if (node->devInfo.networkId) {
        free(node->devInfo.networkId);
        node->devInfo.networkId = NULL;
    }

    if (node->devInfo.networkName) {
        free(node->devInfo.networkName);
        node->devInfo.networkName = NULL;
    }

    if (node->devInfo.software) {
        free(node->devInfo.software);
        node->devInfo.software = NULL;
    }

    if (node->devInfo.hardware) {
        free(node->devInfo.hardware);
        node->devInfo.ip = NULL;
    }

    free(node);

    return 0;
}

static int disc_update_neighbor_info(dev_node_t* node)
{
    bool bingo = false;
    dev_node_t *tmp, *n;

    pthread_mutex_lock(&g_list_mutex);
    
    if (!list_empty(&g_neighbor_list)) {
        list_for_each_entry_safe(tmp, n, &g_neighbor_list, list) {
             if (strcmp(tmp->devInfo.sn, node->devInfo.sn) == 0) {
                list_del_init(&tmp->list);
                disc_free_node(tmp);
                bingo = true;
             }
        }
    }

    node->outTime = 0;
    list_add_tail(&node->list, &g_neighbor_list);

    pthread_mutex_unlock(&g_list_mutex);
    
    if (bingo == false) {
        DISC_DEBUG("[Process] Find new neighbor: %s\n", node->devInfo.sn);
    }
    
    return 0;
}

static void disc_free_neighbor_list(void)
{
    dev_node_t *tmp, *n;

    pthread_mutex_lock(&g_list_mutex);
    
    if (list_empty(&g_neighbor_list)) {
        goto end;
    }

    list_for_each_entry_safe(tmp, n, &g_neighbor_list, list) {
       list_del_init(&tmp->list);
       disc_free_node(tmp);
    }

end:
    pthread_mutex_unlock(&g_list_mutex);
    return;
}

static int disc_foreach_neighbor_list(void)
{
    dev_node_t *tmp, *n;
    
    pthread_mutex_lock(&g_list_mutex);
    
    if (!list_empty(&g_neighbor_list)) {
        list_for_each_entry_safe(tmp, n, &g_neighbor_list, list) {
            if (tmp->outTime >= OUT_TIMES) {
                DISC_DEBUG("%s was offline\n", tmp->devInfo.sn);
                list_del_init(&tmp->list);
                disc_free_node(tmp);
            } else {
                tmp->outTime ++;
            }
        }
    }

    pthread_mutex_unlock(&g_list_mutex);

    return 0;
}

static int disc_get_ip_ifname(const char *iface, char** ip)
{
    int fd;
    struct ifreq ifr;

    if(iface == NULL) {
        DISC_ERROR("param error\n");
        return -1;
    }

    if (*ip != NULL) {
        free(*ip);
        *ip = NULL;
    }

    *ip = malloc(DISC_IP_LEN);
    if (*ip == NULL) {
        return -1;
    }
    memset(*ip, 0, DISC_IP_LEN);
    strncpy(*ip, "0.0.0.0", DISC_IP_LEN);
    
    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
		DISC_ERROR("socket() failed\n");
		return -1;
	}

    /* 获取接口信息 */
    memset(&ifr, 0, sizeof(ifr));
    snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", iface);
    if (ioctl(fd, SIOCGIFADDR, &ifr) < 0) {
        goto end;
    }

    strncpy(*ip, inet_ntoa(((struct sockaddr_in*)&(ifr.ifr_addr))->sin_addr), DISC_IP_LEN);

    /* 过滤10.44.77.254地址 */
    if(strcmp(*ip, "10.44.77.254") == 0) {
        memset(*ip, 0, DISC_IP_LEN);
        strcpy(*ip, "0.0.0.0");
    }

end:
    close(fd);

    return 0;
}

static int disc_get_role(void)
{
    role_t role;
    
    pthread_mutex_lock(&g_role_mutex);
    role = g_dev_cfg->role;
    pthread_mutex_unlock(&g_role_mutex);

    return role; 
}

static int disc_set_role(role_t role)
{
    pthread_mutex_lock(&g_role_mutex);
    g_dev_cfg->role = role;
    pthread_mutex_unlock(&g_role_mutex);

    return 0;
}

static int disc_uci_set_option(const char* package, const char* section, const char* option, const char* value)
{
    struct uci_context* ctx;
    struct uci_ptr ptr;
    
    memset(&ptr, 0, sizeof(struct uci_ptr));
    ptr.package = package;
    ptr.section = section;
    ptr.option = option;
    ptr.value = value;
    
    ctx = uci_alloc_context(); //申请上下文  
    if(ctx) {
        uci_set(ctx, &ptr); //写入配置  
        uci_commit(ctx, &ptr.p, false); //提交保存更改  
        uci_unload(ctx, ptr.p); //卸载包  
        uci_free_context(ctx); //释放上下文 
        return 0;
    }
    
    DISC_FILE("save config, package[%s], section[%s], option[%s], value[%s]\n",
            package, section, option, value);
    return -1;
}

static int disc_set_networkId(char* networkId)
{
    disc_uci_set_option(DISC_PKT_NAME, DISC_SCT_NAME, "networkId", networkId);

    if(g_dev_cfg->networkId) {
        free(g_dev_cfg->networkId);
    }
    g_dev_cfg->networkId = strdup(networkId);

    return 0;
}

static int disc_set_networkName(char* networkName){
    disc_uci_set_option(DISC_PKT_NAME, DISC_SCT_NAME, "networkName", networkName);

    if(g_dev_cfg->networkName) {
        free(g_dev_cfg->networkName);
    }
    g_dev_cfg->networkName = strdup(networkName);

    return 0;
}

static int disc_free_msg(disc_msg_t* msg)
{
    if (msg == NULL) {
        return 0;
    }

    if(msg->payload != NULL) {
        free(msg->payload);
        msg->payload = NULL;
    }

    free(msg);
    
    return 0;
}

static bool disc_queue_is_empty(void)
{
    if(g_queue_head == g_queue_tail) {
        return true;
    }
    
    return false;
}

static bool disc_queue_is_full(void)
{
    /* 判断为full,不是整个数组装满，牺牲一个节点 */ 
    /* 1.尾部大于头部,相减为 QUEUE_MAX_LEN -1表示队列满了 */
    if( g_queue_tail > g_queue_head  
        && (g_queue_tail - g_queue_head >= QUEUE_LEN -1)) {
        return true;
    }

    /* 2.尾部小于头部,头部减尾部为1，表示队列满 */
    if( g_queue_tail < g_queue_head  
        && (g_queue_head - g_queue_tail == 1)) {
        return true;
    }
    
    return false;
}

static int disc_queue_push(disc_msg_t* msg)
{
    if (msg == NULL) {
        DISC_ERROR("param error\n");
        return -1;
    }
        
    if(disc_queue_is_full() == true) {
        return -1;
    }

    g_msg_queue[g_queue_tail] = msg;
    g_queue_tail ++;
    
    if(g_queue_tail >= QUEUE_LEN) {
        g_queue_tail = 0;
    }

    return 0;
}

static disc_msg_t* disc_queue_pop(void)
{
    disc_msg_t* data;
    
    if(disc_queue_is_empty() == true) {
        return NULL;
    }

    data = g_msg_queue[g_queue_head];
    g_msg_queue[g_queue_head] = NULL;

    g_queue_head ++;
    if(g_queue_head >= QUEUE_LEN) {
        g_queue_head = 0;
    }
    
    return data; 
}

static int disc_reset(void)
{
    pthread_mutex_lock(&g_master_mutex);
    if(g_master_info->devInfo.role != NULL) {
        free(g_master_info->devInfo.role);
        g_master_info->devInfo.role = NULL;
    }

    if(g_master_info->devInfo.ip != NULL) {
        free(g_master_info->devInfo.ip);
        g_master_info->devInfo.ip = NULL;
    }

    if(g_master_info->devInfo.mac != NULL) {
        free(g_master_info->devInfo.mac);
        g_master_info->devInfo.mac = NULL;
    }

    if(g_master_info->devInfo.sn != NULL) {
        free(g_master_info->devInfo.sn);
        g_master_info->devInfo.sn = NULL;
    }

    if(g_master_info->devInfo.productModel != NULL) {
        free(g_master_info->devInfo.productModel);
        g_master_info->devInfo.productModel = NULL;
    }

    if(g_master_info->devInfo.networkId != NULL) {
        free(g_master_info->devInfo.networkId);
        g_master_info->devInfo.networkId = NULL;
    }

    if(g_master_info->devInfo.networkName != NULL) {
        free(g_master_info->devInfo.networkName);
        g_master_info->devInfo.networkName = NULL;
    }

    if(g_master_info->devInfo.software != NULL) {
        free(g_master_info->devInfo.software);
        g_master_info->devInfo.software = NULL;
    }

    if(g_master_info->devInfo.hardware != NULL) {
        free(g_master_info->devInfo.hardware);
        g_master_info->devInfo.hardware = NULL;
    }

    g_master_info->outTime = 0;
    pthread_mutex_unlock(&g_master_mutex);

    (void)disc_set_role(ROLE_UNKNOWN);
    g_declare_count = 0;
    
    return 0;
}

static int disc_read_dev_info(dev_info_t* dev_info)
{
    int ret = 0;
    struct json_object* root = NULL;
    struct json_object* node = NULL;
    const char* str;
    
    if (dev_info == NULL) {
        DISC_ERROR("param dev_info is NULL\n");
        return -1;
    }
    
    /* 判断设备信息文件是否存在 */
    if (access(DISC_DEVINFO_FILE, F_OK) != 0 ) {
        DISC_ERROR("Not find %s\n", DISC_DEVINFO_FILE);
        return -1;
    }

    root = json_object_from_file(DISC_DEVINFO_FILE);
    if (is_error(root)) {
        DISC_ERROR("Read device inform file failed, it's not json formate\n");
        ret = -1;
        goto end;
    }

    /* mac */
    node = json_object_object_get(root, "mac");
    if (node == NULL) {
        DISC_ERROR("Not find mac\n");
        goto end;
    }
    str = json_object_get_string(node);
    if (dev_info->mac != NULL) {
        free(dev_info->mac);
    }
    dev_info->mac = strdup(str);

    /* sn */
    node = json_object_object_get(root, "sn");
    if (node == NULL) {
        DISC_ERROR("Not find sn\n");
        goto end;
    }
    str = json_object_get_string(node);
    if (dev_info->sn != NULL) {
        free(dev_info->sn);
    }
    dev_info->sn = strdup(str);

    /* productModel */
    node = json_object_object_get(root, "productModel");
    if (node == NULL) {
        DISC_ERROR("Not find productModel\n");
        goto end;
    }
    str = json_object_get_string(node);
    if (dev_info->productModel != NULL) {
        free(dev_info->productModel);
    }
    dev_info->productModel = strdup(str);

    /* software */
    node = json_object_object_get(root, "software");
    if (node == NULL) {
        DISC_ERROR("Not find software\n");
        goto end;
    }
    str = json_object_get_string(node);
    if (dev_info->software != NULL) {
        free(dev_info->software);
    }
    dev_info->software = strdup(str);

    /* hardware */
    node = json_object_object_get(root, "hardware");
    if (node == NULL) {
        DISC_ERROR("Not find software\n");
        goto end;
    }
    str = json_object_get_string(node);
    if (dev_info->hardware != NULL) {
        free(dev_info->hardware);
    }
    dev_info->hardware = strdup(str);

    
end:
    if (root != NULL) {
         json_object_put(root);
    }
    
    return ret;
}

static role_t disc_string_to_role(const char* roleName)
{
    role_t role = ROLE_UNKNOWN;

    if(strcmp(roleName, "MASTER") == 0) {
        role = ROLE_MASTER;
        goto end;
    }

    if(strcmp(roleName, "SLAVER") == 0) {
        role = ROLE_SLAVER;
        goto end;
    }

end:
    return role;
}

static char* disc_role_to_string(role_t role)
{
    switch(role) {
        case ROLE_MASTER:
            return "MASTER";
        case ROLE_SLAVER:
            return "SLAVER";
        default:
            return "UNKNOWN";
    }
}

static int disc_reload_conf_file(dev_cfg_t* dev_cfg)
{
    struct uci_context *uci_ctx = NULL;
    struct uci_package *uci_pkg = NULL;
    struct uci_section *uci_scn = NULL;
    struct uci_element *e;
    struct uci_option  *op;
    bool bingo = false;

    if (dev_cfg == NULL) {
        DISC_ERROR("param dev_cfg is NULL\n");
        return -1;
    }

    /* 设置默认值 */
    dev_cfg->role           = ROLE_UNKNOWN;
    dev_cfg->port           = DISC_PORT_DEFAULT;
    dev_cfg->hello_enable   = false;
    dev_cfg->bcast_period   = 30;
    dev_cfg->networkId      = strdup("0");
    dev_cfg->networkName    = strdup("default");
    dev_cfg->ifname         = strdup("br-wan");
   
    uci_ctx = uci_alloc_context();
    if (!uci_ctx) {
        DISC_ERROR("Failed to alloc uci context\n");
        return -1;
    }

    if (uci_load(uci_ctx, DISC_PKT_NAME, &uci_pkg) != UCI_OK) {
        DISC_ERROR("Failed to load uci package\n");
        uci_free_context(uci_ctx);
        return -1;
    }

    uci_foreach_element(&uci_pkg->sections, e) {
        uci_scn = uci_to_section(e);
        if (uci_scn && (strcmp(uci_scn->type, DISC_SCT_NAME) == 0)) {
            bingo = true;
            break;
        }
   }

    if (bingo == true) {
        uci_foreach_element(&uci_scn->options, e) {
            op = uci_to_option(e);
            if (!op || (!op->e.name)) {
                continue;
            }

            /* networkId */
            if (!strcmp(op->e.name, "networkId") && strlen(op->v.string) <= NETWORKID_LEN) {
                if (dev_cfg->networkId != NULL) {
                    free(dev_cfg->networkId);
                }
                dev_cfg->networkId = strdup(op->v.string);
            }

            /* networkName */
            if (!strcmp(op->e.name, "networkName") && strlen(op->v.string) <= NETWORKNAME_LEN) {
                if (dev_cfg->networkName != NULL) {
                    free(dev_cfg->networkName);
                }
                dev_cfg->networkName = strdup(op->v.string);
            }

            /* role */
            if (!strcmp(op->e.name, "role")) {
                dev_cfg->role = disc_string_to_role(op->v.string);
            }

            /* port */
            if (!strcmp(op->e.name, "port")) {
                dev_cfg->port = atoi(op->v.string);
            }

            /* hello_enable */
            if (!strcmp(op->e.name, "hello_enable")) {
                if (strcmp(op->v.string, "true") == 0) {
                    dev_cfg->hello_enable = true;
                }
            }

            /* bcast_period */
            if (!strcmp(op->e.name, "bcast_period")) {
                dev_cfg->bcast_period = atoi(op->v.string);
                if (dev_cfg->bcast_period < 10) {
                    dev_cfg->bcast_period = 10;
                }
            }

            /* ifname */
            if (!strcmp(op->e.name, "ifname")) {
                if (dev_cfg->ifname != NULL) {
                    free(dev_cfg->ifname);
                }
                dev_cfg->ifname = strdup(op->v.string);
            }
        }
    }

    uci_unload(uci_ctx, uci_pkg);
    uci_free_context(uci_ctx);
    
    return 0;
}

static void disc_ubus_reconnect_timer(struct uloop_timeout *timeout)
{
    int t = 3;  /* 3秒重连 */
    static struct uloop_timeout retry = {
		.cb = disc_ubus_reconnect_timer,
	};
	
	if (ubus_reconnect(g_ubus_ctx, NULL) != 0) {
		DISC_ERROR("failed to reconnect, trying again in %d seconds\n", t);
		uloop_timeout_set(&retry, t * 1000);
		return;
	}

	DISC_FILE("reconnected to ubus success, new id: %08x\n", g_ubus_ctx->local_id);
	ubus_add_uloop(g_ubus_ctx);

    return;
}

static void disc_ubus_connection_lost(struct ubus_context *ctx)
{
	(void)disc_ubus_reconnect_timer(NULL);
    return;
}

static int disc_master_change_notify(const char* masterSn, const char* masterIp)
{
    char cmd[BUF_LEN] = {0};

    snprintf(cmd, sizeof(cmd), "%s '{\"masterSn\":\"%s\",\"masterIp\":\"%s\"}'", 
            MASTER_CHANGE_HOOK_SCRIPT, masterSn, masterIp);

    /* 执行命令 */
    system(cmd);
    
    return 0;
}

static int disc_update_master_info(dev_info_t* node)
{
    bool changed = false;
    
    pthread_mutex_lock(&g_master_mutex);

    if (g_master_info->devInfo.sn != NULL 
        && strcmp(g_master_info->devInfo.sn, node->sn) == 0
        && strcmp(g_master_info->devInfo.ip, node->ip) == 0 
        && strcmp(g_master_info->devInfo.networkName, node->networkName) == 0) {
        goto end;
    }
    
    /* role */
    if (g_master_info->devInfo.role != NULL) {
        free(g_master_info->devInfo.role);
    }
    g_master_info->devInfo.role = malloc(sizeof(role_t));
    *g_master_info->devInfo.role = *(node->role);

    /* ip */
    if (g_master_info->devInfo.ip != NULL) {
        free(g_master_info->devInfo.ip);
    }
    g_master_info->devInfo.ip = strdup(node->ip);

    /* mac */
    if (g_master_info->devInfo.mac != NULL) {
        free(g_master_info->devInfo.mac);
    }
    g_master_info->devInfo.mac = strdup(node->mac);

    /* sn */
    if (g_master_info->devInfo.sn != NULL) {
        free(g_master_info->devInfo.sn);
    }
    g_master_info->devInfo.sn = strdup(node->sn);

    /* productModel */
    if (g_master_info->devInfo.productModel != NULL) {
        free(g_master_info->devInfo.productModel);
    }
    g_master_info->devInfo.productModel = strdup(node->productModel);

    /* networkId */
    if (g_master_info->devInfo.networkId != NULL) {
        free(g_master_info->devInfo.networkId);
    }
    g_master_info->devInfo.networkId = strdup(node->networkId);

    /* networkName */
    if (g_master_info->devInfo.networkName != NULL) {
        free(g_master_info->devInfo.networkName);
    }
    g_master_info->devInfo.networkName = strdup(node->networkName);

    /* software */
    if (g_master_info->devInfo.software != NULL) {
        free(g_master_info->devInfo.software);
    }
    g_master_info->devInfo.software = strdup(node->software);

    /* hardware */
    if (g_master_info->devInfo.hardware != NULL) {
        free(g_master_info->devInfo.hardware);
    }
    g_master_info->devInfo.hardware = strdup(node->hardware);

    changed = true;

end:
    g_master_info->outTime = 0;
    pthread_mutex_unlock(&g_master_mutex);

    if (changed == true) {
        DISC_DEBUG("Update master info, [SN]: %s, [IP]%s\n", g_master_info->devInfo.sn, g_master_info->devInfo.ip);
        DISC_FILE("Found master, [SN]: %s, [IP]: %s\n", g_master_info->devInfo.sn, g_master_info->devInfo.ip);
        (void)disc_master_change_notify(g_master_info->devInfo.sn, g_master_info->devInfo.ip);
    }

    return 0;
}

static dev_node_t* disc_parse_payload(char* payload, enc_type_t encType, char** destSn)
{
    dev_node_t* devNode = NULL;
    struct json_object *root, *node;
    const char* str;

    root = json_tokener_parse(payload);
    if (is_error(root)) {
        DISC_ERROR("json_tokener_parse() failed\n");
        goto end;
    }
    
    devNode = (dev_node_t*)malloc(sizeof(dev_node_t));
    if (devNode == NULL) {
        DISC_ERROR("malloc() %d bytes failed\n", sizeof(dev_node_t));
        json_object_put(root);
        goto end;
    }
    memset(devNode, 0, sizeof(dev_node_t));

    /* destSn */
    if (destSn != NULL) {
        node = json_object_object_get(root, "destSn");
        if (node == NULL) {
            DISC_ERROR("Not find destSn\n");
            *destSn = NULL;
        } else {
            str = json_object_get_string(node);
            *destSn = strdup(str);
        }
    }

    /* sn */
    node = json_object_object_get(root, "sn");
    if (node == NULL) {
        DISC_ERROR("Not find sn\n");
        json_object_put(root);
        goto end;
    } else {
        str = json_object_get_string(node);
        devNode->devInfo.sn = strdup(str);
    }
    
    /* role */
    devNode->devInfo.role = malloc(sizeof(role_t));
    node = json_object_object_get(root, "role");
    if (node == NULL) {
        DISC_WARNING("Not find role\n");
        *(devNode->devInfo.role) = ROLE_UNKNOWN;
    } else {
        str = json_object_get_string(node);
        *(devNode->devInfo.role) = disc_string_to_role(str);
    }

    /* ip */
    node = json_object_object_get(root, "ip");
    if (node == NULL) {
        DISC_WARNING("Not find ip\n");
        devNode->devInfo.ip = strdup("0.0.0.0");
    } else {
        str = json_object_get_string(node);
        devNode->devInfo.ip = strdup(str);
    }
    
    /* mac */
    node = json_object_object_get(root, "mac");
    if (node == NULL) {
        DISC_WARNING("Not find mac\n");
        devNode->devInfo.mac = strdup("Unknown");
    } else {
        str = json_object_get_string(node);
        devNode->devInfo.mac = strdup(str);
    }

    /* productModel */
    node = json_object_object_get(root, "productModel");
    if (node == NULL) {
        DISC_WARNING("Not find productModel\n");
        devNode->devInfo.productModel = strdup("Unknown");
    } else {
        str = json_object_get_string(node);
        devNode->devInfo.productModel = strdup(str);
    }

    /* networkId */
    node = json_object_object_get(root, "networkId");
    if (node == NULL) {
        DISC_WARNING("Not find networkId\n");
        devNode->devInfo.networkId = strdup("0");
    } else {
        str = json_object_get_string(node);
        devNode->devInfo.networkId = strdup(str);
    }
    
    /* networkName */
    node = json_object_object_get(root, "networkName");
    if (node == NULL) {
        DISC_WARNING("Not find networkName\n");
        devNode->devInfo.networkName = strdup("Unknown");
    } else {
        str = json_object_get_string(node);
        devNode->devInfo.networkName = strdup(str);
    }

    /* software */
    node = json_object_object_get(root, "software");
    if (node == NULL) {
        DISC_WARNING("Not find software\n");
        devNode->devInfo.software = strdup("Unknown");
    } else {
        str = json_object_get_string(node);
        devNode->devInfo.software = strdup(str);
    }

    /* hardware */
    node = json_object_object_get(root, "hardware");
    if (node == NULL) {
        DISC_WARNING("Not find hardware\n");
        devNode->devInfo.hardware = strdup("Unknown");
    } else {
        str = json_object_get_string(node);
        devNode->devInfo.hardware = strdup(str);
    }

    json_object_put(root);
    
 end:
 
    return devNode;
}

static char* disc_parse_shell_msg(char* payload, enc_type_t encType, char** destSn)
{
    struct json_object *root, *node;
    const char* str;
    char* cmdsBuf = NULL;
    int len = 0;
    
    root = json_tokener_parse(payload);
    if (is_error(root)) {
        DISC_ERROR("json_tokener_parse() failed\n");
        goto end;
    }

    /* destSn */
    if (destSn != NULL) {
        node = json_object_object_get(root, "destSn");
        if (node == NULL) {
            DISC_ERROR("Not find destSn\n");
            *destSn = NULL;
        } else {
            str = json_object_get_string(node);
            *destSn = strdup(str);
        }
    }

    /* cmds */
    node = json_object_object_get(root, "cmds");
    if (node == NULL) {
        DISC_ERROR("Not find cmds\n");
        json_object_put(root);
        goto end;
    } else {
        str = json_object_get_string(node);
        len = strlen(str)+2;
        cmdsBuf = malloc(len);
        memset(cmdsBuf, 0, len);
        snprintf(cmdsBuf, len, "%s&", str);/* 追加一个&，避免命令执行卡住 */
    }
    
    json_object_put(root);
end:
    
    return cmdsBuf;
}

static int disc_handle_request(disc_msg_t* msg)
{
    dev_node_t* node = NULL;
    
    node = disc_parse_payload(msg->payload, msg->msgHdr.encType, NULL);
    if ( node == NULL) {
        return -1;
    }
    DISC_DEBUG("receive requset message from %s\n", node->devInfo.sn);

    if (strcmp(node->devInfo.networkId, g_dev_info->networkId) != 0 || *(node->devInfo.role) != ROLE_MASTER) {
        goto end;
    }

    switch (disc_get_role()) {
        case ROLE_MASTER:
            if(strcmp(g_dev_info->mac, node->devInfo.mac) > 0) {
                if (disc_send_merge(node->devInfo.sn) != 0) {
                    DISC_ERROR("Send merge message failed\n");
                }
            }
        break;
    
        case ROLE_SLAVER:
            (void)disc_update_master_info(&node->devInfo);
        break;

        case ROLE_UNKNOWN:
            (void)disc_set_role(ROLE_SLAVER);
            (void)disc_set_networkName(node->devInfo.networkName);
            (void)disc_update_master_info(&node->devInfo);
        break;
        
        default:
        break;
    }

end: 
    /* 回复response报文 */
    if (disc_send_response(node->devInfo.ip, node->devInfo.sn) == 0) {
        DISC_DEBUG("Send response message to %s\n", node->devInfo.sn);
    } else {
        DISC_ERROR("Send response message failed\n");
    }

    /* 更新邻居信息 */
    (void)disc_update_neighbor_info(node);
    
    return 0;
}

static int disc_handle_response(disc_msg_t* msg)
{
    dev_node_t* node = NULL;
    
    node = disc_parse_payload(msg->payload, msg->msgHdr.encType, NULL);
    if ( node == NULL) {
        return -1;
    }
    
    (void)disc_update_neighbor_info(node);
    
    return 0;
}

static int disc_handle_hello(disc_msg_t* msg)
{
    dev_node_t* node;
    
    node = disc_parse_payload(msg->payload, msg->msgHdr.encType, NULL);
    if ( node == NULL) {
        return -1;
    }
    DISC_DEBUG("receive hello message from %s\n", node->devInfo.sn);

    if (strcmp(node->devInfo.networkId, g_dev_info->networkId) != 0 || *(node->devInfo.role) != ROLE_MASTER) {
        goto end;
    }

    switch(disc_get_role()) {
        case ROLE_MASTER:
            if(strcmp(g_dev_info->mac, node->devInfo.mac) > 0) {
                if (disc_send_merge(node->devInfo.sn) != 0) {
                    DISC_ERROR("Send merge message failed\n");
                }
            }
        break;
        case ROLE_SLAVER:
            (void)disc_update_master_info(&node->devInfo);
        break;
        case ROLE_UNKNOWN:
            (void)disc_set_role(ROLE_SLAVER);
            (void)disc_set_networkName(node->devInfo.networkName);
            (void)disc_update_master_info(&node->devInfo);
            /* 信息变更后，广播一次hello报文，保证大家更新邻居信息 */
            (void)disc_send_hello(SN_BROADCAST);
            
            
        break;
        default:
        break;
    
    }


end:
    (void)disc_update_neighbor_info(node);
    
    return 0;
}

static int disc_handle_merge(disc_msg_t* msg)
{
    dev_node_t* node = NULL;
    char* destSn = NULL;
    
    node = disc_parse_payload(msg->payload, msg->msgHdr.encType, &destSn);
    if ( node == NULL || destSn == NULL) {
        return -1;
    }

    /* 判断消息是否是发送给自己的 */
    if(strcmp(destSn, SN_BROADCAST) != 0 && strcmp(destSn, g_dev_info->sn) != 0 ) {
        DISC_WARNING("The message is to me, drop it\n");
        return -1;
    }
    DISC_DEBUG("receive merge message from %s\n", node->devInfo.sn);

    /* 判读对方是否为master，不是master不处理发来的merge消息 */
    if (*(node->devInfo.role) != ROLE_MASTER) {
        goto end;
    }

    /* 更新自身角色和网络信息 */
    (void)disc_set_role(ROLE_SLAVER);
    (void)disc_set_networkId(node->devInfo.networkId);
    (void)disc_set_networkName(node->devInfo.networkName);
    (void)disc_update_master_info(&node->devInfo);
    /* 信息变更后，广播一次hello报文，保证大家更新邻居信息 */
    (void)disc_send_hello(SN_BROADCAST);
    DISC_FILE("Found master, [sn]: %s, [ip]: %s\n", g_master_info->devInfo.sn, g_master_info->devInfo.ip);

end:
    if (destSn) {
        free(destSn);
    }
    (void)disc_update_neighbor_info(node);

    return 0;
}

static int disc_handle_reject(disc_msg_t* msg)
{
    dev_node_t* node = NULL;
    char* destSn = NULL;
    
    node = disc_parse_payload(msg->payload, msg->msgHdr.encType, &destSn);
    if ( node == NULL || destSn == NULL) {
        return -1;
    }

    /* 根据destSn, 判断消息是否是发送给自己的 */
    if (strcmp(destSn, g_dev_info->sn) != 0 && strcmp(destSn, SN_BROADCAST) != 0) {
        goto end;
    }
    DISC_DEBUG("receive reject message from %s\n", node->devInfo.sn);
    
    /* 若networkId不同，则不处理reject报文 */
    if (strcmp(g_dev_info->networkId, node->devInfo.networkId) != 0) {
        goto end;
    }

    /* 若自身角为UNKNOWN，且对方为Master，则设置自身角色为Slaver */
    if (disc_get_role() == ROLE_UNKNOWN && *(node->devInfo.role) == ROLE_MASTER) {
        (void)disc_set_role(ROLE_SLAVER);
        (void)disc_set_networkName(node->devInfo.networkName); 
        (void)disc_update_master_info(&node->devInfo);
        /* 信息变更后，广播一次hello报文，保证大家更新邻居信息 */
        (void)disc_send_hello(SN_BROADCAST);
        DISC_FILE("Found master, [sn]: %s, [ip]: %s\n", g_master_info->devInfo.sn, g_master_info->devInfo.ip);
    }

    /* 收到reject报文，则清零g_declare_count */
    g_declare_count = 0;

end:
    (void)disc_update_neighbor_info(node);
    
    return 0;
}

static int disc_handle_declare(disc_msg_t* msg)
{
    dev_node_t* node;
    
    node = disc_parse_payload(msg->payload, msg->msgHdr.encType, NULL);
    if ( node == NULL) {
        return -1;
    }

    /* 若networkId不同，则不处理reject报文 */
    if (strcmp(g_dev_info->networkId, node->devInfo.networkId) != 0) {
        goto end;
    }

    /* 自身角色为master或自身mac地址更大，则发送reject报文 */
    if( disc_get_role() == ROLE_MASTER || strcmp(g_dev_info->mac, node->devInfo.mac) > 0) {
        if (disc_send_reject(node->devInfo.sn) != 0) {
            DISC_ERROR("Send reject message failed\n");
        } else {
            DISC_DEBUG("Send reject message to %s\n", node->devInfo.sn);
        }
    }

end:
    (void)disc_update_neighbor_info(node);
    
    return 0;
}

static int disc_handle_shell(disc_msg_t* msg)
{
    char* destSn = NULL;
    char* cmdsBuf = NULL;

    cmdsBuf = disc_parse_shell_msg(msg->payload, msg->msgHdr.encType, &destSn);
    if( cmdsBuf == NULL || destSn == NULL) {
        goto end;
    }
    
    /* 根据destSn, 判断消息是否是发送给自己的 */
    if (strcmp(destSn, g_dev_info->sn) != 0 && strcmp(destSn, SN_BROADCAST) != 0) {
        goto end;
    }
    DISC_DEBUG("receive shell message, [cmds]: %s\n", cmdsBuf);

    /* 执行命令 */
    system(cmdsBuf);

end:
    if (cmdsBuf) {
        free(cmdsBuf);
    }

    if (destSn) {
        free(destSn);
    }
    
    return 0;
}

static int disc_msg_handler(disc_msg_t* msg)
{
    if (msg == NULL) {
        return -1;
    }
    
    switch (msg->msgHdr.msgType) {
        case MSG_TYPE_DECLARE:
            disc_handle_declare(msg);
        break;
        case MSG_TYPE_REJECT:
            disc_handle_reject(msg);
        break;
        case MSG_TYPE_MERGE:
            disc_handle_merge(msg);
        break;
        case MSG_TYPE_HELLO:
            disc_handle_hello(msg);
        break;
        case MSG_TYPE_REQUEST:
            disc_handle_request(msg);
        break;
        case MSG_TYPE_RESPONSE:
            disc_handle_response(msg);
        break;
        case MSG_TYPE_SHELL:
            disc_handle_shell(msg);
        break;
        default:
            DISC_ERROR("Unknown msgType\n");
        break;

    }
    
    return 0;
}

static int disc_read_interface(const char *interface, int *ifindex, uint32_t *nip, uint8_t *mac)
{
	int fd;
	struct sockaddr_in *our_ip;
    char ifr_buf[sizeof(struct ifreq)];
	struct ifreq *const ifr = (void *)ifr_buf;

	memset(ifr, 0, sizeof(*ifr));
	fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (fd < 0) {
		DISC_WARNING("socket() failed\n");
		return -1;
	}
    
	ifr->ifr_addr.sa_family = AF_INET;
	snprintf(ifr->ifr_name, IFNAMSIZ, "%s", interface);
    
	if (nip) {
		if (ioctl(fd, SIOCGIFADDR, ifr) != 0) {
            DISC_WARNING("ioctl() fail\n");
			close(fd);
			return -1;
		}
		our_ip = (struct sockaddr_in *) &ifr->ifr_addr;
		*nip = our_ip->sin_addr.s_addr;
        //DISC_DEBUG("IP: %s\n", inet_ntoa(our_ip->sin_addr));
	}

	if (ifindex) {
		if (ioctl(fd, SIOCGIFINDEX, ifr) != 0) {
            DISC_WARNING("ioctl() fail\n");
			close(fd);
			return -1;
		}
		//DISC_DEBUG("Adapter index: %d\n", ifr->ifr_ifindex);
		*ifindex = ifr->ifr_ifindex;
	}

	if (mac) {
		if (ioctl(fd, SIOCGIFHWADDR, ifr) != 0) {
            DISC_WARNING("ioctl() fail\n");
			close(fd);
			return -1;
		}
		memcpy(mac, ifr->ifr_hwaddr.sa_data, 6);
        //DISC_DEBUG("MAC: %02x:%02x:%02x:%02x:%02x:%02x\n", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
	}

	close(fd);
	return 0;
}

#if 0
static int disc_raw_socket(const char *interface)
{
    int fd;
	struct sockaddr_ll sock;
	int opt;
    int ifindex;
    struct timeval tv;
    
    /*
    过滤指定报文：udp and dst port 36521    
    root@MACC000023456:~# tcpdump -dd udp dst port 36521
        { 0x28, 0, 0, 0x0000000c },
        { 0x15, 0, 4, 0x000086dd },
        { 0x30, 0, 0, 0x00000014 },
        { 0x15, 0, 11, 0x00000011 },
        { 0x28, 0, 0, 0x00000038 },
        { 0x15, 8, 9, 0x00008ea9 },
        { 0x15, 0, 8, 0x00000800 },
        { 0x30, 0, 0, 0x00000017 },
        { 0x15, 0, 6, 0x00000011 },
        { 0x28, 0, 0, 0x00000014 },
        { 0x45, 4, 0, 0x00001fff },
        { 0xb1, 0, 0, 0x0000000e },
        { 0x48, 0, 0, 0x00000010 },
        { 0x15, 0, 1, 0x00008ea9 },
        { 0x6, 0, 0, 0x0000ffff },
        { 0x6, 0, 0, 0x00000000 },
    */
    struct sock_filter filter_instr[] = {
        { 0x28, 0, 0, 0x0000000c },
        { 0x15, 0, 4, 0x000086dd },
        { 0x30, 0, 0, 0x00000014 },
        { 0x15, 0, 11, 0x00000011 },
        { 0x28, 0, 0, 0x00000038 },
        { 0x15, 8, 9, 0x00008ea9 },
        { 0x15, 0, 8, 0x00000800 },
        { 0x30, 0, 0, 0x00000017 },
        { 0x15, 0, 6, 0x00000011 },
        { 0x28, 0, 0, 0x00000014 },
        { 0x45, 4, 0, 0x00001fff },
        { 0xb1, 0, 0, 0x0000000e },
        { 0x48, 0, 0, 0x00000010 },
        { 0x15, 0, 1, 0x00008ea9 },
        { 0x6, 0, 0, 0x0000ffff },
        { 0x6, 0, 0, 0x00000000 },
	};
        
    struct sock_fprog filter_prog = {
		.len = sizeof(filter_instr) / sizeof(filter_instr[0]),
		.filter = (struct sock_filter *) filter_instr,
	};

    fd = socket(PF_PACKET, SOCK_DGRAM, htons(ETH_P_IP));
    if (fd < 0) {
         DISC_ERROR("socket create failed\n");
        return -1;
    }

    if(disc_read_interface(interface, &ifindex, NULL, NULL) != 0) {
        DISC_ERROR("disc_read_interface failed\n");
        close(fd);
        return -1;
    }
    sock.sll_family = AF_PACKET;
	sock.sll_protocol = htons(ETH_P_IP);
	sock.sll_ifindex = ifindex;
    
	if (bind(fd, (struct sockaddr*)&sock, sizeof(sock)) != 0) {
        DISC_ERROR("socket bind failed\n");
        close(fd);
        return -1;
    }

    if (setsockopt(fd, SOL_SOCKET, SO_ATTACH_FILTER, &filter_prog, sizeof(filter_prog)) != 0) {
        DISC_ERROR("socket option set SO_ATTACH_FILTER failed\n");
        close(fd);
        return -1;
    }

    opt = 1;
	if (setsockopt(fd, SOL_PACKET, PACKET_AUXDATA, &opt, sizeof(opt)) != 0) {
        DISC_ERROR("socket option set PACKET_AUXDATA failed\n");
        close(fd);
        return -1;
    }

    /* 设置超时接收：2个广播周期 */ 
    tv.tv_sec = g_dev_cfg->bcast_period * 2;  
    tv.tv_usec = 0;
    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) != 0) {   
        DISC_ERROR("socket option set SO_RCVTIMEO failed\n");
        close(fd);
        return -1; 
    } 
    
    return fd;
}
#endif

static int disc_create_recv_socket(void) 
{
    int opt = 1;
    int fd  = -1;
    struct sockaddr_in server_addr;
    struct timeval tv;
    
    fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0) {
		DISC_ERROR("socket() failed\n");
		return -1;
	}

    /* 设置超时接收：2个广播周期 */ 
    tv.tv_sec = g_dev_cfg->bcast_period * 2;  
    tv.tv_usec = 0;
    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) != 0) {   
        DISC_ERROR("socket option set SO_RCVTIMEO failed\n");
        close(fd);
        return -1; 
    } 

    /* 端口复用 */
    if(setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) != 0)
    {
        DISC_ERROR("setsockopt() failed\n");
        close(fd);
        return -1;
    }

    /* 指定网络接口 
    memset(&ifr, 0x00, sizeof(ifr));
    snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), mqtt_disc_get_ifname());
    if(setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, (char *)&ifr, sizeof(ifr)) != 0)
    {
        MQTT_DISC_ERROR("setsockopt() failed\n");
        close(fd);
        return -1;
    }*/

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(g_dev_cfg->port);
    server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
 
    if (bind(fd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        DISC_ERROR("bind() failed");
        close(fd);
        return -1;
    }

    return fd;
}

static uint16_t disc_checksum(void *addr, int count)
{
	/* Compute Internet Checksum for "count" bytes
	 * beginning at location "addr".
	 */
	int32_t sum = 0;
	uint16_t *source = (uint16_t *) addr;

	while (count > 1)  {
		/*  This is the inner loop */
		sum += *source++;
		count -= 2;
	}

	/*  Add left-over byte, if any */
	if (count > 0) {
		/* Make sure that the left-over byte is added correctly both
		 * with little and big endian hosts */
		uint16_t tmp = 0;
		*(uint8_t*)&tmp = *(uint8_t*)source;
		sum += tmp;
	}
    
	/*  Fold 32-bit sum to 16 bits */
	while (sum >> 16) {
        sum = (sum & 0xffff) + (sum >> 16);
    }	

	return ~sum;
}

static int disc_send_raw_packet(char* data, int data_len,uint32_t source_nip, int source_port,
		uint32_t dest_nip, int dest_port, const uint8_t *dest_arp, int ifindex)
{
    int fd = 0;
	int len = 0;
    int p_len = 0;
    int ret = 0;
	struct sockaddr_ll dest_sll;
	packet_hdr_t packet_hdr;
	char* packet = NULL;
    struct iphdr*  ipHdr = NULL;
    struct udphdr* udpHdr = NULL;

    if (data == NULL) {
        DISC_ERROR("param is NULL\n");
		return -1;
    }
    p_len = data_len;

    //DISC_DEBUG("data p_len: %d \n", p_len);
    
	fd = socket(PF_PACKET, SOCK_DGRAM, htons(ETH_P_IP));
	if (fd < 0) {
		DISC_ERROR("socket() failed\n");
		return -1;
	}

	memset(&dest_sll, 0, sizeof(dest_sll));
	memset(&packet_hdr, 0, sizeof(packet_hdr_t));

	dest_sll.sll_family = AF_PACKET;
	dest_sll.sll_protocol = htons(ETH_P_IP);
	dest_sll.sll_ifindex = ifindex;
	dest_sll.sll_halen = 6;
	memcpy(dest_sll.sll_addr, dest_arp, 6);

	if (bind(fd, (struct sockaddr *)&dest_sll, sizeof(dest_sll)) < 0) {
        DISC_ERROR("bind() failed\n");
        ret = -1;
        goto end;
	}

    len = sizeof(struct iphdr) + sizeof(struct udphdr) + data_len;
    packet = (char*)malloc(len);
    if (packet == NULL) {
        DISC_ERROR("malloc %d bytes failed\n", len);
        ret = -1;
        goto end;
    }
    memset(packet, 0, len);
    memcpy(packet + sizeof(struct iphdr) + sizeof(struct udphdr), data, data_len);

    ipHdr = (struct iphdr*)packet;
    udpHdr = (struct udphdr*)(packet + sizeof(struct iphdr));

	ipHdr->protocol = IPPROTO_UDP;
	ipHdr->saddr = source_nip;
	ipHdr->daddr = dest_nip;
	udpHdr->source = htons(source_port);
	udpHdr->dest = htons(dest_port);
	p_len += sizeof(struct udphdr);
	udpHdr->len = htons(p_len);
	ipHdr->tot_len = udpHdr->len;
	p_len += sizeof(struct iphdr);
	udpHdr->check = disc_checksum(packet, p_len);
	ipHdr->tot_len = htons(p_len);
	ipHdr->ihl = sizeof(struct iphdr) >> 2;
	ipHdr->version = IPVERSION;
	ipHdr->ttl = IPDEFTTL;
	ipHdr->check = disc_checksum(ipHdr, sizeof(struct iphdr));

	len = sendto(fd, packet, p_len, 0, (struct sockaddr *) &dest_sll, sizeof(dest_sll));

	if (len < 0) {
		DISC_ERROR("sendto() failed \n");
        ret = -1;
        goto end;
	}
    
    //DISC_DEBUG("send discover packet success,data lenth: %d\n", len);
    
end:
    if (packet != NULL) {
        free(packet);
    }

    if (fd != 0) {
        close(fd);
    }
    
    
	return ret;    
}

static int disc_get_msg_payload(char** payload, int* payloadLen, enc_type_t encType, const char* destSn) 
{
    struct json_object *root;
    const char* str;

    if (destSn == NULL) {
        DISC_ERROR("destSn is NULL\n");
        return -1;
    }
    
    root = json_object_new_object();
    if (root == NULL) {
        DISC_ERROR("json_object_new_object() failed\n");
        return -1;
    }

    /* 发送对象的SN, FFFFFFFFFFFF表示所有对象 */
    json_object_object_add(root, "destSn", json_object_new_string(destSn)); 
    json_object_object_add(root, "role", json_object_new_string(disc_role_to_string(g_dev_cfg->role)));
    (void)disc_get_ip_ifname("br-wan", &g_dev_info->ip);
    json_object_object_add(root, "ip", json_object_new_string(g_dev_info->ip));
    json_object_object_add(root, "mac", json_object_new_string(g_dev_info->mac));
    json_object_object_add(root, "sn", json_object_new_string(g_dev_info->sn));
    json_object_object_add(root, "productModel", json_object_new_string(g_dev_info->productModel));
    json_object_object_add(root, "networkId", json_object_new_string(g_dev_info->networkId));
    json_object_object_add(root, "networkName", json_object_new_string(g_dev_info->networkName));
    json_object_object_add(root, "software", json_object_new_string(g_dev_info->software));
    json_object_object_add(root, "hardware", json_object_new_string(g_dev_info->hardware));

    str = json_object_to_json_string(root);

    *payloadLen = strlen(str);
    *payload = strdup(str);

    //DISC_DEBUG("payload: %s\n", *payload);
    
    json_object_put(root);
    
    return 0;
}      

static int disc_send_broadcast_msg(disc_msg_t* msg, const char* destSn)
{
    int len = 0;
    char send_buf[BUF_LEN] = {0};
    int ifindex;
    uint8_t MAC_BCAST_ADDR[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

    len = sizeof(disc_msg_hdr_t) + msg->msgHdr.payloadLen;
    if (len > BUF_LEN) {
        DISC_ERROR("msg length is big than %d, drop it\n", BUF_LEN);
        return -1;
    }
    
    msg->msgHdr.version = htonl(msg->msgHdr.version);
    msg->msgHdr.msgType = htonl(msg->msgHdr.msgType);
    msg->msgHdr.encType = htonl(msg->msgHdr.encType);
    msg->msgHdr.payloadLen = htonl(msg->msgHdr.payloadLen);
    
    memset(send_buf, 0, BUF_LEN);
    memcpy(send_buf, &msg->msgHdr, sizeof(msg->msgHdr));
    memcpy(send_buf+sizeof(msg->msgHdr), msg->payload, len-sizeof(msg->msgHdr));
    //DISC_DEBUG("Send msg->payload: %s\n", send_buf+sizeof(msg->msgHdr));

    if (disc_read_interface(g_dev_cfg->ifname, &ifindex, NULL, NULL) != 0) {
        DISC_ERROR("disc_read_interface() failed\n");
        return -1;
    }
    
    return disc_send_raw_packet(send_buf, len, INADDR_ANY, g_dev_cfg->port+1, 
                INADDR_BROADCAST, g_dev_cfg->port, MAC_BCAST_ADDR, ifindex);    
}

static int disc_send_unicast_msg(disc_msg_t* msg, const char* destIp)
{
    int ret = 0;
    int len = 0;
    char send_buf[BUF_LEN] = {0};
    int opt = 1;
    int sockfd = -1;
    struct sockaddr_in dest_addr;

    len = sizeof(disc_msg_hdr_t) + msg->msgHdr.payloadLen;
    if (len > BUF_LEN) {
        DISC_ERROR("msg length is big than %d, drop it\n", BUF_LEN);
        return -1;
    }

    msg->msgHdr.version = htonl(msg->msgHdr.version);
    msg->msgHdr.msgType = htonl(msg->msgHdr.msgType);
    msg->msgHdr.encType = htonl(msg->msgHdr.encType);
    msg->msgHdr.payloadLen = htonl(msg->msgHdr.payloadLen);

    memset(send_buf, 0, BUF_LEN);
    memcpy(send_buf, &msg->msgHdr, sizeof(msg->msgHdr));
    memcpy(send_buf+sizeof(msg->msgHdr), msg->payload, len-sizeof(msg->msgHdr));
    
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (sockfd < 0) {
		DISC_ERROR("socket() failed\n");
		return -1;
	}

    /* 允许端口复用 */
    if(setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) != 0) {
        DISC_ERROR("setsockopt() failed\n");
        close(sockfd);
        return -1;
    }

    memset(&dest_addr, 0, sizeof(dest_addr));
	dest_addr.sin_family = AF_INET;
	dest_addr.sin_port = htons(g_dev_cfg->port);
    dest_addr.sin_addr.s_addr=inet_addr(destIp);
    
    len = sendto(sockfd, send_buf, len, 0, (struct sockaddr*)&dest_addr, sizeof(dest_addr));
    if (len < 0) {
        if(errno == EAGAIN) {
            DISC_ERROR("sendto() time out.\n");
        } else {
            DISC_ERROR("sendto() failed, erron reason: %s.\n", strerror(errno));  
        }
        ret = -1;
        goto end;
    }

    ret = 0;
    
end:
    if (sockfd != -1) {
        close(sockfd);
    }
    
    return ret;  
}

#if 0
static int disc_send_msg(msg_type_t msgType, const char* destIp, const char* destSn)
{
    int ret = 0;
    disc_msg_t* msg = NULL;
    /* 若自身或对方没有IP时，则通过广播发送，否则通过单播发送 */
    if (strcmp(destIp, "0.0.0.0") == 0 || strcmp(g_dev_info->ip, "0.0.0.0") == 0) {
        ret = disc_send_broadcast_msg(msgType, destSn);
        if (ret != 0) {
            DISC_ERROR("Send broadcast msg failed\n");
        }
    } else {
        ret = disc_send_unicast_msg(msgType, destIp);
        if (ret != 0) {
            DISC_ERROR("Send unicast msg failed, dest ip: [%s]\n", destIp);
        }
    }

    return ret;
}
#endif
static int disc_send_msg(msg_type_t msgType, enc_type_t encType, const char* destSn)
{
    int ret = 0;
    disc_msg_t msg;

    memset(&msg, 0, sizeof(disc_msg_t));
    msg.msgHdr.version = VERISON_DEFAULT;
    msg.msgHdr.msgType = msgType;
    msg.msgHdr.encType = encType;
    msg.msgHdr.payloadLen = 0;
    msg.payload = NULL;

    if(disc_get_msg_payload(&msg.payload, &msg.msgHdr.payloadLen, msg.msgHdr.encType, destSn) != 0 ) {
        DISC_ERROR("Get msg payload failed\n");
        ret =  -1;
        goto end;
    }
    
    if (disc_send_broadcast_msg(&msg, destSn) != 0) {
        DISC_ERROR("Send broadcast msg failed\n");
        ret = -1;
    }

end:
    if (msg.payload) {
        free(msg.payload);  
    }
    
    return ret;
}

static int disc_send_declare(const char* destSn) 
{
    return disc_send_msg(MSG_TYPE_DECLARE, ENC_TYPE_NONE, destSn);
}

static int disc_send_reject(const char* destSn)
{
    return disc_send_msg(MSG_TYPE_REJECT, ENC_TYPE_NONE, destSn);;
}

static int disc_send_merge(const char* destSn)
{
    return disc_send_msg(MSG_TYPE_MERGE, ENC_TYPE_NONE, destSn);;
}

static int disc_send_hello(const char* destSn)
{
    return disc_send_msg(MSG_TYPE_HELLO, ENC_TYPE_NONE, destSn);;
}

static int disc_send_request(const char* destSn)
{
    return disc_send_msg(MSG_TYPE_REQUEST, ENC_TYPE_NONE, destSn);;
}

static int disc_send_response(const char* destIp,const char* destSn)
{
    int ret = 0;
    disc_msg_t msg;

    memset(&msg, 0, sizeof(disc_msg_t));
    msg.msgHdr.version = VERISON_DEFAULT;
    msg.msgHdr.msgType = MSG_TYPE_RESPONSE;
    msg.msgHdr.encType = ENC_TYPE_NONE;
    msg.msgHdr.payloadLen = 0;
    msg.payload = NULL;

    if(disc_get_msg_payload(&msg.payload, &msg.msgHdr.payloadLen, msg.msgHdr.encType, destSn) != 0 ) {
        DISC_ERROR("Get msg payload failed\n");
        ret =  -1;
        goto end;
    }
    
    /* 若自身或对方没有IP时，则通过广播发送，否则通过单播发送 */
    if (strcmp(destIp, "0.0.0.0") == 0 || strcmp(g_dev_info->ip, "0.0.0.0") == 0) {
        ret = disc_send_broadcast_msg(&msg, destSn);
        if (ret != 0) {
            DISC_ERROR("Send broadcast msg failed\n");
            ret =  -1;
        }
    } else {
        ret = disc_send_unicast_msg(&msg, destIp);
        if (ret != 0) {
            DISC_ERROR("Send unicast msg failed, dest ip: [%s]\n", destIp);
            ret =  -1;
        }
    }

end:
    if (msg.payload) {
        free(msg.payload);  
    }
    
    return ret;
}

static int disc_get_shell_payload(char** payload, int* payloadLen, enc_type_t encType, 
    const char* cmds, const char* destSn)
{
    struct json_object *root;
    const char* str;

    if (destSn == NULL) {
        DISC_ERROR("destSn is NULL\n");
        return -1;
    }
    
    root = json_object_new_object();
    if (root == NULL) {
        DISC_ERROR("json_object_new_object() failed\n");
        return -1;
    }

    /* 发送对象的SN, FFFFFFFFFFFF表示所有对象 */
    json_object_object_add(root, "destSn", json_object_new_string(destSn)); 
    json_object_object_add(root, "cmds", json_object_new_string(cmds));

    str = json_object_to_json_string(root);

    *payloadLen = strlen(str);
    *payload = strdup(str);

    //DISC_DEBUG("payload: %s\n", *payload);
    
    json_object_put(root);

    return 0;
}

static int disc_send_shell(const char* cmds, const char* destSn)
{
    int ret = 0;
    disc_msg_t msg;

    memset(&msg, 0, sizeof(disc_msg_t));
    msg.msgHdr.version = VERISON_DEFAULT;
    msg.msgHdr.msgType = MSG_TYPE_SHELL;
    msg.msgHdr.encType = ENC_TYPE_NONE;
    msg.msgHdr.payloadLen = 0;
    msg.payload = NULL;

    if(disc_get_shell_payload(&msg.payload, &msg.msgHdr.payloadLen, msg.msgHdr.encType, cmds, destSn) != 0 ) {
        DISC_ERROR("Get shell payload failed\n");
        ret =  -1;
        goto end;
    }

    if (disc_send_broadcast_msg(&msg, destSn) != 0) {
        DISC_ERROR("Send broadcast msg failed\n");
        ret = -1;
    }
        
end:
    if (msg.payload) {
        free(msg.payload);  
    }
    
    return ret;
}

static int disc_param_init(void)
{
    /* 设备信息 */
    g_dev_info = (dev_info_t*)malloc(sizeof(dev_info_t));
    if (g_dev_info == NULL) {
        DISC_ERROR("malloc() %d byte failed\n", sizeof(dev_info_t));
        return -1;
    }
    memset(g_dev_info, 0, sizeof(dev_info_t));

    /* master信息 */
    g_master_info = (dev_node_t*)malloc(sizeof(dev_node_t));
    if (g_master_info == NULL) {
        DISC_ERROR("malloc() %d byte failed\n", sizeof(dev_node_t));
        return -1;
    }
    memset(g_master_info, 0, sizeof(dev_node_t));
    
    /* 设备配置信息 */
    g_dev_cfg = (dev_cfg_t*)malloc(sizeof(dev_cfg_t));
    if (g_dev_cfg == NULL) {
        DISC_ERROR("malloc() %d byte failed\n", sizeof(dev_cfg_t));
        return -1;
    }
    memset(g_dev_cfg, 0, sizeof(dev_cfg_t));

    /* 定时器 */
    g_send_timer = (struct uloop_timeout*)malloc(sizeof(struct uloop_timeout));
    if (g_send_timer == NULL) {
        DISC_ERROR("malloc() %d byte failed\n", sizeof(struct uloop_timeout));
        return -1;
    }
    memset(g_send_timer, 0, sizeof(struct uloop_timeout));

    /* 逾期定时器 */
    g_age_timer = (struct uloop_timeout*)malloc(sizeof(struct uloop_timeout));
    if (g_age_timer == NULL) {
        DISC_ERROR("malloc() %d byte failed\n", sizeof(struct uloop_timeout));
        return -1;
    }
    memset(g_age_timer, 0, sizeof(struct uloop_timeout));
    
    /* uloop文件描述符 */
    g_fd = (struct uloop_fd*)malloc(sizeof(struct uloop_fd));
    if (g_fd == NULL) {
        DISC_ERROR("malloc() %d byte failed\n", sizeof(struct uloop_fd));
        return -1;
    }
    memset(g_fd, 0, sizeof(struct uloop_fd));


    return 0;
}

static int disc_ubus_init(void)
{
    struct ubus_object* dbg_obj;
    
    g_ubus_ctx = ubus_connect(NULL);
    if (g_ubus_ctx == NULL) {
        DISC_ERROR("Failed to connect to ubus!\n");
        return -1;
    }

    g_ubus_ctx->connection_lost = disc_ubus_connection_lost;
    ubus_add_uloop(g_ubus_ctx);

    /* 添加debug ubus 对象*/
    dbg_obj = dbg_get_ubus_object();
    if (dbg_obj == NULL) {
        DISC_ERROR("Failed to get debug ubus object\n");
        return -1;
    }
    
    if (ubus_add_object(g_ubus_ctx, dbg_obj)) {
        DISC_ERROR("Failed to add debug ubus object\n");
        return -1;
    }
    
    if (ubus_add_object(g_ubus_ctx, &disc_object)) {
        DISC_ERROR("Failed to add ubus object\n");
        return -1;
    }


    DISC_FILE("disc_ubus_init() success!\n");

    return 0;
}

static int disc_debug_init(void)
{
    if (dbg_init("discovery", DISC_LOG_FILE, DISC_LOG_SIZE) != 0) {
        fprintf(stderr, "ERROR: debug init failed in %s on %d lines\n", __FILE__, __LINE__);
        return -1;
    }
    
    g_md_id = dbg_module_reg("main");
    if(g_md_id < 0) {
        fprintf(stderr, "ERROR: register debug module failed in %s on %d lines\n", __FILE__, __LINE__);
        return -1;
    }

    DISC_FILE("\n------------------------- Start disc -------------------------\n");
    DISC_FILE("dbg_init() success\n");

    return 0;
}

static int disc_master_expire_check(void)
{
    if (disc_get_role() == ROLE_SLAVER ) { 
        g_master_info->outTime ++;
        if (g_master_info->outTime >= OUT_TIMES) {
            DISC_DEBUG("Master was offline, rediscovery now\n");
            (void)disc_reset();
        }
    }
    return 0;
}

static void disc_send_timer_cb(struct uloop_timeout *timer)
{
    switch(disc_get_role()) {
        case ROLE_UNKNOWN:
            /* 若连续3个declare，为收到reject, 则自身为master */
            if (g_declare_count >= 3) {
                g_declare_count = 0;
                (void)disc_set_role(ROLE_MASTER);
                if (g_dev_info->ip != NULL) {
                    free(g_dev_info->ip);
                }
                g_dev_info->ip = strdup("127.0.0.1");
                (void)disc_update_master_info(g_dev_info);
                /* 立即发送一个request报文，加快组网和邻居信息更新 */
                (void)disc_send_request(SN_BROADCAST);
                goto end;
            } 
            
             if (disc_send_declare(SN_BROADCAST) == 0){
                g_declare_count ++;
                DISC_DEBUG("Send delcare message %d times\n", g_declare_count);
            }else {
                DISC_ERROR("Send delcare message failed\n");
            }            
        break;
        case ROLE_MASTER:
            if (disc_send_request(SN_BROADCAST) == 0) {
                DISC_DEBUG("Send request message success\n");
            } else {
                DISC_ERROR("Send request message failed\n");
            }
        break;
        case ROLE_SLAVER:
            if (g_dev_cfg->hello_enable == true) {
                if (disc_send_hello(SN_BROADCAST) == 0) {
                    DISC_DEBUG("Send hello message success\n");
                } else {
                    DISC_ERROR("Send hello message failed\n");
                }
            }
        break;
        default:
        break;
    }

end:
    if (disc_get_role() == ROLE_UNKNOWN) {
        /* 角色未确定前，定时器设置为 3S */
            uloop_timeout_set(g_send_timer, 3 * 1000);
    } else {
        /* 角色确定后，定时器设置为 bcast_period */
        uloop_timeout_set(g_send_timer, g_dev_cfg->bcast_period * 1000);
    }

    return;
}

static void disc_age_timer_cb(struct uloop_timeout *timer)
{
    (void)disc_foreach_neighbor_list();
    (void)disc_master_expire_check();
    
    uloop_timeout_set(g_age_timer, g_dev_cfg->bcast_period * 1000);

    return;
}

static void* disc_uloop_pthread(void* arg)
{
    /* 设置线程名称 */
    prctl(PR_SET_NAME, "uloop_thread");

    /* 设置send定时器: 初始值5秒 */
    g_send_timer->cb = disc_send_timer_cb;
    uloop_timeout_set(g_send_timer, 5 * 1000);
    DISC_FILE("Add send timer success\n");

    /* 设置age定时器: 默认值 */
    g_age_timer->cb = disc_age_timer_cb;
    uloop_timeout_set(g_age_timer, g_dev_cfg->bcast_period * 1000);
    DISC_FILE("Add age timer success\n");
    
    uloop_run();
    uloop_done();

    return NULL;
}

static void* disc_receive_pthread(void* arg)
{
    int fd;
    int recv_len;
    char recv_buf[BUF_LEN];
    struct sockaddr_in client_addr;
	socklen_t sockaddr_len = sizeof(client_addr);
    disc_msg_t* msg;
    disc_msg_hdr_t* msgHdr;
    //char* ifname = (char*)arg;
    
    /* 设置线程名称 */
    prctl(PR_SET_NAME, "recv_thread");

    //fd = disc_raw_socket(ifname);
    fd = disc_create_recv_socket();
    if(fd == -1) {
        DISC_ERROR("[Recieve] Create recv socket fail, exit now.\n");
        exit(1);
    }

    while(1) {
        /* 非完全阻塞，超时接收 */
        memset(recv_buf, 0, BUF_LEN);
        recv_len = recvfrom(fd, recv_buf, BUF_LEN, 0, (struct sockaddr*)&client_addr, &sockaddr_len);
        if(recv_len < 0) {
            if (errno == EWOULDBLOCK || errno == EAGAIN) {
                DISC_WARNING("[Recieve] Recieve pthread timeout...\n");
                continue;
            } else {
                /* socket异常，退出程序，由监控程序拉起 */
                DISC_ERROR("[Recieve] Recv socket[%d] error, eixt now\n",fd);
                exit(-1);
            }
        }

        /* 检查获取消息类型 */
        msgHdr = (disc_msg_hdr_t*)recv_buf;
        if (ntohl(msgHdr->msgType) >= MSG_TYPE_MAX) {
           DISC_WARNING("[Recieve] illegal msgType[%d], drop it\n", msgHdr->msgType); 
           continue;
        }

        /* 检查获取消息长度 */
        if (ntohl(msgHdr->payloadLen) != recv_len - sizeof(disc_msg_hdr_t)) {
           DISC_WARNING("[Recieve] illegal payload length[%d], drop it\n", msgHdr->msgType); 
           continue;
        }

        /* 组装消息 */        
        msg = (disc_msg_t*)malloc(sizeof(disc_msg_t));
        if (msg == NULL) {
            DISC_ERROR("[Recieve] malloc %d bytes failed, eixt now\n", sizeof(disc_msg_t));
            exit(-1);
        }
        memset(msg, 0, sizeof(disc_msg_t));
        msg->msgHdr.version = ntohl(msgHdr->version);
        msg->msgHdr.msgType = ntohl(msgHdr->msgType);
        msg->msgHdr.encType = ntohl(msgHdr->encType);
        msg->msgHdr.payloadLen = ntohl(msgHdr->payloadLen);
        //DISC_DEBUG("recv msg: %s\n", recv_buf + sizeof(disc_msg_hdr_t));
        
        msg->payload = (char*)malloc(msg->msgHdr.payloadLen+1);
        if (msg->payload == NULL) {
            DISC_ERROR("[Recieve] malloc %d bytes failed, eixt now\n", sizeof(msg->msgHdr.payloadLen+1));
            exit(-1);
        }
        memset(msg->payload, 0, msg->msgHdr.payloadLen+1);
        memcpy(msg->payload, recv_buf + sizeof(disc_msg_hdr_t), msgHdr->payloadLen);
        
        /* 数据插入队列中 */
        if(disc_queue_push(msg) != 0) {
            DISC_WARNING("[Recieve] Msg queue is full, drop it\n");
            disc_free_msg(msg);
            msg = NULL;
        }

        /* 发送信号，唤醒处理线程 */
        pthread_mutex_lock(&g_proc_mutex);
        pthread_cond_signal(&g_proc_cond);
        pthread_mutex_unlock(&g_proc_mutex);
    }

    DISC_FILE("Receive thread exit\n");
    close(fd);
    exit(-1);

    return NULL;
}

static void* disc_process_pthread(void* arg)
{
    int ret;
    int print_count = 0;
    struct timeval now;
    struct timespec out_time;
    disc_msg_t* msg;
    
    /* 设置线程名称 */
    prctl(PR_SET_NAME, "process_thread");

    while(1) {
        while(disc_queue_is_empty() == true) {
            /* 设置超时时间：2个广播周期 */
            gettimeofday(&now, NULL);
            out_time.tv_sec = now.tv_sec + g_dev_cfg->bcast_period * 2;
            out_time.tv_nsec = now.tv_usec * 1000;
            
            pthread_mutex_lock(&g_proc_mutex);
            ret = pthread_cond_timedwait(&g_proc_cond, &g_proc_mutex, &out_time);
            if(ret != 0) {
                DISC_DEBUG("[Process] Wait cond timeout...\n");
            }else {
                if(print_count % PRINT_INTERVAL == 0) {
                    DISC_DEBUG("[Process] Get a process signal...\n");
                    print_count ++;
                }
            }
            pthread_mutex_unlock(&g_proc_mutex);      
        }

        /* 从队列中读取一个数据 */
        msg = disc_queue_pop();
        if(msg == NULL) {
            DISC_DEBUG("[Process] Get a null msg from queue.\n");
            continue;
        } else {
            if(print_count % PRINT_INTERVAL == 0) {
                DISC_DEBUG("[Process] Get a msg from queue, start to process...\n");
                print_count ++;
            }
        }

        /* 消息处理 */
        (void)disc_msg_handler(msg);

        /* 释放内存 */
        if(msg != NULL) {
            disc_free_msg(msg);
            msg = NULL;
        }
   
    }

    return NULL;
}

static int disc_init(void)
{
    int rc;
    
    uloop_init();
    
    rc = disc_debug_init();
    if (rc != 0) {
        DISC_ERROR("disc debug init failed, exit now!\n");
        exit(1);
    }
    
    rc = disc_ubus_init();
    if (rc != 0) {
        DISC_ERROR("disc ubus init failed, exit now!\n");
        exit(1);   
    }

    rc = disc_param_init();
    if (rc != 0) {
        DISC_ERROR("disc param init failed, exit now!\n");
        exit(1);   
    }

    rc = disc_reload_conf_file(g_dev_cfg);
    if (rc != 0) {
        DISC_ERROR("disc load conf file failed, exit now\n");
        exit(1);
    }

     rc = disc_read_dev_info(g_dev_info);
    if (rc != 0) {
        DISC_ERROR("disc read device info failed, exit now\n");
        exit(1);
    }

    g_dev_info->role = &(g_dev_cfg->role);
    g_dev_info->networkId = g_dev_cfg->networkId;
    g_dev_info->networkName = g_dev_cfg->networkName;
    g_dev_info->ip = strdup("0.0.0.0");

    /* 链表、互斥变量初始化 */
    INIT_LIST_HEAD(&g_neighbor_list);
    pthread_mutex_init(&g_role_mutex, NULL);
    pthread_mutex_init(&g_master_mutex, NULL);
    pthread_mutex_init(&g_list_mutex, NULL);
    pthread_mutex_init(&g_proc_mutex, NULL);
    pthread_cond_init(&g_proc_cond, NULL); 
    
    return 0;
}

int main(int argc, char* argv[])
{
    pthread_t proc_pthid;
    pthread_t recv_pthid;
    pthread_t uloop_pthid;
    
    /* 初始化 */
    (void)disc_init(); 

    /* process线程 */
    if (pthread_create(&proc_pthid, NULL, disc_process_pthread, NULL)) {
        DISC_ERROR("Create process pthread failed\n");
        return -1;
    } 
    DISC_FILE("Create process pthread successfully\n");

    /* receive线程 */
    if (pthread_create(&recv_pthid, NULL, disc_receive_pthread, "br-wan")) {
        DISC_ERROR("Create receive pthread failed\n");
        return -1;
    } 
    DISC_FILE("Create process pthread successfully\n");

    /* uloop线程 */
    if (pthread_create(&uloop_pthid, NULL, disc_uloop_pthread, NULL)) {
        DISC_ERROR("Create uloop pthread failed\n");
        return -1;
    } 
    DISC_FILE("Create process pthread successfully\n");

    pthread_join(proc_pthid, NULL);
    pthread_join(uloop_pthid, NULL);
    pthread_join(recv_pthid, NULL);
    
    return 0;
}

