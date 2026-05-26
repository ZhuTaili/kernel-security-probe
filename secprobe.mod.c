// SPDX-License-Identifier: GPL-2.0
/*
 * secprobe.c
 *
 * 基于 Kprobe 的 Linux 内核安全探针：Netlink 用户态展示
 *
 *   Ubuntu 20.04 x86_64 / Linux 5.4
 *   Ubuntu 22.04 x86_64 / Linux 5.15
 *   Ubuntu 22.04 HWE x86_64 / Linux 6.8
 */

#define pr_fmt(fmt) "SEC_PROBE: " fmt

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/kprobes.h>
#include <linux/ptrace.h>
#include <linux/binfmts.h>
#include <linux/fs.h>
#include <linux/dcache.h>
#include <linux/err.h>
#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/cred.h>
#include <linux/uidgid.h>
#include <linux/string.h>
#include <linux/net.h>
#include <linux/socket.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/byteorder/generic.h>
#include <linux/timekeeping.h>
#include <linux/skbuff.h>
#include <linux/netlink.h>
#include <net/sock.h>
#include <net/netlink.h>
#include <net/net_namespace.h>

#include "../common/secprobe_event.h"

#ifndef CONFIG_X86_64
#error "secprobe currently supports x86_64 Ubuntu virtual machines only."
#endif

#define MAX_WATCH_PORTS 8

/*
 * watch_ports 是配置的重点观察端口，而不是“恶意端口全集”。
 * 默认 4444 ，可替换
 *
 *   sudo insmod ./secprobe.ko watch_ports=8888,9001
 */
static unsigned short watch_ports[MAX_WATCH_PORTS] = { 4444 };
static int watch_ports_count = 1;

module_param_array(watch_ports, ushort, &watch_ports_count, 0444);
MODULE_PARM_DESC(watch_ports,
                 "Destination ports configured as watched security indicators");

/* 探针注册状态 */
static bool exec_probe_registered;
static bool socket_probe_registered;

/* 告警 Netlink 通道：仅传输内核态已经完成判断的 ALERT 事件 */
static struct sock *alert_nl_sock;

static void nl_recv_msg(struct sk_buff *skb)
{
    (void)skb;
    /* 当前阶段只由内核发送告警，不接收用户态控制命令。 */
}

static struct netlink_kernel_cfg alert_nl_cfg = {
    .input = nl_recv_msg,
    .groups = SECPROBE_NETLINK_GROUP,
};

/*
 * 文件检测优先使用 security_file_permission 获取 READ/WRITE 语义；
 * 若目标内核无法注册该探针，则回退到 security_file_open。
 */
enum file_probe_mode {
    FILE_PROBE_NONE = 0,
    FILE_PROBE_PERMISSION,
    FILE_PROBE_OPEN_FALLBACK
};

static enum file_probe_mode current_file_probe_mode = FILE_PROBE_NONE;

/* 文件安全规则分类 */
enum protected_file_rule {
    FILE_RULE_NONE = 0,
    FILE_RULE_ACCOUNT_DATABASE,
    FILE_RULE_CREDENTIAL_SECRET,
    FILE_RULE_PRIVILEGE_CONFIG,
    FILE_RULE_AUTHORIZED_KEYS,
    FILE_RULE_PRIVATE_KEY,
    FILE_RULE_DEMO_SECRET
};

static unsigned int get_current_uid(void)
{
    return __kuid_val(current_uid());
}

static unsigned int get_current_euid(void)
{
    return __kuid_val(current_euid());
}

/*
 * 将内核态已经判定为告警的结构化事件发送给用户态展示程序。
 * 若当前没有展示程序监听，dmesg 告警仍保留，不影响检测功能。
 */
static int send_alert_event(__u32 type,
                            __u32 severity,
                            const char *rule,
                            const char *action,
                            const char *target)
{
    struct secprobe_alert_event event;
    struct sk_buff *skb;
    struct nlmsghdr *nlh;
    int ret;

    if (alert_nl_sock == NULL)
        return -ENODEV;

    memset(&event, 0, sizeof(event));
    event.type = type;
    event.severity = severity;
    event.timestamp_ns = ktime_get_real_ns();
    event.pid = task_tgid_nr(current);
    event.uid = get_current_uid();
    event.euid = get_current_euid();

    strscpy(event.comm, current->comm, sizeof(event.comm));
    strscpy(event.rule, rule, sizeof(event.rule));
    strscpy(event.action, action, sizeof(event.action));
    strscpy(event.target, target, sizeof(event.target));

    skb = nlmsg_new(sizeof(event), GFP_ATOMIC);
    if (skb == NULL)
        return -ENOMEM;

    nlh = nlmsg_put(skb, 0, 0, NLMSG_DONE, sizeof(event), 0);
    if (nlh == NULL) {
        kfree_skb(skb);
        return -EMSGSIZE;
    }

    memcpy(nlmsg_data(nlh), &event, sizeof(event));

    ret = netlink_broadcast(alert_nl_sock,
                            skb,
                            0,
                            SECPROBE_NETLINK_GROUP,
                            GFP_ATOMIC);

    /*
     * 没有监听器时会返回 -ESRCH，这不代表内核检测失败。
     * 现场未启动监控程序时，仍可通过 dmesg 查看告警。
     */
    if (ret == -ESRCH)
        return 0;

    return ret;
}

static void release_alert_channel(void)
{
    if (alert_nl_sock != NULL) {
        netlink_kernel_release(alert_nl_sock);
        alert_nl_sock = NULL;
    }
}

/*
 * 内核线程不属于本实验关注的用户行为。
 * 用户态后台服务仍会进入判断，但只有命中安全规则才输出告警。
 */
static bool should_skip_current_task(void)
{
    return (current->flags & PF_KTHREAD) != 0;
}

static const char *path_basename(const char *path)
{
    const char *slash;

    if (path == NULL)
        return "";

    slash = strrchr(path, '/');

    return slash != NULL ? slash + 1 : path;
}

/*
 * 执行层面的可疑工具判断。
 * 此处只说明可疑工具被启动，不将其直接判定为攻击成功。
 */
static bool is_suspicious_exec_tool(const char *name)
{
    if (name == NULL)
        return false;

    return strcmp(name, "nc") == 0 ||
           strcmp(name, "nc.openbsd") == 0 ||
           strcmp(name, "netcat") == 0 ||
           strcmp(name, "ncat") == 0 ||
           strcmp(name, "nmap") == 0 ||
           strcmp(name, "socat") == 0;
}

/*
 * 网络连接层面的可疑工具判断。
 * nmap 并非所有扫描模式都会走普通 connect 路径，因此这里重点覆盖
 * 常见连接/转发工具。
 */
static bool is_suspicious_network_tool(const char *comm)
{
    if (comm == NULL)
        return false;

    return strcmp(comm, "nc") == 0 ||
           strcmp(comm, "nc.openbsd") == 0 ||
           strcmp(comm, "netcat") == 0 ||
           strcmp(comm, "ncat") == 0 ||
           strcmp(comm, "socat") == 0;
}

static bool is_configured_watch_port(unsigned short port)
{
    int i;

    for (i = 0; i < watch_ports_count && i < MAX_WATCH_PORTS; i++) {
        if (watch_ports[i] != 0 && watch_ports[i] == port)
            return true;
    }

    return false;
}

/*
 * 文件路径分类：
 *
 * - 账号/提权配置文件：读取频繁，仅写入告警
 * - 密钥/口令数据：读取即告警，写入更严重
 * - 演示文件：用于安全地验证 READ/WRITE 分级，不修改真实系统配置
 */
static enum protected_file_rule classify_protected_file(const char *path)
{
    if (path == NULL)
        return FILE_RULE_NONE;

    if (strcmp(path, "/etc/passwd") == 0 ||
        strcmp(path, "/etc/group") == 0)
        return FILE_RULE_ACCOUNT_DATABASE;

    if (strcmp(path, "/etc/shadow") == 0 ||
        strcmp(path, "/etc/gshadow") == 0)
        return FILE_RULE_CREDENTIAL_SECRET;

    if (strcmp(path, "/etc/sudoers") == 0 ||
        strncmp(path, "/etc/sudoers.d/",
                sizeof("/etc/sudoers.d/") - 1) == 0)
        return FILE_RULE_PRIVILEGE_CONFIG;

    if (strcmp(path, "/root/.ssh/authorized_keys") == 0)
        return FILE_RULE_AUTHORIZED_KEYS;

    if (strcmp(path, "/root/.ssh/id_rsa") == 0 ||
        strcmp(path, "/root/.ssh/id_ed25519") == 0)
        return FILE_RULE_PRIVATE_KEY;

    if (strcmp(path, "/root/secprobe_demo.txt") == 0)
        return FILE_RULE_DEMO_SECRET;

    return FILE_RULE_NONE;
}

static const char *file_rule_name(enum protected_file_rule rule)
{
    switch (rule) {
    case FILE_RULE_ACCOUNT_DATABASE:
        return "ACCOUNT_DATABASE";
    case FILE_RULE_CREDENTIAL_SECRET:
        return "CREDENTIAL_SECRET";
    case FILE_RULE_PRIVILEGE_CONFIG:
        return "PRIVILEGE_CONFIG";
    case FILE_RULE_AUTHORIZED_KEYS:
        return "AUTHORIZED_KEYS";
    case FILE_RULE_PRIVATE_KEY:
        return "PRIVATE_KEY";
    case FILE_RULE_DEMO_SECRET:
        return "DEMO_SECRET";
    default:
        return "NONE";
    }
}

static bool should_alert_file_read(enum protected_file_rule rule)
{
    return rule == FILE_RULE_CREDENTIAL_SECRET ||
           rule == FILE_RULE_PRIVATE_KEY ||
           rule == FILE_RULE_DEMO_SECRET;
}

static bool should_alert_file_write(enum protected_file_rule rule)
{
    return rule != FILE_RULE_NONE;
}

/*
 * 文件安全判断的核心：
 *   - WRITE 优先于 READ 输出，避免一次读写权限事件重复打印
 *   - 普通读取 passwd/group/sudoers/authorized_keys 不输出
 *   - 修改任何受保护文件都输出 CRITICAL
 */
static void evaluate_file_access(const char *path, int mask)
{
    enum protected_file_rule rule;
    bool is_read;
    bool is_write;

    rule = classify_protected_file(path);

    if (rule == FILE_RULE_NONE)
        return;

    is_read = (mask & MAY_READ) != 0;
    is_write = (mask & (MAY_WRITE | MAY_APPEND)) != 0;

    if (is_write && should_alert_file_write(rule)) {
        pr_warn(
            "[ALERT][FILE][CRITICAL] sensitive file modification: rule=%s access=WRITE uid=%u euid=%u pid=%d comm=%s path=%s\n",
            file_rule_name(rule),
            get_current_uid(),
            get_current_euid(),
            current->pid,
            current->comm,
            path
        );

        send_alert_event(SECPROBE_ALERT_FILE,
                         SECPROBE_SEVERITY_CRITICAL,
                         file_rule_name(rule),
                         "WRITE",
                         path);
        return;
    }

    if (is_read && should_alert_file_read(rule)) {
        pr_warn(
            "[ALERT][FILE][HIGH] sensitive file read: rule=%s access=READ uid=%u euid=%u pid=%d comm=%s path=%s\n",
            file_rule_name(rule),
            get_current_uid(),
            get_current_euid(),
            current->pid,
            current->comm,
            path
        );

        send_alert_event(SECPROBE_ALERT_FILE,
                         SECPROBE_SEVERITY_HIGH,
                         file_rule_name(rule),
                         "READ",
                         path);
    }
}

static void inspect_file_access(struct file *file, int mask)
{
    char *buffer;
    char *path;

    if (file == NULL || file->f_path.dentry == NULL)
        return;

    /*
     * 回调中使用原子分配，避免因内存分配睡眠破坏探针执行环境。
     */
    buffer = (char *)__get_free_page(GFP_ATOMIC);

    if (buffer == NULL)
        return;

    path = d_path(&file->f_path, buffer, PAGE_SIZE);

    if (!IS_ERR(path))
        evaluate_file_access(path, mask);

    free_page((unsigned long)buffer);
}

/*
 * 探针一：可疑程序执行
 * security_bprm_check(struct linux_binprm *bprm)
 */
static int exec_pre_handler(struct kprobe *probe, struct pt_regs *regs)
{
    struct linux_binprm *bprm;
    const char *filename;
    const char *command;

    (void)probe;

    if (should_skip_current_task())
        return 0;

    bprm = (struct linux_binprm *)regs->di;

    if (bprm == NULL || bprm->filename == NULL)
        return 0;

    filename = bprm->filename;
    command = path_basename(filename);

    if (!is_suspicious_exec_tool(command))
        return 0;

    pr_warn(
        "[ALERT][EXEC][MEDIUM] suspicious tool executed: rule=SUSPICIOUS_TOOL uid=%u euid=%u pid=%d comm=%s path=%s\n",
        get_current_uid(),
        get_current_euid(),
        current->pid,
        current->comm,
        filename
    );

    send_alert_event(SECPROBE_ALERT_EXEC,
                     SECPROBE_SEVERITY_MEDIUM,
                     "SUSPICIOUS_TOOL",
                     "EXEC",
                     filename);

    return 0;
}

/*
 * 首选文件探针：
 * security_file_permission(struct file *file, int mask)
 *
 * mask 可区分 MAY_READ 与 MAY_WRITE/MAY_APPEND。
 */
static int file_permission_pre_handler(struct kprobe *probe,
                                       struct pt_regs *regs)
{
    struct file *file;
    int mask;

    (void)probe;

    if (should_skip_current_task())
        return 0;

    file = (struct file *)regs->di;
    mask = (int)regs->si;

    inspect_file_access(file, mask);

    return 0;
}

/*
 * 文件探针回退方案：
 * security_file_open(struct file *file)
 *
 * 使用打开模式近似判断 READ/WRITE；能力弱于 security_file_permission，
 * 仅在首选探针注册失败时使用。
 */
static int file_open_fallback_pre_handler(struct kprobe *probe,
                                          struct pt_regs *regs)
{
    struct file *file;
    int mask = 0;

    (void)probe;

    if (should_skip_current_task())
        return 0;

    file = (struct file *)regs->di;

    if (file == NULL)
        return 0;

    if (file->f_mode & FMODE_READ)
        mask |= MAY_READ;

    if (file->f_mode & FMODE_WRITE)
        mask |= MAY_WRITE;

    inspect_file_access(file, mask);

    return 0;
}

/*
 * 探针三：网络连接安全判断
 *
 * 规则：
 *   可疑网络工具主动连接任意端口       -> HIGH
 *   普通程序连接配置的观察端口         -> HIGH
 *   可疑网络工具连接配置的观察端口     -> CRITICAL
 *
 * security_socket_connect(struct socket *sock,
 *                         struct sockaddr *address,
 *                         int addrlen)
 */
static int socket_pre_handler(struct kprobe *probe, struct pt_regs *regs)
{
    struct sockaddr *address;
    int address_len;
    bool tool_match;
    bool port_match;
    char endpoint[SECPROBE_TARGET_LEN];

    (void)probe;

    if (should_skip_current_task())
        return 0;

    address = (struct sockaddr *)regs->si;
    address_len = (int)regs->dx;

    if (address == NULL)
        return 0;

    tool_match = is_suspicious_network_tool(current->comm);

    if (address->sa_family == AF_INET &&
        address_len >= (int)sizeof(struct sockaddr_in)) {
        struct sockaddr_in *address_v4;
        unsigned short port;

        address_v4 = (struct sockaddr_in *)address;
        port = be16_to_cpu(address_v4->sin_port);
        port_match = is_configured_watch_port(port);

        if (!tool_match && !port_match)
            return 0;

        scnprintf(endpoint,
                  sizeof(endpoint),
                  "%pI4:%u",
                  &address_v4->sin_addr.s_addr,
                  port);

        if (tool_match && port_match) {
            pr_warn(
                "[ALERT][NET][CRITICAL] suspicious tool connected to watched port: rule=TOOL_AND_WATCH_PORT uid=%u euid=%u pid=%d comm=%s dst=%s\n",
                get_current_uid(),
                get_current_euid(),
                current->pid,
                current->comm,
                endpoint
            );

            send_alert_event(SECPROBE_ALERT_NET,
                             SECPROBE_SEVERITY_CRITICAL,
                             "TOOL_AND_WATCH_PORT",
                             "CONNECT",
                             endpoint);
        } else if (tool_match) {
            pr_warn(
                "[ALERT][NET][HIGH] suspicious network tool connection: rule=SUSPICIOUS_TOOL_CONNECT uid=%u euid=%u pid=%d comm=%s dst=%s\n",
                get_current_uid(),
                get_current_euid(),
                current->pid,
                current->comm,
                endpoint
            );

            send_alert_event(SECPROBE_ALERT_NET,
                             SECPROBE_SEVERITY_HIGH,
                             "SUSPICIOUS_TOOL_CONNECT",
                             "CONNECT",
                             endpoint);
        } else {
            pr_warn(
                "[ALERT][NET][HIGH] connection to configured watched port: rule=WATCH_PORT_CONNECT uid=%u euid=%u pid=%d comm=%s dst=%s\n",
                get_current_uid(),
                get_current_euid(),
                current->pid,
                current->comm,
                endpoint
            );

            send_alert_event(SECPROBE_ALERT_NET,
                             SECPROBE_SEVERITY_HIGH,
                             "WATCH_PORT_CONNECT",
                             "CONNECT",
                             endpoint);
        }
    } else if (address->sa_family == AF_INET6 &&
               address_len >= (int)sizeof(struct sockaddr_in6)) {
        struct sockaddr_in6 *address_v6;
        unsigned short port;

        address_v6 = (struct sockaddr_in6 *)address;
        port = be16_to_cpu(address_v6->sin6_port);
        port_match = is_configured_watch_port(port);

        if (!tool_match && !port_match)
            return 0;

        scnprintf(endpoint,
                  sizeof(endpoint),
                  "[%pI6c]:%u",
                  &address_v6->sin6_addr,
                  port);

        if (tool_match && port_match) {
            pr_warn(
                "[ALERT][NET][CRITICAL] suspicious tool connected to watched port: rule=TOOL_AND_WATCH_PORT uid=%u euid=%u pid=%d comm=%s dst=%s\n",
                get_current_uid(),
                get_current_euid(),
                current->pid,
                current->comm,
                endpoint
            );

            send_alert_event(SECPROBE_ALERT_NET,
                             SECPROBE_SEVERITY_CRITICAL,
                             "TOOL_AND_WATCH_PORT",
                             "CONNECT",
                             endpoint);
        } else if (tool_match) {
            pr_warn(
                "[ALERT][NET][HIGH] suspicious network tool connection: rule=SUSPICIOUS_TOOL_CONNECT uid=%u euid=%u pid=%d comm=%s dst=%s\n",
                get_current_uid(),
                get_current_euid(),
                current->pid,
                current->comm,
                endpoint
            );

            send_alert_event(SECPROBE_ALERT_NET,
                             SECPROBE_SEVERITY_HIGH,
                             "SUSPICIOUS_TOOL_CONNECT",
                             "CONNECT",
                             endpoint);
        } else {
            pr_warn(
                "[ALERT][NET][HIGH] connection to configured watched port: rule=WATCH_PORT_CONNECT uid=%u euid=%u pid=%d comm=%s dst=%s\n",
                get_current_uid(),
                get_current_euid(),
                current->pid,
                current->comm,
                endpoint
            );

            send_alert_event(SECPROBE_ALERT_NET,
                             SECPROBE_SEVERITY_HIGH,
                             "WATCH_PORT_CONNECT",
                             "CONNECT",
                             endpoint);
        }
    }

    return 0;
}

static struct kprobe exec_probe = {
    .symbol_name = "security_bprm_check",
    .pre_handler = exec_pre_handler,
};

static struct kprobe file_permission_probe = {
    .symbol_name = "security_file_permission",
    .pre_handler = file_permission_pre_handler,
};

static struct kprobe file_open_fallback_probe = {
    .symbol_name = "security_file_open",
    .pre_handler = file_open_fallback_pre_handler,
};

static struct kprobe socket_probe = {
    .symbol_name = "security_socket_connect",
    .pre_handler = socket_pre_handler,
};

static int register_file_probe(void)
{
    int ret;

    ret = register_kprobe(&file_permission_probe);

    if (ret == 0) {
        current_file_probe_mode = FILE_PROBE_PERMISSION;
        pr_info("registered probe: security_file_permission (read/write aware)\n");
        return 0;
    }

    pr_warn(
        "security_file_permission unavailable, error=%d; falling back to security_file_open\n",
        ret
    );

    ret = register_kprobe(&file_open_fallback_probe);

    if (ret == 0) {
        current_file_probe_mode = FILE_PROBE_OPEN_FALLBACK;
        pr_info("registered probe: security_file_open (compatibility fallback)\n");
        return 0;
    }

    pr_err("failed to register file security probe, error=%d\n", ret);
    return ret;
}

static void unregister_file_probe(void)
{
    if (current_file_probe_mode == FILE_PROBE_PERMISSION)
        unregister_kprobe(&file_permission_probe);
    else if (current_file_probe_mode == FILE_PROBE_OPEN_FALLBACK)
        unregister_kprobe(&file_open_fallback_probe);

    current_file_probe_mode = FILE_PROBE_NONE;
}

static void unregister_secprobe_probes(void)
{
    if (socket_probe_registered) {
        unregister_kprobe(&socket_probe);
        socket_probe_registered = false;
    }

    unregister_file_probe();

    if (exec_probe_registered) {
        unregister_kprobe(&exec_probe);
        exec_probe_registered = false;
    }
}

static int __init secprobe_init(void)
{
    int ret;
    int i;

    pr_info("loading kernel security probe module V5.0 (netlink display enabled)\n");

    /*
     * 参考 mini_edr 的方式创建 Netlink multicast 通道。
     * 安全判断仍由下方的 Kprobe 回调在内核态完成。
     */
    alert_nl_sock = netlink_kernel_create(&init_net,
                                          SECPROBE_NETLINK_PROTO,
                                          &alert_nl_cfg);
    if (alert_nl_sock == NULL) {
        pr_err("failed to create netlink alert channel\n");
        return -ENOMEM;
    }

    pr_info("netlink alert channel created: protocol=%d group=%d\n",
            SECPROBE_NETLINK_PROTO,
            SECPROBE_NETLINK_GROUP);

    ret = register_kprobe(&exec_probe);
    if (ret < 0) {
        pr_err("failed to register security_bprm_check, error=%d\n", ret);
        release_alert_channel();
        return ret;
    }

    exec_probe_registered = true;
    pr_info("registered probe: security_bprm_check\n");

    ret = register_file_probe();
    if (ret < 0) {
        unregister_secprobe_probes();
        release_alert_channel();
        return ret;
    }

    ret = register_kprobe(&socket_probe);
    if (ret < 0) {
        pr_err("failed to register security_socket_connect, error=%d\n", ret);
        unregister_secprobe_probes();
        release_alert_channel();
        return ret;
    }

    socket_probe_registered = true;
    pr_info("registered probe: security_socket_connect\n");

    pr_info("module loaded successfully, active_security_categories=3\n");
    pr_info("file policy: read/write-aware protected path filtering enabled\n");
    pr_info("network policy: tool connect or configured watched port connect\n");

    for (i = 0; i < watch_ports_count && i < MAX_WATCH_PORTS; i++) {
        if (watch_ports[i] != 0)
            pr_info("configured watched port[%d]=%hu\n", i, watch_ports[i]);
    }

    pr_info("userspace monitor: start secprobe_monitor to receive alerts\n");
    pr_info("current mode: alert only, no active blocking\n");

    return 0;
}

static void __exit secprobe_exit(void)
{
    unregister_secprobe_probes();
    release_alert_channel();
    pr_info("kernel security probe module V5.0 unloaded\n");
}

module_init(secprobe_init);
module_exit(secprobe_exit);

MODULE_LICENSE("GPL");

