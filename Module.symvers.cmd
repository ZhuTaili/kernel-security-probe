/* SPDX-License-Identifier: GPL-2.0 */
/*
 * secprobe_event.h
 *
 * secprobe 内核模块与用户态监控程序共用的告警事件结构。
 *
 * 设计原则：
 *   安全规则判断在内核态完成；
 *   用户态程序只接收并展示内核已经确认的告警。
 */

#ifndef _SECPROBE_EVENT_H_
#define _SECPROBE_EVENT_H_

#include <linux/types.h>

/*
 * Netlink 通信参数。
 * 使用自定义 Netlink 协议号 31 和组播组 1。
 */
#define SECPROBE_NETLINK_PROTO 31
#define SECPROBE_NETLINK_GROUP 1

/* 字符串字段长度 */
#define SECPROBE_COMM_LEN      16
#define SECPROBE_RULE_LEN      32
#define SECPROBE_ACTION_LEN    16
#define SECPROBE_TARGET_LEN    256

/* 告警类型 */
#define SECPROBE_ALERT_EXEC    1
#define SECPROBE_ALERT_FILE    2
#define SECPROBE_ALERT_NET     3

/* 告警等级 */
#define SECPROBE_SEVERITY_MEDIUM    1
#define SECPROBE_SEVERITY_HIGH      2
#define SECPROBE_SEVERITY_CRITICAL  3

/*
 * 结构化告警事件。
 *
 * type       告警类别：EXEC / FILE / NET
 * severity   告警等级：MEDIUM / HIGH / CRITICAL
 * timestamp  内核产生告警的时间
 * pid        触发告警的进程 ID
 * uid/euid   触发告警进程的身份信息
 * comm       进程名称
 * rule       命中的内核安全规则
 * action     EXEC / READ / WRITE / CONNECT
 * target     程序路径、文件路径或网络目标地址
 */
struct secprobe_alert_event {
    __u32 type;
    __u32 severity;
    __u64 timestamp_ns;

    __u32 pid;
    __u32 uid;
    __u32 euid;

    char comm[SECPROBE_COMM_LEN];
    char rule[SECPROBE_RULE_LEN];
    char action[SECPROBE_ACTION_LEN];
    char target[SECPROBE_TARGET_LEN];
};

#endif
