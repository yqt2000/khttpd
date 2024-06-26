#ifndef KHTTPD_HTTP_SERVER_H
#define KHTTPD_HTTP_SERVER_H

#include <linux/module.h>
#include <linux/workqueue.h>
#include <net/sock.h>
#define MODULE_NAME "khttpd"

struct http_server_param {
    struct socket *listen_socket;
};

struct khttpd_service {
    bool is_stopped;
    char *path;
    struct list_head head;  // workqueue
};

extern int http_server_daemon(void *arg);

#endif
