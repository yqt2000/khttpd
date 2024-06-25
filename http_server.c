#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/kthread.h>
#include <linux/sched/signal.h>
#include <linux/tcp.h>

#include <linux/workqueue.h>
#include "http_parser.h"
#include "http_server.h"

#define CRLF "\r\n"
#define KBUILD_MODNAME "khttpd"

#define HTTP_RESPONSE_200_DUMMY                               \
    ""                                                        \
    "HTTP/1.1 200 OK" CRLF "Server: " KBUILD_MODNAME CRLF     \
    "Content-Type: text/plain" CRLF "Content-Length: 12" CRLF \
    "Connection: Close" CRLF CRLF "Hello World!" CRLF
#define HTTP_RESPONSE_200_KEEPALIVE_DUMMY                     \
    ""                                                        \
    "HTTP/1.1 200 OK" CRLF "Server: " KBUILD_MODNAME CRLF     \
    "Content-Type: text/plain" CRLF "Content-Length: 12" CRLF \
    "Connection: Keep-Alive" CRLF CRLF "Hello World!" CRLF
#define HTTP_RESPONSE_501                                              \
    ""                                                                 \
    "HTTP/1.1 501 Not Implemented" CRLF "Server: " KBUILD_MODNAME CRLF \
    "Content-Type: text/plain" CRLF "Content-Length: 21" CRLF          \
    "Connection: Close" CRLF CRLF "501 Not Implemented" CRLF
#define HTTP_RESPONSE_501_KEEPALIVE                                    \
    ""                                                                 \
    "HTTP/1.1 501 Not Implemented" CRLF "Server: " KBUILD_MODNAME CRLF \
    "Content-Type: text/plain" CRLF "Content-Length: 21" CRLF          \
    "Connection: KeepAlive" CRLF CRLF "501 Not Implemented" CRLF

#define RECV_BUFFER_SIZE 4096

struct http_request {
    struct socket *socket;
    enum http_method method;
    char request_url[128];
    int complete;
    struct list_head node;
    struct work_struct khttpd_work;
};

struct khttpd_service daemon_list = {.is_stopped = false};
struct workqueue_struct *khttpd_wq;  // set up workqueue

static int http_server_recv(struct socket *sock, char *buf, size_t size)
{
    struct kvec iov = {.iov_base = (void *) buf, .iov_len = size};
    struct msghdr msg = {.msg_name = 0,
                         .msg_namelen = 0,
                         .msg_control = NULL,
                         .msg_controllen = 0,
                         .msg_flags = 0};
    return kernel_recvmsg(sock, &msg, &iov, 1, size, msg.msg_flags);
}

static int http_server_send(struct socket *sock, const char *buf, size_t size)
{
    struct msghdr msg = {.msg_name = NULL,
                         .msg_namelen = 0,
                         .msg_control = NULL,
                         .msg_controllen = 0,
                         .msg_flags = 0};
    int done = 0;
    while (done < size) {
        struct kvec iov = {
            .iov_base = (void *) ((char *) buf + done),
            .iov_len = size - done,
        };
        int length = kernel_sendmsg(sock, &msg, &iov, 1, iov.iov_len);
        if (length < 0) {
            pr_err("write error: %d\n", length);
            break;
        }
        done += length;
    }
    return done;
}

static int http_server_response(struct http_request *request, int keep_alive)
{
    char const *response;

    pr_info("requested_url = %s\n", request->request_url);
    if (request->method != HTTP_GET)
        response = keep_alive ? HTTP_RESPONSE_501_KEEPALIVE : HTTP_RESPONSE_501;
    else
        response = keep_alive ? HTTP_RESPONSE_200_KEEPALIVE_DUMMY
                              : HTTP_RESPONSE_200_DUMMY;
    http_server_send(request->socket, response, strlen(response));
    return 0;
}

static int http_parser_callback_message_begin(http_parser *parser)
{
    struct http_request *request = parser->data;
    struct socket *socket = request->socket;
    memset(request, 0x00, sizeof(struct http_request));
    request->socket = socket;
    return 0;
}

static int http_parser_callback_request_url(http_parser *parser,
                                            const char *p,
                                            size_t len)
{
    struct http_request *request = parser->data;
    strncat(request->request_url, p, len);
    return 0;
}

static int http_parser_callback_header_field(http_parser *parser,
                                             const char *p,
                                             size_t len)
{
    return 0;
}

static int http_parser_callback_header_value(http_parser *parser,
                                             const char *p,
                                             size_t len)
{
    return 0;
}

static int http_parser_callback_headers_complete(http_parser *parser)
{
    struct http_request *request = parser->data;
    request->method = parser->method;
    return 0;
}

static int http_parser_callback_body(http_parser *parser,
                                     const char *p,
                                     size_t len)
{
    return 0;
}

// 設定 call back function 的部份，主要是用來送出回應 client 的資料
static int http_parser_callback_message_complete(http_parser *parser)
{
    struct http_request *request = parser->data;
    http_server_response(request, http_should_keep_alive(parser));
    request->complete = 1;
    return 0;
}

static void http_server_worker(struct work_struct *work)
{
    char *buf;
    struct http_parser parser;
    // 1. 設定 callback function
    struct http_parser_settings setting = {
        .on_message_begin = http_parser_callback_message_begin,
        .on_url = http_parser_callback_request_url,
        .on_header_field = http_parser_callback_header_field,
        .on_header_value = http_parser_callback_header_value,
        .on_headers_complete = http_parser_callback_headers_complete,
        .on_body = http_parser_callback_body,
        .on_message_complete = http_parser_callback_message_complete};

    struct http_request request;
    // worker->socket, http_work 透過 container_of 找到 http_server 中的 socket
    struct socket *socket =
        container_of(work, struct http_request, khttpd_work)->socket;

    allow_signal(SIGKILL);
    allow_signal(SIGTERM);

    buf = kzalloc(RECV_BUFFER_SIZE, GFP_KERNEL);
    if (!buf) {
        pr_err("can't allocate memory!\n");
        return;
    }

    request.socket = socket;
    http_parser_init(&parser, HTTP_REQUEST);
    parser.data = &request;

    // 2. 進到迴圈，使用函式 kthread_should_stop 判斷該執行緒是否該中止
    while (!kthread_should_stop()) {
        // 3. 接收資料
        int ret = http_server_recv(socket, buf, RECV_BUFFER_SIZE - 1);
        if (ret <= 0) {
            if (ret)
                pr_err("recv error: %d\n", ret);
            break;
        }
        // 4. 解析收到的資料
        http_parser_execute(&parser, &setting, buf, ret);
        if (request.complete && !http_should_keep_alive(&parser))
            break;
        // 使用函式 memset 將參數 buf 的值清空
        memset(buf, 0, RECV_BUFFER_SIZE);
    }
    // 5. 中斷連線後釋放用到的所有記憶體
    kernel_sock_shutdown(socket, SHUT_RDWR);
    sock_release(socket);
    kfree(buf);
}

// ref : kecho create_work
static struct work_struct *create_work(struct socket *sk)
{
    struct http_request *work;
    // GFP_KERNEL the flag of allocation
    // https://elixir.bootlin.com/linux/latest/source/include/linux/gfp.h#L341
    if (!(work = kmalloc(sizeof(struct http_request), GFP_KERNEL)))
        return NULL;

    work->socket = sk;

    // 初始化已經建立的 work ，並運行函式 http_server_worker
    INIT_WORK(&work->khttpd_work, http_server_worker);
    list_add(&work->node, &daemon_list.head);  // 加 work 加到 list 中
    return &work->khttpd_work;
}

static void free_work(void)
{
    struct http_request *tmp, *target; /* cppcheck-suppress uninitvar */

    // list : member
    list_for_each_entry_safe (target, tmp, &daemon_list.head, node) {
        kernel_sock_shutdown(target->socket, SHUT_RDWR);
        flush_work(&target->khttpd_work);
        sock_release(target->socket);
        kfree(target);
    }
}

int http_server_daemon(void *arg)
{
    struct socket *socket;
    // struct task_struct *worker;
    struct http_server_param *param = (struct http_server_param *) arg;

    // CMWQ
    struct work_struct *work;
    // 在初始化模組時用來建立一個 workqueue
    khttpd_wq = alloc_workqueue("khttp_wq", WQ_UNBOUND, 0); /* workqueue.h API*/
    if (!khttpd_wq)
        return -ENOMEM;
    // initial workqueue head
    INIT_LIST_HEAD(&daemon_list.head);

    // 登記要接收的 signal
    allow_signal(SIGKILL);
    allow_signal(SIGTERM);

    // 判斷執行緒是否該被中止
    while (!kthread_should_stop()) {
        // 接受 client 連線要求
        int err = kernel_accept(param->listen_socket, &socket, 0);
        if (err < 0) {
            // 檢查當前執行緒是否有 signal 發生
            if (signal_pending(current))
                break;
            pr_err("kernel_accept() error: %d\n", err);
            continue;
        }

        // CMWQ 為每一個連線的請求建立一個 work 進行處理
        if (unlikely(!(work = create_work(socket)))) {
            pr_err("can't create work\n");
            continue;
        }
        // 而建立出來的 work 會由 os 分配 worker 執行，
        // 配置後由 khttp_wq 將每一個 work 用 list_head 的 linked list
        // 進行管理， 使用到 queue_work() 將 work 放入 workqueue 中排程
        queue_work(khttpd_wq, work);
    }

    daemon_list.is_stopped = true;

    // free work and workqueue
    free_work();
    destroy_workqueue(khttpd_wq);

    return 0;
}
