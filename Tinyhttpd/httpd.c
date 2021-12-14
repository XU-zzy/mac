/* J. David's webserver */
/* This is a simple webserver.
 * Created November 1999 by J. David Blackstone.
 * CSE 4344 (Network concepts), Prof. Zeigler
 * University of Texas at Arlington
 */
/* This program compiles for Sparc Solaris 2.6.
 * To compile for Linux:
 *  1) Comment out the #include <pthread.h> line.
 *  2) Comment out the line that defines the variable newthread.
 *  3) Comment out the two lines that run pthread_create().
 *  4) Uncomment the line that runs accept_request().
 *  5) Remove -lsocket from the Makefile.
 */
/* J. David 的网络服务器 */
/* 这是一个简单的网络服务器。
  * 由 J. David Blackstone 于 1999 年 11 月创建。
  * CSE 4344（网络概念），Zeigler 教授
  * 德克萨斯大学阿灵顿分校 
  */
/* 该程序为 Sparc Solaris 2.6 编译。
  * 为 Linux 编译：
  * 1) 注释掉#include <pthread.h> 行。
  * 2) 注释掉定义变量newthread 的行。
  * 3) 注释掉运行 pthread_create() 的两行。
  * 4) 取消注释运行accept_request() 的行。
  * 5) 从 Makefile 中删除 -lsocket。
  */
#include <stdio.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <ctype.h>
#include <strings.h>
#include <string.h>
#include <sys/stat.h>
#include <pthread.h>
#include <sys/wait.h>
#include <stdlib.h>
#include <stdint.h>

#define ISspace(x) isspace((int)(x))

#define SERVER_STRING "Server: jdbhttpd/0.1.0\r\n"
#define STDIN   0
#define STDOUT  1
#define STDERR  2

void accept_request(void *);
void bad_request(int);
void cat(int, FILE *);
void cannot_execute(int);
void error_die(const char *);
void execute_cgi(int, const char *, const char *, const char *);
int get_line(int, char *, int);
void headers(int, const char *);
void not_found(int);
void serve_file(int, const char *);
int startup(u_short *);
void unimplemented(int);

/**********************************************************************/
/* A request has caused a call to accept() on the server port to
 * return.  Process the request appropriately.
 * Parameters: the socket connected to the client */
// 处理从套接字上监听到的一个 HTTP 请求，在这里可以很大一部分地体现服务器处理请求流程。
/**********************************************************************/
void accept_request(void *arg)
{
    /*
        使用int时也可以使用intptr_t来保证平台的通用性，它在不同的平台上编译时长度不同，
        但都是标准的平台字长，比如64位机器它的长度就是8字节，32位机器它的长度是4字节，
        使用它可以安全地进行整数与指针的转换运算，也就是说当需要将指针作为整数运算时，将它转换成intptr_t进行运算才是安全的。
    */
    int client = (intptr_t)arg; 
    char buf[1024];
    size_t numchars;
    char method[255];
    char url[255];
    char path[512];
    size_t i, j;
    struct stat st;
    int cgi = 0;      /* becomes true if server decides this is a CGI
                       * program */
    //遍历url的指针
    char *query_string = NULL;

    //解析http报文
    //将http中的方法取出到method
    numchars = get_line(client, buf, sizeof(buf));
    i = 0; j = 0;
    while (!ISspace(buf[i]) && (i < sizeof(method) - 1))
    {
        method[i] = buf[i];
        i++;
    }
    j=i;
    method[i] = '\0';

    //判断是哪个method
    if (strcasecmp(method, "GET") && strcasecmp(method, "POST"))
    {
        unimplemented(client);
        return;
    }
    //POST方法的花瓣，需要使用cgi脚本
    if (strcasecmp(method, "POST") == 0)
        cgi = 1;

    //将URL取出到url 
    i = 0;
    //跳过空格
    while (ISspace(buf[j]) && (j < numchars))
        j++;
    while (!ISspace(buf[j]) && (i < sizeof(url) - 1) && (j < numchars))
    {
        url[i] = buf[j];
        i++; j++;
    }
    url[i] = '\0';

    //如果是GET方法
    if (strcasecmp(method, "GET") == 0)
    {
        query_string = url;
        //遍历寻找直到遇到'?'或者到达结尾
        while ((*query_string != '?') && (*query_string != '\0'))
            query_string++;
        //如果是到达'?'
        if (*query_string == '?')
        {
            cgi = 1;
            //分隔url
            *query_string = '\0';
            query_string++;
        }
    }

    //将分隔后前半部分的url拼接在htdocs后，放入path中
    sprintf(path, "htdocs%s", url);

    //如果path最后一个字符是'/'，则拼接，即请求的是首页
    if (path[strlen(path) - 1] == '/')
        strcat(path, "index.html");

    //通过该路径查找首页文件
    if (stat(path, &st) == -1) {        //获取文件信息，文件路径不合法，即找不到，则读完http后面所有信息并忽略，然后返回找不到文件的response给客户端
        while ((numchars > 0) && strcmp("\n", buf))  /* read & discard headers */
            numchars = get_line(client, buf, sizeof(buf));
        not_found(client);
    }
    else    //文件路径合法，找到了文件，则进行后续操作
    {
        //判断文件的类型再进行操作
        //如果是，目录类型，则拼接
        if ((st.st_mode & S_IFMT) == S_IFDIR)
            strcat(path, "/index.html");
        //如果是，可执行文件类型，则cgi=1，以便后面运行脚本
        if ((st.st_mode & S_IXUSR) ||
                (st.st_mode & S_IXGRP) ||
                (st.st_mode & S_IXOTH)    )
            cgi = 1;

        if (!cgi)   
            serve_file(client, path);
        else    
            execute_cgi(client, path, method, query_string);
    }

    close(client);
}

/**********************************************************************/
/* Inform the client that a request it has made has a problem.
 * Parameters: client socket 
 * 通知客户端它发出的请求有问题。
 * 参数：客户端套接字*/
/**********************************************************************/
void bad_request(int client)
{
    char buf[1024];

    sprintf(buf, "HTTP/1.0 400 BAD REQUEST\r\n");
    send(client, buf, sizeof(buf), 0);
    sprintf(buf, "Content-type: text/html\r\n");
    send(client, buf, sizeof(buf), 0);
    sprintf(buf, "\r\n");
    send(client, buf, sizeof(buf), 0);
    sprintf(buf, "<P>Your browser sent a bad request, ");
    send(client, buf, sizeof(buf), 0);
    sprintf(buf, "such as a POST without a Content-Length.\r\n");
    send(client, buf, sizeof(buf), 0);
}

/**********************************************************************/
/* Put the entire contents of a file out on a socket.  This function
 * is named after the UNIX "cat" command, because it might have been
 * easier just to do something like pipe, fork, and exec("cat").
 * Parameters: the client socket descriptor
 *             FILE pointer for the file to cat */
/*
    将文件的全部内容放在套接字上。这个函数以 UNIX 的“cat”命令命名，因为它可能更容易执行诸如 pipe、fork 和 exec("cat") 之类的操作。
    参数：要cat的文件的客户端套接字描述符FILE指针
*/
/**********************************************************************/
void cat(int client, FILE *resource)
{
    char buf[1024];

    fgets(buf, sizeof(buf), resource);
    while (!feof(resource))
    {
        send(client, buf, strlen(buf), 0);
        fgets(buf, sizeof(buf), resource);
    }
}

/**********************************************************************/
/* Inform the client that a CGI script could not be executed.
 * Parameter: the client socket descriptor. 
 * 通知客户端无法执行 CGI 脚本。
 * 参数：客户端套接字描述符。*/
/**********************************************************************/
void cannot_execute(int client)
{
    char buf[1024];

    sprintf(buf, "HTTP/1.0 500 Internal Server Error\r\n");
    send(client, buf, strlen(buf), 0);
    sprintf(buf, "Content-type: text/html\r\n");
    send(client, buf, strlen(buf), 0);
    sprintf(buf, "\r\n");
    send(client, buf, strlen(buf), 0);
    sprintf(buf, "<P>Error prohibited CGI execution.\r\n");
    send(client, buf, strlen(buf), 0);
}

/**********************************************************************/
/* Print out an error message with perror() (for system errors; based
 * on value of errno, which indicates system call errors) and exit the
 * program indicating an error. */
/**********************************************************************/
void error_die(const char *sc)
{
    perror(sc);
    exit(1);
}

/**********************************************************************/
/* Execute a CGI script.  Will need to set environment variables as
 * appropriate.
 * Parameters: client socket descriptor
 *             path to the CGI script */
/*
 *  执行 CGI 脚本。需要根据需要设置环境变量。
 *  参数：CGI 脚本的客户端套接字描述符路径
*/
/**********************************************************************/
void execute_cgi(int client, const char *path,
        const char *method, const char *query_string)
{
    char buf[1024];
    int cgi_output[2];
    int cgi_input[2];
    pid_t pid;
    int status;
    int i;
    char c;
    int numchars = 1;
    int content_length = -1;

    //buf不为空，以便进入循环
    buf[0] = 'A'; buf[1] = '\0';
    //GET请求的话读取并忽略请求后面的内容
    if (strcasecmp(method, "GET") == 0)
        while ((numchars > 0) && strcmp("\n", buf))  /* read & discard headers */
            numchars = get_line(client, buf, sizeof(buf));
    //POST请求
    else if (strcasecmp(method, "POST") == 0) /*POST*/
    {
        numchars = get_line(client, buf, sizeof(buf));
        //读出body长度大小的参数
        while ((numchars > 0) && strcmp("\n", buf))
        {
            buf[15] = '\0';
            //记录长度参数大小
            if (strcasecmp(buf, "Content-Length:") == 0)
                content_length = atoi(&(buf[16]));
            numchars = get_line(client, buf, sizeof(buf));
        }
        if (content_length == -1) {
            bad_request(client);
            return;
        }
    }
    

    sprintf(buf, "HTTP/1.0 200 OK\r\n");
    send(client, buf, strlen(buf), 0);

    //创建管道进行进程间通信
    if (pipe(cgi_output) < 0) {
        cannot_execute(client);
        return;
    }
    if (pipe(cgi_input) < 0) {
        cannot_execute(client);
        return;
    }

    if ( (pid = fork()) < 0 ) {
        cannot_execute(client);
        return;
    }
    
    //子进程执行cgi脚本
    if (pid == 0)  /* child: CGI script */
    {
        char meth_env[255];
        char query_env[255];
        char length_env[255];

        //子进程的标准输出重定向到cgi_output[1]上
        dup2(cgi_output[1], STDOUT);
        //子进程的标准输入重定向到cgi_input[0]上
        dup2(cgi_input[0], STDIN);
        //关闭output的读端和cgi_input的写端 
        close(cgi_output[0]);
        close(cgi_input[1]);

        //构建环境一个变量并加入到子进程的运行环境中
        sprintf(meth_env, "REQUEST_METHOD=%s", method);
        putenv(meth_env);

        //为两种方法构造环境变量并加入到子进程中
        if (strcasecmp(method, "GET") == 0) {
            sprintf(query_env, "QUERY_STRING=%s", query_string);
            putenv(query_env);
        }
        else {   /* POST */
            sprintf(length_env, "CONTENT_LENGTH=%d", content_length);
            putenv(length_env);
        }

        //将子进程替换成另一个进程并执行cgi脚本
        execl(path, path,NULL);
        exit(0);
    } else {    /* parent */
        //父进程关闭cgi_output[1]写端和cgi_input[0]读端
        close(cgi_output[1]);
        close(cgi_input[0]);
        //如果是POST方法，就一直读，写到cgi_input中让子进程读
        if (strcasecmp(method, "POST") == 0)
            for (i = 0; i < content_length; i++) {
                recv(client, &c, 1, 0);
                write(cgi_input[1], &c, 1);
            }
        
        //从cgi_output中读取子进程的输出，发送到客户端
        while (read(cgi_output[0], &c, 1) > 0)
            send(client, &c, 1, 0);
        //关闭管道
        close(cgi_output[0]);
        close(cgi_input[1]);
        
        waitpid(pid, &status, 0);
    }
}

/**********************************************************************/
/* Get a line from a socket, whether the line ends in a newline,
 * carriage return, or a CRLF combination.  Terminates the string read
 * with a null character.  If no newline indicator is found before the
 * end of the buffer, the string is terminated with a null.  If any of
 * the above three line terminators is read, the last character of the
 * string will be a linefeed and the string will be terminated with a
 * null character.
 * Parameters: the socket descriptor
 *             the buffer to save the data in
 *             the size of the buffer
 * Returns: the number of bytes stored (excluding null) 
 * 从套接字获取一行，无论该行是否以换行符、回车符或 CRLF 组合结尾。用空字符终止读取的字符串。
 * 如果在缓冲区结束之前没有找到换行符，则字符串以空值终止。
 * 如果读取了上述三个行终止符中的任何一个，则字符串的最后一个字符将是换行符，并且字符串将以空字符终止。
 * 参数：套接字描述符
 * 保存数据的缓冲区
 * 缓冲区的大小
 * 返回：存储的字节数（不包括空值）
 */
/**********************************************************************/
int get_line(int sock, char *buf, int size)
{
    int i = 0;
    char c = '\0';
    int n;

    while ((i < size - 1) && (c != '\n'))
    {
        n = recv(sock, &c, 1, 0);
        /* DEBUG printf("%02X\n", c); */
        if (n > 0)
        {
            if (c == '\r')
            {
                n = recv(sock, &c, 1, MSG_PEEK);
                /* DEBUG printf("%02X\n", c); */
                if ((n > 0) && (c == '\n'))
                    recv(sock, &c, 1, 0);
                else
                    c = '\n';
            }
            buf[i] = c;
            i++;
        }
        else
            c = '\n';
    }
    buf[i] = '\0';

    return(i);
}

/**********************************************************************/
/* Return the informational HTTP headers about a file. */
/* 返回有关文件的信息性 HTTP 标头。 */
/* Parameters: the socket to print the headers on
 *             the name of the file */
/**********************************************************************/
void headers(int client, const char *filename)
{
    char buf[1024];
    (void)filename;  /* could use filename to determine file type 可以使用文件名来确定文件类型*/

    strcpy(buf, "HTTP/1.0 200 OK\r\n");
    send(client, buf, strlen(buf), 0);
    strcpy(buf, SERVER_STRING);
    send(client, buf, strlen(buf), 0);
    sprintf(buf, "Content-Type: text/html\r\n");
    send(client, buf, strlen(buf), 0);
    strcpy(buf, "\r\n");
    send(client, buf, strlen(buf), 0);
}

/**********************************************************************/
/* Give a client a 404 not found status message. */
/* 给客户端一个 404 not found 状态消息。 */
/**********************************************************************/
void not_found(int client)
{
    char buf[1024];

    sprintf(buf, "HTTP/1.0 404 NOT FOUND\r\n");
    send(client, buf, strlen(buf), 0);
    sprintf(buf, SERVER_STRING);
    send(client, buf, strlen(buf), 0);
    sprintf(buf, "Content-Type: text/html\r\n");
    send(client, buf, strlen(buf), 0);
    sprintf(buf, "\r\n");
    send(client, buf, strlen(buf), 0);
    sprintf(buf, "<HTML><TITLE>Not Found</TITLE>\r\n");
    send(client, buf, strlen(buf), 0);
    sprintf(buf, "<BODY><P>The server could not fulfill\r\n");
    send(client, buf, strlen(buf), 0);
    sprintf(buf, "your request because the resource specified\r\n");
    send(client, buf, strlen(buf), 0);
    sprintf(buf, "is unavailable or nonexistent.\r\n");
    send(client, buf, strlen(buf), 0);
    sprintf(buf, "</BODY></HTML>\r\n");
    send(client, buf, strlen(buf), 0);
}

/**********************************************************************/
/* Send a regular file to the client.  Use headers, and report
 * errors to client if they occur.
 * Parameters: a pointer to a file structure produced from the socket
 *              file descriptor
 *             the name of the file to serve */
/* 向客户端发送常规文件。使用标头，并在发生错误时向客户端报告。
 * 参数：指向从套接字文件描述符产生的文件结构的指针要服务的文件的名称
 */
/**********************************************************************/
void serve_file(int client, const char *filename)
{
    FILE *resource = NULL;
    int numchars = 1;
    char buf[1024];

    //先确保buf不为空，可进入循环
    buf[0] = 'A'; buf[1] = '\0';

    //读取并忽略http请求后面所有的内容
    while ((numchars > 0) && strcmp("\n", buf))  /* read & discard headers */
        numchars = get_line(client, buf, sizeof(buf));

    //打开路径所指文件
    resource = fopen(filename, "r");
    if (resource == NULL)
        not_found(client);
    else
    {
        //找到文件后，将文件的基本信息封装成response的header然后返回
        headers(client, filename);
        //读取文件内容，作为response的body发送
        cat(client, resource);
    }
    fclose(resource);
}

/**********************************************************************/
/* This function starts the process of listening for web connections
 * on a specified port.  If the port is 0, then dynamically allocate a
 * port and modify the original port variable to reflect the actual
 * port.
 * Parameters: pointer to variable containing the port to connect on
 * Returns: the socket */
/*该函数启动监听网络连接的过程
  * 在指定的端口上。 如果端口为 0，则动态分配一个
  * 端口并修改原始端口变量以反映实际端口
  * 参数：指向包含要连接的端口的变量的指针
  * 返回：套接字
*/
/**********************************************************************/
int startup(u_short *port)
{
    int httpd = 0;
    int on = 1;
    //IPV4套接字地址结构
    struct sockaddr_in name;

    //开始创建套接字
    httpd = socket(PF_INET, SOCK_STREAM, 0);
    if (httpd == -1)
        error_die("socket");
    //初始化socket地址
    memset(&name, 0, sizeof(name));
    name.sin_family = AF_INET;
    name.sin_port = htons(*port);
    name.sin_addr.s_addr = htonl(INADDR_ANY);
    //设置关闭socket后继续可重用该socket
    //避免关闭后进入TIME_WAIT状态而导致短时间内重新启动时，socket所绑定的端口不可用
    if ((setsockopt(httpd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on))) < 0)  
    {  
        error_die("setsockopt failed");
    }
    //绑定套接字和地址
    if (bind(httpd, (struct sockaddr *)&name, sizeof(name)) < 0)
        error_die("bind");
    if (*port == 0)  /* if dynamically allocating a port */ //如果传入的端口号为0，则重新分配一个端口
    {
        socklen_t namelen = sizeof(name);
        if (getsockname(httpd, (struct sockaddr *)&name, &namelen) == -1)
            error_die("getsockname");
        *port = ntohs(name.sin_port);
    }
    //监听
    //内核2.2以后，backlog参数只指处于完全连接的socket的上限，处于半连接的socket的上限在内核参数中定义
    if (listen(httpd, 5) < 0)
        error_die("listen");
    return(httpd);
}

/**********************************************************************/
/* Inform the client that the requested web method has not been
 * implemented.
 * Parameter: the client socket 
 * 通知客户端所请求的 Web 方法尚未实现。
 * 参数：客户端套接字
 */
/**********************************************************************/
void unimplemented(int client)
{
    char buf[1024];

    sprintf(buf, "HTTP/1.0 501 Method Not Implemented\r\n");
    send(client, buf, strlen(buf), 0);
    sprintf(buf, SERVER_STRING);
    send(client, buf, strlen(buf), 0);
    sprintf(buf, "Content-Type: text/html\r\n");
    send(client, buf, strlen(buf), 0);
    sprintf(buf, "\r\n");
    send(client, buf, strlen(buf), 0);
    sprintf(buf, "<HTML><HEAD><TITLE>Method Not Implemented\r\n");
    send(client, buf, strlen(buf), 0);
    sprintf(buf, "</TITLE></HEAD>\r\n");
    send(client, buf, strlen(buf), 0);
    sprintf(buf, "<BODY><P>HTTP request method not supported.\r\n");
    send(client, buf, strlen(buf), 0);
    sprintf(buf, "</BODY></HTML>\r\n");
    send(client, buf, strlen(buf), 0);
}

/**********************************************************************/

int main(void)
{
    int server_sock = -1;
    u_short port = 4000;
    int client_sock = -1;
    struct sockaddr_in client_name;
    socklen_t  client_name_len = sizeof(client_name);
    pthread_t newthread;

    //启动监听，获取服务端套接字
    server_sock = startup(&port);
    printf("httpd running on port %d\n", port);

    while (1)
    {
        //接收连接
        client_sock = accept(server_sock,
                (struct sockaddr *)&client_name,
                &client_name_len);
        if (client_sock == -1)
            error_die("accept");
        /* accept_request(&client_sock); */
        if (pthread_create(&newthread , NULL, (void *)accept_request, (void *)(intptr_t)client_sock) != 0)
            perror("pthread_create");
    }

    close(server_sock);

    return(0);
}
