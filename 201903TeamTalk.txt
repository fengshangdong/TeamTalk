/************************************************
 * TeamTalk - 服务端源码阅读.
 * vim 配置文件: .vimrc
 * vim 折叠信息: .vim/view/~=+201903TeamTalk.txt=
 *
 * TODO:
 * 1.db_proxy_server
 *   |- async.h
 *   |- DBPool.h
 *   |- DBPool.cpp
 *   |- CachePool.h
 *   |- CachePool.cpp
 *   |- AutoPool.h
 *   |- AutoPool.cpp
 *   |- HandlerMap.h
 *   |- HandlerMap.cpp
 *   |- ProxyTask.h
 *   |- ProxyTask.cpp
 *   |- ProxyConn.h
 *   |- ProxyConn.cpp
 *   |- SyncCenter.h
 *   |- SyncCenter.cpp
 *   |- db_proxy_server.cpp
 *   |- business(业务逻辑)
 *      |- Login.h
 *      |- Login.cpp
 *      |- LoginStrategy.h
 *      |- InterLogin.h
 *      |- InterLogin.cpp
 *      |- ExterLogin.h
 *      |- ExterLogin.cpp
 *      |- UserModel.h
 *      |- UserModel.cpp
 *      |- UserAction.h
 *      |- UserAction.cpp
 *      |- SessionModel.h
 *      |- SessionModel.cpp
 *      |- RecentSession.h
 *      |- RecentSession.cpp
 *      |- RelationModel.h
 *      |- RelationModel.cpp
 *
************************************************/

/* db_proxy_server - 数据库代理服务器,提供mysql以及redis的访问服务.
 * msg_server - 消息服务器,提供客户端大部分信令处理功能,包括私人聊天 群组聊天等.
 * login_server - 负载均衡服务器,分配一个负载小的MsgServer给客户端使用.
 * msfs_server -  图片存储服务器,提供头像,图片传输中的图片存储服务.
 * file_server - 文件服务器,提供客户端之间得文件传输服务,支持在线以及离线文件传输.
 * route_server -路由服务器,为登录在不同MsgServer的用户提供消息转发功能.
 * http_msg_server - 对外接口服务器,提供对外接口功能.
 * push_server - 消息推送服务器,提供IOS系统消息推送.
 */

/* db_proxy_server - async.h */
#ifndef __HIREDIS_ASYNC_H
#define __HIREDIS_ASYNC_H
#include "hiredis.h"

#ifdef __cplusplus
extern "C" {
#endif

/* redis客户端-Hiredis异步API接口.
 * redisAsyncContext 前置声明, 该异步数据结构在下文中有定义.
 * dict 是Redis字典数据结构.
 */
struct redisAsyncContext; /* need forward declaration of redisAsyncContext */
struct dict; /* dictionary header is included in async.c */

/* Reply callback prototype and container */
/* redisCallbackFn是回调函数原型 */
typedef void (redisCallbackFn)(struct redisAsyncContext*, void*, void*);

/* redisCallback是redisCallbackList -  Redis回调函数链表的结点 */
typedef struct redisCallback {
  struct redisCallback *next; /* simple singly linked list */
  redisCallbackFn *fn;
  void *privdata;
} redisCallback;

/* List of callbacks for either regular replies or pub/sub */
/* redisCallbackList是回调函数链表 */
typedef struct redisCallbackList {
  redisCallback *head, *tail;
} redisCallbackList;

/* Connection callback prototypes */
/* redis连接回调和断开连接回调函数原型 */
typedef void (redisDisconnectCallback)(const struct redisAsyncContext*, int status);
typedef void (redisConnectCallback)(const struct redisAsyncContext*, int status);

/* Context for an async connection to Redis */
/* 异步连接Redis的 "Redis连接信息" 结构体 */
typedef struct redisAsyncContext {
  /* Hold the regular context, so it can be realloc'ed. */
  /* c 是Redis连接套接字 */
  redisContext c;

  /* Setup error flags so they can be used directly. */
  int err;
  char *errstr;

  /* Not used by hiredis */
  void *data;

  /* Event library data and hooks */
  /* 事件数据和钩子函数 */
  /* 插入删除读写事件 和 cleanup清理事件*/
  struct {
    void *data;

    /* Hooks that are called when the library expects to start
     * reading/writing. These functions should be idempotent.
     */
    void (*addRead)(void *privdata);
    void (*delRead)(void *privdata);
    void (*addWrite)(void *privdata);
    void (*delWrite)(void *privdata);
    void (*cleanup)(void *privdata);
  } ev;

  /* Called when either the connection is terminated due to an error or per
   * user request. The status is set accordingly (REDIS_OK, REDIS_ERR). */
  /* Redis断开连接回调函数指针 */
  redisDisconnectCallback *onDisconnect;

  /* Called when the first write event was received. */
  /* Redis建立连接回调函数指针 */
  redisConnectCallback *onConnect;

  /* Regular command callbacks */
  /* Redis 回调函数链表 */
  redisCallbackList replies;

  /* Subscription callbacks */
  /* 消息订阅 */
  struct {
    redisCallbackList invalid;
    struct dict *channels;
    struct dict *patterns;
  } sub;
} redisAsyncContext;

/* Functions that proxy to hiredis.
 * hiredis客户端API接口.
 * redisAsyncConnect 连接Redis.
 * redisAsyncConnectBind 绑定地址-连接Redis.
 * redisAsyncConnectBindWithReuse 绑定地址并端口复用-连接Redis.
 * redisAsyncConnectUnix 连接Unix.
 * redisAsyncSetConnectCallback 设置Redis建立连接回调函数.
 * redisAsyncSetDisconnectCallback 设置Redis断开连接回调函数.
 * redisAsyncDisconnect 断开连接.
 * redisAsyncFree 释放内存
 */
redisAsyncContext *redisAsyncConnect(const char *ip, int port);
redisAsyncContext *redisAsyncConnectBind(const char *ip, int port, const char *source_addr);
redisAsyncContext *redisAsyncConnectBindWithReuse(const char *ip, int port, const char *source_addr);
redisAsyncContext *redisAsyncConnectUnix(const char *path);
int redisAsyncSetConnectCallback(redisAsyncContext *ac, redisConnectCallback *fn);
int redisAsyncSetDisconnectCallback(redisAsyncContext *ac, redisDisconnectCallback *fn);
void redisAsyncDisconnect(redisAsyncContext *ac);
void redisAsyncFree(redisAsyncContext *ac);

/* Handle read/write events */
/* hiredis客户端执行读写事件 */
void redisAsyncHandleRead(redisAsyncContext *ac);
void redisAsyncHandleWrite(redisAsyncContext *ac);

/* Command functions for an async context. Write the command to the
 * output buffer and register the provided callback. */
/* hiredis客户端写入命令注册回调函数 */
int redisvAsyncCommand(redisAsyncContext *ac, redisCallbackFn *fn, void *privdata, const char *format, va_list ap);
int redisAsyncCommand(redisAsyncContext *ac, redisCallbackFn *fn, void *privdata, const char *format, ...);
int redisAsyncCommandArgv(redisAsyncContext *ac, redisCallbackFn *fn, void *privdata, int argc, const char **argv, const size_t *argvlen);
int redisAsyncFormattedCommand(redisAsyncContext *ac, redisCallbackFn *fn, void *privdata, const char *cmd, size_t len);

#ifdef __cplusplus
}
#endif

#endif

/* db_proxy_server - DBPool.h */
#ifndef DBPOOL_H_
#define DBPOOL_H_

#include "../base/util.h"
#include "ThreadPool.h"
#include <mysql.h>

#define MAX_ESCAPE_STRING_LEN	10240

/* MySql数据结构
 * MYSQL - This structure represents handler for one database connection.
 * MYSQL 是数据库连接的句柄,类似于套接字socket.
 * MYSQL_RES - This structure represents the result of a query that returns rows (SELECT, SHOW, DESCRIBE, EXPLAIN).
 * MYSQL_RES 是用于做为资源的结构体.
 * MYSQL_ROW - This is a type-safe representation of one row of data.
 * MYSQL_ROW 是MYSQL自带的结构类型(定义域mysql.h中的字符串数组,typedef char **MYSQL_ROW;).
 * MYSQL_FIELD - This structure contains metadata: information about a field, such as the field's name, type, and size.
 * MYSQL_FIELD 是表字段. 
 * MYSQL_STMT - This structure is a handler for a prepared statement.
 * MYSQL_STMT 是预处理程序的句柄, mysql_stmt_init()返回的一个MYSQL_STMT指针.
 * MYSQL_BIND - This structure is used both for statement input and output.
 * MYSQL_BIND 提供预处理程序的输入输出参数.
 * --作为输入参数使用时,先使用mysql_stmt_bind_param()绑定参数,之后再执行mysql_stmt_execute().
 * --作为输出参数使用时,需要mysql_stmt_bind_result()将结果绑定到缓存,用 mysql_stmt_fetch()获取一行结果.
 *
 * 23.8.8 C API Prepared Statements(预处理语句)
 * MySQL可以使用预处理语句.通过使用 mysql_stmt_init() 初始化方法返回一个MYSQL_STMT*句柄.
 * Prepared Statements对一条语句执行多次效率很高,因为语句只有第一次执行时被解析,之后
 * 再次执行都是使用已经初始化的MYSQL_STMT*句柄.
 *
 * 23.8.9 C API Prepared Statement Data Structures(预处理语句数据结构).
 * 传参MYSQL连接句柄给mysql_stmt_init(MYSQL *mysql),返回一个MYSQL_STMT数据结构指针.
 * 将MYSQL_STMT指针和指定预处理的sql语句传给mysql_stmt_prepare(),后者将返回一个状态值.
 * 预处理的sql语句结尾不需要";"分号.且sql语句传参使用"?"做参数标志符号.例如:
 * "INSERT INTO test_table(col1,col2,col3) VALUES(?,?,?)"
 * "SELECT col1,col2,col3,col4 FROM test_table"
 * 所以执行sql语句之前,需要使用mysql_stmt_bind_param()对"?"标识符根据其参数类型绑定实际参数.
 * 为了提供输入参数,需要设置MYSQL_BIND数据结构并且传参至mysql_stmt_bind_param().
 * 同理为了获取返回结果, 需要设置MYSQL_BIND数据结构并且传参至mysql_stmt_bind_result().
 */
 
/* CResultSet - MYSQL资源对象,保存MYSQL查询语句的执行结果集 */
class CResultSet {
public:
  CResultSet(MYSQL_RES* res);
  virtual ~CResultSet();

  bool Next();
  int GetInt(const char* key);
  char* GetString(const char* key);
private:
  int _GetIndex(const char* key);

  MYSQL_RES*  m_res;
  MYSQL_ROW   m_row;
  map<string, int> m_key_map;
};

/* CPrepareStatement - SQL语句预处理对象 */
class CPrepareStatement {
public:
  CPrepareStatement();
  virtual ~CPrepareStatement();

  bool Init(MYSQL* mysql, string& sql);

  void SetParam(uint32_t index, int& value);
  void SetParam(uint32_t index, uint32_t& value);
  void SetParam(uint32_t index, string& value);
  void SetParam(uint32_t index, const string& value);

  bool ExecuteUpdate();
  CResultSet* ExecuteQuery();
  uint32_t GetInsertId();
private:
  MYSQL_STMT* m_stmt;
  MYSQL_BIND* m_param_bind;
  uint32_t    m_param_cnt;
};

class CDBPool;

/* 数据库连接对象 */
class CDBConn {
public:
  CDBConn(CDBPool* pDBPool);
  virtual ~CDBConn();
  int Init();

  CResultSet* ExecuteQuery(const char* sql_query);
  bool ExecuteUpdate(const char* sql_query);
  char* EscapeString(const char* content, uint32_t content_len);

  uint32_t GetInsertId();

  const char* GetPoolName();
  MYSQL* GetMysql() { return m_mysql; }
private:
  CDBPool*  m_pDBPool;	// to get MySQL server information
  MYSQL*    m_mysql;
  //MYSQL_RES* m_res;
  char      m_escape_string[MAX_ESCAPE_STRING_LEN + 1];
};


/* 数据库连接池 */
class CDBPool {
public:
  CDBPool(const char* pool_name, const char* db_server_ip, uint16_t db_server_port,
          const char* username, const char* password, const char* db_name, int max_conn_cnt);
  virtual ~CDBPool();

  int Init();
  CDBConn* GetDBConn();
  void RelDBConn(CDBConn* pConn);

  const char* GetPoolName() { return m_pool_name.c_str(); }
  const char* GetDBServerIP() { return m_db_server_ip.c_str(); }
  uint16_t GetDBServerPort() { return m_db_server_port; }
  const char* GetUsername() { return m_username.c_str(); }
  const char* GetPasswrod() { return m_password.c_str(); }
  const char* GetDBName() { return m_db_name.c_str(); }
private:
  string    m_pool_name;
  string    m_db_server_ip;
  uint16_t  m_db_server_port;
  string    m_username;
  string    m_password;
  string    m_db_name;
  int       m_db_cur_conn_cnt;
  int       m_db_max_conn_cnt;
  list<CDBConn*> m_free_list;
  CThreadNotify  m_free_notify;
};

// manage db pool (master for write and slave for read)
/* 管理连接池(单例模式) */
class CDBManager {
public:
  virtual ~CDBManager();

  static CDBManager* getInstance();

  int Init();

  CDBConn* GetDBConn(const char* dbpool_name);
  void RelDBConn(CDBConn* pConn);
private:
  CDBManager();

private:
  static CDBManager*    s_db_manager;
  map<string, CDBPool*> m_dbpool_map;
};

#endif /* DBPOOL_H_ */

/* db_proxy_server - DBPool.cpp */
#include "DBPool.h"
#include "ConfigFileReader.h"

#define MIN_DB_CONN_CNT		2

CDBManager* CDBManager::s_db_manager = NULL;

/* CResultSet 构造函数,构造MYSQL资源对象(即MYSQL的查询执行结果)
 * mysql_num_fields() 函数返回结果集中字段的数.
 * mysql_fetch_fields(res) - 获取表字段字符串数组MYSQL_FIELD的指针.
 * 将表字段名和对应的下标位置插入到 m_key_map.
 */
CResultSet::CResultSet(MYSQL_RES* res)
{
  m_res = res;

  // map table field key to index in the result array
  int num_fields = mysql_num_fields(m_res);
  MYSQL_FIELD* fields = mysql_fetch_fields(m_res);
  for(int i = 0; i < num_fields; i++)
  {
    m_key_map.insert(make_pair(fields[i].name, i));
  }
}

/* 释放MYSQL资源 */
CResultSet::~CResultSet()
{
  if (m_res) {
    mysql_free_result(m_res);
    m_res = NULL;
  }
}

/* mysql_fetch_row(res) - Retrieves the next row of a result set.
 * 获取MYSQL执行结果的下一行. 指针会依次从row[0]遍历到row[num_fields-1].
 */
bool CResultSet::Next()
{
  m_row = mysql_fetch_row(m_res);
  if (m_row) {
    return true;
  } else {
    return false;
  }
}

/* 取构造函数中初始化<表字段,下标> m_key_map 中对应字段的下标位置. */
int CResultSet::_GetIndex(const char* key)
{
  map<string, int>::iterator it = m_key_map.find(key);
  if (it == m_key_map.end()) {
    return -1;
  } else {
    return it->second;
  }
}

/* 根据表字段下标值,获取该下标的行数据(整形). */
int CResultSet::GetInt(const char* key)
{
  int idx = _GetIndex(key);
  if (idx == -1) {
    return 0;
  } else {
    return atoi(m_row[idx]);
  }
}

/* 根据表字段下标值,获取该下标的行数据(字符串). */
char* CResultSet::GetString(const char* key)
{
  int idx = _GetIndex(key);
  if (idx == -1) {
    return NULL;
  } else {
    return m_row[idx];
  }
}

/////////////////////////////////////////
CPrepareStatement::CPrepareStatement()
{
  m_stmt = NULL;
  m_param_bind = NULL;
  m_param_cnt = 0;
}

CPrepareStatement::~CPrepareStatement()
{
  if (m_stmt) {
    mysql_stmt_close(m_stmt);
    m_stmt = NULL;
  }

  if (m_param_bind) {
    delete [] m_param_bind;
    m_param_bind = NULL;
  }
}

/* mysql_ping() - Checks whether the connection to the server is working.
 * mysql_stmt_init(mysql) - Allocates memory for a MYSQL_STMT structure and initializes it.
 * mysql_stmt_prepare(...) - Prepares an SQL statement string for execution.
 * mysql_stmt_param_count(stmt) - Returns the number of parameters in a prepared statement.
 * memset(m_param_bind, 0, sizeof(MYSQL_BIND) * m_param_cnt); 置零,m_param_bind是输入输出参数.
 */
bool CPrepareStatement::Init(MYSQL* mysql, string& sql)
{
  mysql_ping(mysql);

  m_stmt = mysql_stmt_init(mysql);
  if (!m_stmt) {
    log("mysql_stmt_init failed");
    return false;
  }

  if (mysql_stmt_prepare(m_stmt, sql.c_str(), sql.size())) {
    log("mysql_stmt_prepare failed: %s", mysql_stmt_error(m_stmt));
    return false;
  }

  m_param_cnt = mysql_stmt_param_count(m_stmt);
  if (m_param_cnt > 0) {
    m_param_bind = new MYSQL_BIND [m_param_cnt];
    if (!m_param_bind) {
      log("new failed");
      return false;
    }

    memset(m_param_bind, 0, sizeof(MYSQL_BIND) * m_param_cnt);
  }

  return true;
}

void CPrepareStatement::SetParam(uint32_t index, int& value)
{
  if (index >= m_param_cnt) {
    log("index too large: %d", index);
    return;
  }

  m_param_bind[index].buffer_type = MYSQL_TYPE_LONG;
  m_param_bind[index].buffer = &value;
}

void CPrepareStatement::SetParam(uint32_t index, uint32_t& value)
{
  if (index >= m_param_cnt) {
    log("index too large: %d", index);
    return;
  }

  m_param_bind[index].buffer_type = MYSQL_TYPE_LONG;
  m_param_bind[index].buffer = &value;
}

void CPrepareStatement::SetParam(uint32_t index, string& value)
{
  if (index >= m_param_cnt) {
    log("index too large: %d", index);
    return;
  }

  m_param_bind[index].buffer_type = MYSQL_TYPE_STRING;
  m_param_bind[index].buffer = (char*)value.c_str();
  m_param_bind[index].buffer_length = value.size();
}

void CPrepareStatement::SetParam(uint32_t index, const string& value)
{
  if (index >= m_param_cnt) {
    log("index too large: %d", index);
    return;
  }

  m_param_bind[index].buffer_type = MYSQL_TYPE_STRING;
  m_param_bind[index].buffer = (char*)value.c_str();
  m_param_bind[index].buffer_length = value.size();
}

/* CPrepareStatement::SetParam() 给m_param_bind设置执行sql语句参数.
 * mysql_stmt_bind_param() 绑定参数.
 * mysql_stmt_execute() 执行sql语句.
 * mysql_stmt_affected_rows() 返回执行sql的执行效果.
 */
bool CPrepareStatement::ExecuteUpdate()
{
  if (!m_stmt) {
    log("no m_stmt");
    return false;
  }

  if (mysql_stmt_bind_param(m_stmt, m_param_bind)) {
    log("mysql_stmt_bind_param failed: %s", mysql_stmt_error(m_stmt));
    return false;
  }

  if (mysql_stmt_execute(m_stmt)) {
    log("mysql_stmt_execute failed: %s", mysql_stmt_error(m_stmt));
    return false;
  }

  if (mysql_stmt_affected_rows(m_stmt) == 0) {
    log("ExecuteUpdate have no effect");
    return false;
  }

  return true;
}

/* mysql_stmt_bind_param() 绑定m_param_bind参数.
 * mysql_stmt_execute() 执行sql语句,返回执行状态.
 * mysql_stmt_result_metadata()返回执行结果 MYSQL_RES* 指针.
 * new CResultSet(res), 初始化CResultSet对象.
 */
CResultSet* CPrepareStatement::ExecuteQuery() {

  if(!m_stmt) {
    log("no m_stmt");
    return NULL;
  }

  if (mysql_stmt_bind_param(m_stmt, m_param_bind)) {
    log("mysql_stmt_bind_param failed: %s", mysql_stmt_error(m_stmt));
    return NULL;
  }

  if (mysql_stmt_execute(m_stmt)) {
    log("mysql_stmt_execute failed: %s", mysql_stmt_error(m_stmt));
    return NULL;
  }

  MYSQL_RES* res = mysql_stmt_result_metadata(m_stmt);
  if (!res) {
    log("mysql_stmt_result_metadata failed: %s", mysql_stmt_error(m_stmt));
    return NULL;
  }

  CResultSet* result_set = new CResultSet(res);
  return result_set;

}

uint32_t CPrepareStatement::GetInsertId()
{
  return mysql_stmt_insert_id(m_stmt);
}

/////////////////////
CDBConn::CDBConn(CDBPool* pPool)
{
  m_pDBPool = pPool;
  m_mysql = NULL;
}

CDBConn::~CDBConn()
{
}

/* mysql_init() - Allocates or initializes a MYSQL object suitable for mysql_real_connect(). 
 * 初始化MYSQL示例,适配mysql_real_connect()函数建立连接.连接句柄是m_mysql.
 */ 
int CDBConn::Init()
{
  m_mysql = mysql_init(NULL);
  if (!m_mysql) {
    log("mysql_init failed");
    return 1;
  }

  my_bool reconnect = true;
  mysql_options(m_mysql, MYSQL_OPT_RECONNECT, &reconnect);
  mysql_options(m_mysql, MYSQL_SET_CHARSET_NAME, "utf8mb4");

  if (!mysql_real_connect(m_mysql, m_pDBPool->GetDBServerIP(), m_pDBPool->GetUsername(), m_pDBPool->GetPasswrod(),
        m_pDBPool->GetDBName(), m_pDBPool->GetDBServerPort(), NULL, 0)) {
    log("mysql_real_connect failed: %s", mysql_error(m_mysql));
    return 2;
  }

  return 0;
}

const char* CDBConn::GetPoolName()
{
  return m_pDBPool->GetPoolName();
}

/* mysql_real_query() 执行sql语句.
 * mysql_store_result() 返回执行结果保存在 MYSQL_RES* 中.
 */
CResultSet* CDBConn::ExecuteQuery(const char* sql_query)
{
  mysql_ping(m_mysql);

  if (mysql_real_query(m_mysql, sql_query, strlen(sql_query))) {
    log("mysql_real_query failed: %s, sql: %s", mysql_error(m_mysql), sql_query);
    return NULL;
  }

  MYSQL_RES* res = mysql_store_result(m_mysql);
  if (!res) {
    log("mysql_store_result failed: %s", mysql_error(m_mysql));
    return NULL;
  }

  CResultSet* result_set = new CResultSet(res);
  return result_set;
}

/* 执行sql语句,mysql_affected_rows()判断是否生效. */
bool CDBConn::ExecuteUpdate(const char* sql_query)
{
  mysql_ping(m_mysql);

  if (mysql_real_query(m_mysql, sql_query, strlen(sql_query))) {
    log("mysql_real_query failed: %s, sql: %s", mysql_error(m_mysql), sql_query);
    return false;
  }

  if (mysql_affected_rows(m_mysql) > 0) {
    return true;
  } else {
    return false;
  }
}

/* mysql_real_escape_string() 函数转义 SQL 语句中使用的字符串中的特殊字符,防注入攻击 */
char* CDBConn::EscapeString(const char* content, uint32_t content_len)
{
  if (content_len > (MAX_ESCAPE_STRING_LEN >> 1)) {
    m_escape_string[0] = 0;
  } else {
    mysql_real_escape_string(m_mysql, m_escape_string, content, content_len);
  }

  return m_escape_string;
}

uint32_t CDBConn::GetInsertId()
{
  return (uint32_t)mysql_insert_id(m_mysql);
}

////////////////
CDBPool::CDBPool(const char* pool_name, const char* db_server_ip, uint16_t db_server_port,
    const char* username, const char* password, const char* db_name, int max_conn_cnt)
{
  m_pool_name = pool_name;
  m_db_server_ip = db_server_ip;
  m_db_server_port = db_server_port;
  m_username = username;
  m_password = password;
  m_db_name = db_name;
  m_db_max_conn_cnt = max_conn_cnt;
  m_db_cur_conn_cnt = MIN_DB_CONN_CNT;
}

CDBPool::~CDBPool()
{
  for (list<CDBConn*>::iterator it = m_free_list.begin(); it != m_free_list.end(); it++) {
    CDBConn* pConn = *it;
    delete pConn;
  }

  m_free_list.clear();
}

/* 初始化数据库连接池, new 连接资源CDBConn存入到m_free_list空闲MySQL连接队列 */
int CDBPool::Init()
{
  for (int i = 0; i < m_db_cur_conn_cnt; i++) {
    CDBConn* pDBConn = new CDBConn(this);
    int ret = pDBConn->Init();
    if (ret) {
      delete pDBConn;
      return ret;
    }

    m_free_list.push_back(pDBConn);
  }

  log("db pool: %s, size: %d", m_pool_name.c_str(), (int)m_free_list.size());
  return 0;
}

/*
 *TODO: 增加保护机制,把分配的连接加入另一个队列,这样获取连接时,如果没有空闲连接,
 *TODO: 检查已经分配的连接多久没有返回,如果超过一定时间,则自动收回连接,放在用户忘了调用释放连接的接口
 */
/* 取m_free_list空闲MySQL连接队列的连接, 如果m_free_list为空,则new一个连接.
 * 如果当前连接数大于最大连接数, 则挂起等待RelDBConn()回收资源.
 */
CDBConn* CDBPool::GetDBConn()
{
  m_free_notify.Lock();

  while (m_free_list.empty()) {
    if (m_db_cur_conn_cnt >= m_db_max_conn_cnt) {
      m_free_notify.Wait();
    } else {
      CDBConn* pDBConn = new CDBConn(this);
      int ret = pDBConn->Init();
      if (ret) {
        log("Init DBConnecton failed");
        delete pDBConn;
        m_free_notify.Unlock();
        return NULL;
      } else {
        m_free_list.push_back(pDBConn);
        m_db_cur_conn_cnt++;
        log("new db connection: %s, conn_cnt: %d", m_pool_name.c_str(), m_db_cur_conn_cnt);
      }
    }
  }

  CDBConn* pConn = m_free_list.front();
  m_free_list.pop_front();

  m_free_notify.Unlock();

  return pConn;
}

/* 回收MySQL连接资源,重新保存到m_free_list,
 * 同时发出条件变量信号.解除GetDBConn()的条件等待.
 * 如果所有的pConn连接资源重新回到m_free_list中, 析构操作可以完整释放内存.
 */
void CDBPool::RelDBConn(CDBConn* pConn)
{
  m_free_notify.Lock();

  list<CDBConn*>::iterator it = m_free_list.begin();
  for (; it != m_free_list.end(); it++) {
    if (*it == pConn) {
      break;
    }
  }

  if (it == m_free_list.end()) {
    m_free_list.push_back(pConn);
  }

  m_free_notify.Signal();
  m_free_notify.Unlock();
}

/////////////////
CDBManager::CDBManager()
{

}

CDBManager::~CDBManager()
{

}

/* 获取单例, 自动初始化MySQL连接池. */
CDBManager* CDBManager::getInstance()
{
  if (!s_db_manager) {
    s_db_manager = new CDBManager();
    if (s_db_manager->Init()) {
      delete s_db_manager;
      s_db_manager = NULL;
    }
  }

  return s_db_manager;
}
/*
 * 2015-01-12
 * modify by ZhangYuanhao :enable config the max connection of every instance
 *
 */
/*
 * 初始化 teamtalk_master,teamtalk_slave 2个MySQL连接池实例.
 */
int CDBManager::Init()
{
  CConfigFileReader config_file("dbproxyserver.conf");

  char* db_instances = config_file.GetConfigName("DBInstances");

  if (!db_instances) {
    log("not configure DBInstances");
    return 1;
  }

  char host[64];
  char port[64];
  char dbname[64];
  char username[64];
  char password[64];
  char maxconncnt[64];
  CStrExplode instances_name(db_instances, ',');

  for (uint32_t i = 0; i < instances_name.GetItemCnt(); i++) {
    char* pool_name = instances_name.GetItem(i);
    snprintf(host, 64, "%s_host", pool_name);
    snprintf(port, 64, "%s_port", pool_name);
    snprintf(dbname, 64, "%s_dbname", pool_name);
    snprintf(username, 64, "%s_username", pool_name);
    snprintf(password, 64, "%s_password", pool_name);
    snprintf(maxconncnt, 64, "%s_maxconncnt", pool_name);

    char* db_host = config_file.GetConfigName(host);
    char* str_db_port = config_file.GetConfigName(port);
    char* db_dbname = config_file.GetConfigName(dbname);
    char* db_username = config_file.GetConfigName(username);
    char* db_password = config_file.GetConfigName(password);
    char* str_maxconncnt = config_file.GetConfigName(maxconncnt);

    if (!db_host || !str_db_port || !db_dbname || !db_username || !db_password || !str_maxconncnt) {
      log("not configure db instance: %s", pool_name);
      return 2;
    }

    int db_port = atoi(str_db_port);
    int db_maxconncnt = atoi(str_maxconncnt);
    CDBPool* pDBPool = new CDBPool(pool_name, db_host, db_port, db_username, db_password, db_dbname, db_maxconncnt);
    if (pDBPool->Init()) {
      log("init db instance failed: %s", pool_name);
      return 3;
    }
    m_dbpool_map.insert(make_pair(pool_name, pDBPool));
  }

  return 0;
}

/* 获取连接池dbpool_name中一条MySQL连接资源 */
CDBConn* CDBManager::GetDBConn(const char* dbpool_name)
{
  map<string, CDBPool*>::iterator it = m_dbpool_map.find(dbpool_name);
  if (it == m_dbpool_map.end()) {
    return NULL;
  } else {
    return it->second->GetDBConn();
  }
}

/* 回收该MySQL连接资源 */
void CDBManager::RelDBConn(CDBConn* pConn)
{
  if (!pConn) {
    return;
  }

  map<string, CDBPool*>::iterator it = m_dbpool_map.find(pConn->GetPoolName());
  if (it != m_dbpool_map.end()) {
    it->second->RelDBConn(pConn);
  }
}

/* db_proxy_server - CachePool.h */
#ifndef CACHEPOOL_H_
#define CACHEPOOL_H_

#include <vector>
#include "../base/util.h"
#include "ThreadPool.h"
#include "hiredis.h"

class CachePool;

class CacheConn {
public:
  CacheConn(CachePool* pCachePool);
  virtual ~CacheConn();

  int Init();
  const char* GetPoolName();

  string get(string key);
  string setex(string key, int timeout, string value);
  string set(string key, string& value);

  //批量获取
  bool mget(const vector<string>& keys, map<string, string>& ret_value);
  // 判断一个key是否存在
  bool isExists(string &key);

  // Redis hash structure
  long hdel(string key, string field);
  string hget(string key, string field);
  bool hgetAll(string key, map<string, string>& ret_value);
  long hset(string key, string field, string value);

  long hincrBy(string key, string field, long value);
  long incrBy(string key, long value);
  string hmset(string key, map<string, string>& hash);
  bool hmget(string key, list<string>& fields, list<string>& ret_value);

  //原子加减1
  long incr(string key);
  long decr(string key);

  // Redis list structure
  long lpush(string key, string value);
  long rpush(string key, string value);
  long llen(string key);
  bool lrange(string key, long start, long end, list<string>& ret_value);

private:
  CachePool*    m_pCachePool;
  redisContext* m_pContext;
  uint64_t      m_last_connect_time;
};

class CachePool {
public:
  CachePool(const char* pool_name, const char* server_ip,
            int server_port, int db_num, int max_conn_cnt);
  virtual ~CachePool();

  int Init();

  CacheConn* GetCacheConn();
  void RelCacheConn(CacheConn* pCacheConn);

  const char* GetPoolName() { return m_pool_name.c_str(); }
  const char* GetServerIP() { return m_server_ip.c_str(); }
  int GetServerPort() { return m_server_port; }
  int GetDBNum() { return m_db_num; }
private:
  string m_pool_name;
  string m_server_ip;
  int    m_server_port;
  int    m_db_num;

  int    m_cur_conn_cnt;
  int    m_max_conn_cnt;
  list<CacheConn*> m_free_list;
  CThreadNotify    m_free_notify;
};

class CacheManager {
public:
  virtual ~CacheManager();

  static CacheManager* getInstance();

  int Init();
  CacheConn* GetCacheConn(const char* pool_name);
  void RelCacheConn(CacheConn* pCacheConn);
private:
  CacheManager();

private:
  static CacheManager*    s_cache_manager;
  map<string, CachePool*>	m_cache_pool_map;
};

#endif /* CACHEPOOL_H_ */

/* db_proxy_server - CachePool.cpp */
#include "CachePool.h"
#include "ConfigFileReader.h"

#define MIN_CACHE_CONN_CNT	2

CacheManager* CacheManager::s_cache_manager = NULL;

CacheConn::CacheConn(CachePool* pCachePool)
{
  m_pCachePool = pCachePool;
  m_pContext = NULL;
  m_last_connect_time = 0;
}

CacheConn::~CacheConn()
{
  if (m_pContext) {
    redisFree(m_pContext);
    m_pContext = NULL;
  }
}

/* redis初始化连接和重连操作
 * redisConnectWithTimeout() 返回一个Redis连接句柄redisContext *m_pContext,
 * 其 redisContext 数据结构的内部实现是套接字socket, 即返回一个连接套接字connfd.
 */
int CacheConn::Init()
{
  if (m_pContext) {
    return 0;
  }

  // 4s 尝试重连一次
  uint64_t cur_time = (uint64_t)time(NULL);
  if (cur_time < m_last_connect_time + 4) {
    return 1;
  }

  m_last_connect_time = cur_time;

  // 200ms超时
  struct timeval timeout = {0, 200000};
  m_pContext = redisConnectWithTimeout(m_pCachePool->GetServerIP(), m_pCachePool->GetServerPort(), timeout);
  if (!m_pContext || m_pContext->err) {
    if (m_pContext) {
      log("redisConnect failed: %s", m_pContext->errstr);
      redisFree(m_pContext);
      m_pContext = NULL;
    } else {
      log("redisConnect failed");
    }

    return 1;
  }

  redisReply* reply = (redisReply *)redisCommand(m_pContext, "SELECT %d", m_pCachePool->GetDBNum());
  if (reply && (reply->type == REDIS_REPLY_STATUS) && (strncmp(reply->str, "OK", 2) == 0)) {
    freeReplyObject(reply);
    return 0;
  } else {
    log("select cache db failed");
    return 2;
  }
}


const char* CacheConn::GetPoolName()
{
  return m_pCachePool->GetPoolName();
}

/* get 命令, 成功返回"OK" */
string CacheConn::get(string key)
{
  string value;

  if (Init()) {
    return value;
  }

  redisReply* reply = (redisReply *)redisCommand(m_pContext, "GET %s", key.c_str());
  if (!reply) {
    log("redisCommand failed:%s", m_pContext->errstr);
    redisFree(m_pContext);
    m_pContext = NULL;
    return value;
  }

  if (reply->type == REDIS_REPLY_STRING) {
    value.append(reply->str, reply->len);
  }

  freeReplyObject(reply);
  return value;
}

/* SETEX 命令 - 设置生存时间,成功返回"OK" */
string CacheConn::setex(string key, int timeout, string value)
{
  string ret_value;

  if (Init()) {
    return ret_value;
  }

  redisReply* reply = (redisReply *)redisCommand(m_pContext, "SETEX %s %d %s", key.c_str(), timeout, value.c_str());
  if (!reply) {
    log("redisCommand failed:%s", m_pContext->errstr);
    redisFree(m_pContext);
    m_pContext = NULL;
    return ret_value;
  }

  ret_value.append(reply->str, reply->len);
  freeReplyObject(reply);
  return ret_value;
}

/* set 命令, 成功返回"OK". */
string CacheConn::set(string key, string &value)
{
  string ret_value;

  if (Init()) {
    return ret_value;
  }

  redisReply* reply = (redisReply *)redisCommand(m_pContext, "SET %s %s", key.c_str(), value.c_str());
  if (!reply) {
    log("redisCommand failed:%s", m_pContext->errstr);
    redisFree(m_pContext);
    m_pContext = NULL;
    return ret_value;
  }

  ret_value.append(reply->str, reply->len);
  freeReplyObject(reply);
  return ret_value;
}

/* 批量get字符串数组keys的每个字符串的value值, 一一对应保存在ret_value中. */
bool CacheConn::mget(const vector<string>& keys, map<string, string>& ret_value)
{
  if(Init())
  {
    return false;
  }
  if(keys.empty())
  {
    return false;
  }

  string strKey;
  bool bFirst = true;
  for (vector<string>::const_iterator it=keys.begin(); it!=keys.end(); ++it) {
    if(bFirst)
    {
      bFirst = false;
      strKey = *it;
    }
    else
    {
      strKey += " " + *it;
    }
  }

  if(strKey.empty())
  {
    return false;
  }
  strKey = "MGET " + strKey;
  redisReply* reply = (redisReply*) redisCommand(m_pContext, strKey.c_str());
  if (!reply) {
    log("redisCommand failed:%s", m_pContext->errstr);
    redisFree(m_pContext);
    m_pContext = NULL;
    return false;
  }
  if(reply->type == REDIS_REPLY_ARRAY)
  {
    for(size_t i=0; i<reply->elements; ++i)
    {
      redisReply* child_reply = reply->element[i];
      if (child_reply->type == REDIS_REPLY_STRING) {
        ret_value[keys[i]] = child_reply->str;
      }
    }
  }
  freeReplyObject(reply);
  return true;
}

/* key是否已存在. */
bool CacheConn::isExists(string &key)
{
  if (Init()) {
    return false;
  }

  redisReply* reply = (redisReply*) redisCommand(m_pContext, "EXISTS %s", key.c_str());
  if(!reply)
  {
    log("redisCommand failed:%s", m_pContext->errstr);
    redisFree(m_pContext);
    return false;
  }
  long ret_value = reply->integer;
  freeReplyObject(reply);
  if(0 == ret_value)
  {
    return false;
  }
  else
  {
    return true;
  }
}

/* 删除哈希表 key 中的一个或多个指定域,不存在的域将被忽略.返回成功移除的数量 */
long CacheConn::hdel(string key, string field)
{
  if (Init()) {
    return 0;
  }

  redisReply* reply = (redisReply *)redisCommand(m_pContext, "HDEL %s %s", key.c_str(), field.c_str());
  if (!reply) {
    log("redisCommand failed:%s", m_pContext->errstr);
    redisFree(m_pContext);
    m_pContext = NULL;
    return 0;
  }

  long ret_value = reply->integer;
  freeReplyObject(reply);
  return ret_value;
}

/* 返回哈希表中给定域的值,成功返回"OK" */
string CacheConn::hget(string key, string field)
{
  string ret_value;
  if (Init()) {
    return ret_value;
  }

  redisReply* reply = (redisReply *)redisCommand(m_pContext, "HGET %s %s", key.c_str(), field.c_str());
  if (!reply) {
    log("redisCommand failed:%s", m_pContext->errstr);
    redisFree(m_pContext);
    m_pContext = NULL;
    return ret_value;
  }

  if (reply->type == REDIS_REPLY_STRING) {
    ret_value.append(reply->str, reply->len);
  }

  freeReplyObject(reply);
  return ret_value;
}

/* 返回哈希表 key 中,所有的域和值. */
bool CacheConn::hgetAll(string key, map<string, string>& ret_value)
{
  if (Init()) {
    return false;
  }

  redisReply* reply = (redisReply *)redisCommand(m_pContext, "HGETALL %s", key.c_str());
  if (!reply) {
    log("redisCommand failed:%s", m_pContext->errstr);
    redisFree(m_pContext);
    m_pContext = NULL;
    return false;
  }

  if ( (reply->type == REDIS_REPLY_ARRAY) && (reply->elements % 2 == 0) ) {
    for (size_t i = 0; i < reply->elements; i += 2) {
      redisReply* field_reply = reply->element[i];
      redisReply* value_reply = reply->element[i + 1];

      string field(field_reply->str, field_reply->len);
      string value(value_reply->str, value_reply->len);
      ret_value.insert(make_pair(field, value));
    }
  }

  freeReplyObject(reply);
  return true;
}

/* 将哈希表 hash 中 key 在域 field 的值设置为 value */
long CacheConn::hset(string key, string field, string value)
{
  if (Init()) {
    return -1;
  }

  redisReply* reply = (redisReply *)redisCommand(m_pContext, "HSET %s %s %s", key.c_str(), field.c_str(), value.c_str());
  if (!reply) {
    log("redisCommand failed:%s", m_pContext->errstr);
    redisFree(m_pContext);
    m_pContext = NULL;
    return -1;
  }

  long ret_value = reply->integer;
  freeReplyObject(reply);
  return ret_value;
}

/* 为哈希表 key 中的域 field 的值加上增量 value */
long CacheConn::hincrBy(string key, string field, long value)
{
  if (Init()) {
    return -1;
  }

  redisReply* reply = (redisReply *)redisCommand(m_pContext, "HINCRBY %s %s %ld", key.c_str(), field.c_str(), value);
  if (!reply) {
    log("redisCommand failed:%s", m_pContext->errstr);
    redisFree(m_pContext);
    m_pContext = NULL;
    return -1;
  }

  long ret_value = reply->integer;
  freeReplyObject(reply);
  return ret_value;
}

long CacheConn::incrBy(string key, long value)
{
  if(Init())
  {
    return -1;
  }

  redisReply* reply = (redisReply*)redisCommand(m_pContext, "INCRBY %s %ld", key.c_str(), value);
  if(!reply)
  {
    log("redis Command failed:%s", m_pContext->errstr);
    redisFree(m_pContext);
    m_pContext = NULL;
    return -1;
  }
  long ret_value = reply->integer;
  freeReplyObject(reply);
  return ret_value;
}

/* 同时将多个 field-value (域-值)对设置到哈希表 key 中. */
string CacheConn::hmset(string key, map<string, string>& hash)
{
  string ret_value;

  if (Init()) {
    return ret_value;
  }

  int argc = hash.size() * 2 + 2;
  const char** argv = new const char* [argc];
  if (!argv) {
    return ret_value;
  }

  argv[0] = "HMSET";
  argv[1] = key.c_str();
  int i = 2;
  for (map<string, string>::iterator it = hash.begin(); it != hash.end(); it++) {
    argv[i++] = it->first.c_str();
    argv[i++] = it->second.c_str();
  }

  redisReply* reply = (redisReply *)redisCommandArgv(m_pContext, argc, argv, NULL);
  if (!reply) {
    log("redisCommand failed:%s", m_pContext->errstr);
    delete [] argv;

    redisFree(m_pContext);
    m_pContext = NULL;
    return ret_value;
  }

  ret_value.append(reply->str, reply->len);

  delete [] argv;
  freeReplyObject(reply);
  return ret_value;
}

bool CacheConn::hmget(string key, list<string>& fields, list<string>& ret_value)
{
  if (Init()) {
    return false;
  }

  int argc = fields.size() + 2;
  const char** argv = new const char* [argc];
  if (!argv) {
    return false;
  }

  argv[0] = "HMGET";
  argv[1] = key.c_str();
  int i = 2;
  for (list<string>::iterator it = fields.begin(); it != fields.end(); it++) {
    argv[i++] = it->c_str();
  }

  redisReply* reply = (redisReply *)redisCommandArgv(m_pContext, argc, (const char**)argv, NULL);
  if (!reply) {
    log("redisCommand failed:%s", m_pContext->errstr);
    delete [] argv;

    redisFree(m_pContext);
    m_pContext = NULL;

    return false;
  }

  if (reply->type == REDIS_REPLY_ARRAY) {
    for (size_t i = 0; i < reply->elements; i++) {
      redisReply* value_reply = reply->element[i];
      string value(value_reply->str, value_reply->len);
      ret_value.push_back(value);
    }
  }

  delete [] argv;
  freeReplyObject(reply);
  return true;
}

long CacheConn::incr(string key)
{
  if(Init())
  {
    return -1;
  }

  redisReply* reply = (redisReply*)redisCommand(m_pContext, "INCR %s", key.c_str());
  if(!reply)
  {
    log("redis Command failed:%s", m_pContext->errstr);
    redisFree(m_pContext);
    m_pContext = NULL;
    return -1;
  }
  long ret_value = reply->integer;
  freeReplyObject(reply);
  return ret_value;
}

long CacheConn::decr(string key)
{
  if(Init())
  {
    return -1;
  }

  redisReply* reply = (redisReply*)redisCommand(m_pContext, "DECR %s", key.c_str());
  if(!reply)
  {
    log("redis Command failed:%s", m_pContext->errstr);
    redisFree(m_pContext);
    m_pContext = NULL;
    return -1;
  }
  long ret_value = reply->integer;
  freeReplyObject(reply);
  return ret_value;
}

/* 将一个或多个值 value 插入到列表 key 的表头 */
long CacheConn::lpush(string key, string value)
{
  if (Init()) {
    return -1;
  }

  redisReply* reply = (redisReply *)redisCommand(m_pContext, "LPUSH %s %s", key.c_str(), value.c_str());
  if (!reply) {
    log("redisCommand failed:%s", m_pContext->errstr);
    redisFree(m_pContext);
    m_pContext = NULL;
    return -1;
  }

  long ret_value = reply->integer;
  freeReplyObject(reply);
  return ret_value;
}

/* 将一个或多个值 value 插入到列表 key 的表尾(最右边). */
long CacheConn::rpush(string key, string value)
{
  if (Init()) {
    return -1;
  }

  redisReply* reply = (redisReply *)redisCommand(m_pContext, "RPUSH %s %s", key.c_str(), value.c_str());
  if (!reply) {
    log("redisCommand failed:%s", m_pContext->errstr);
    redisFree(m_pContext);
    m_pContext = NULL;
    return -1;
  }

  long ret_value = reply->integer;
  freeReplyObject(reply);
  return ret_value;
}

/* 返回列表 key 的长度 */
long CacheConn::llen(string key)
{
  if (Init()) {
    return -1;
  }

  redisReply* reply = (redisReply *)redisCommand(m_pContext, "LLEN %s", key.c_str());
  if (!reply) {
    log("redisCommand failed:%s", m_pContext->errstr);
    redisFree(m_pContext);
    m_pContext = NULL;
    return -1;
  }

  long ret_value = reply->integer;
  freeReplyObject(reply);
  return ret_value;
}

/* 返回列表 key 中指定区间内的元素,区间以偏移量 start 和 stop 指定. */
bool CacheConn::lrange(string key, long start, long end, list<string>& ret_value)
{
  if (Init()) {
    return false;
  }

  redisReply* reply = (redisReply *)redisCommand(m_pContext, "LRANGE %s %d %d", key.c_str(), start, end);
  if (!reply) {
    log("redisCommand failed:%s", m_pContext->errstr);
    redisFree(m_pContext);
    m_pContext = NULL;
    return false;
  }

  if (reply->type == REDIS_REPLY_ARRAY) {
    for (size_t i = 0; i < reply->elements; i++) {
      redisReply* value_reply = reply->element[i];
      string value(value_reply->str, value_reply->len);
      ret_value.push_back(value);
    }
  }

  freeReplyObject(reply);
  return true;
}

///////////////
CachePool::CachePool(const char* pool_name, const char* server_ip, int server_port, int db_num, int max_conn_cnt)
{
  m_pool_name = pool_name;
  m_server_ip = server_ip;
  m_server_port = server_port;
  m_db_num = db_num;
  m_max_conn_cnt = max_conn_cnt;
  m_cur_conn_cnt = MIN_CACHE_CONN_CNT; //当前连接数设置为最小连接.
}

/* 释放m_free_list连接队列, m_free_list是空闲Redis连接资源(未被取用) */
CachePool::~CachePool()
{
  m_free_notify.Lock();
  for (list<CacheConn*>::iterator it = m_free_list.begin(); it != m_free_list.end(); it++) {
    CacheConn* pConn = *it;
    delete pConn;
  }

  m_free_list.clear();
  m_cur_conn_cnt = 0;
  m_free_notify.Unlock();
}

/* 初始化缓存池, 只分配最少连接数到m_free_list连接队列. */
int CachePool::Init()
{
  for (int i = 0; i < m_cur_conn_cnt; i++) {
    CacheConn* pConn = new CacheConn(this);
    if (pConn->Init()) {
      delete pConn;
      return 1;
    }

    m_free_list.push_back(pConn);
  }

  log("cache pool: %s, list size: %lu", m_pool_name.c_str(), m_free_list.size());
  return 0;
}

/* 从 m_free_list资源队列获取Redis连接资源.
 * 如果队列为空, new 一个新的连接资源.
 * 如果当前连接数大于等于最大连接数,使用调节变量等待RelCacheConn()进行资源回收.
 */
CacheConn* CachePool::GetCacheConn()
{
  m_free_notify.Lock();

  while (m_free_list.empty()) {
    if (m_cur_conn_cnt >= m_max_conn_cnt) {
      m_free_notify.Wait();
    } else {
      CacheConn* pCacheConn = new CacheConn(this);
      int ret = pCacheConn->Init();
      if (ret) {
        log("Init CacheConn failed");
        delete pCacheConn;
        m_free_notify.Unlock();
        return NULL;
      } else {
        m_free_list.push_back(pCacheConn);
        m_cur_conn_cnt++;
        log("new cache connection: %s, conn_cnt: %d", m_pool_name.c_str(), m_cur_conn_cnt);
      }
    }
  }

  CacheConn* pConn = m_free_list.front();
  m_free_list.pop_front();

  m_free_notify.Unlock();

  return pConn;
}

/* 回收 Redis缓存连接 保存到 m_free_list 资源队列.
 * 同时释放条件变量信号, 解除 GetCacheConn() 中的等待信号.
 */
void CachePool::RelCacheConn(CacheConn* pCacheConn)
{
  m_free_notify.Lock();

  list<CacheConn*>::iterator it = m_free_list.begin();
  for (; it != m_free_list.end(); it++) {
    if (*it == pCacheConn) {
      break;
    }
  }

  if (it == m_free_list.end()) {
    m_free_list.push_back(pCacheConn);
  }

  m_free_notify.Signal();
  m_free_notify.Unlock();
}

///////////
CacheManager::CacheManager()
{

}

CacheManager::~CacheManager()
{

}

/* 获取单例, 自动初始化Redis连接池. */
CacheManager* CacheManager::getInstance()
{
  if (!s_cache_manager) {
    s_cache_manager = new CacheManager();
    if (s_cache_manager->Init()) {
      delete s_cache_manager;
      s_cache_manager = NULL;
    }
  }

  return s_cache_manager;
}

/* 取配置文件,初始化unread,group_set,token,sync,group_member 5个缓存池
 * 保存在 m_cache_pool_map缓存池map中.
 */
int CacheManager::Init()
{
  CConfigFileReader config_file("dbproxyserver.conf");

  char* cache_instances = config_file.GetConfigName("CacheInstances");
  if (!cache_instances) {
    log("not configure CacheIntance");
    return 1;
  }

  char host[64];
  char port[64];
  char db[64];
  char maxconncnt[64];
  CStrExplode instances_name(cache_instances, ',');
  for (uint32_t i = 0; i < instances_name.GetItemCnt(); i++) {
    char* pool_name = instances_name.GetItem(i);
    //printf("%s", pool_name);
    snprintf(host, 64, "%s_host", pool_name);
    snprintf(port, 64, "%s_port", pool_name);
    snprintf(db, 64, "%s_db", pool_name);
    snprintf(maxconncnt, 64, "%s_maxconncnt", pool_name);

    char* cache_host = config_file.GetConfigName(host);
    char* str_cache_port = config_file.GetConfigName(port);
    char* str_cache_db = config_file.GetConfigName(db);
    char* str_max_conn_cnt = config_file.GetConfigName(maxconncnt);
    if (!cache_host || !str_cache_port || !str_cache_db || !str_max_conn_cnt) {
      log("not configure cache instance: %s", pool_name);
      return 2;
    }

    CachePool* pCachePool = new CachePool(pool_name, cache_host, atoi(str_cache_port),
        atoi(str_cache_db), atoi(str_max_conn_cnt));
    if (pCachePool->Init()) {
      log("Init cache pool failed");
      return 3;
    }

    m_cache_pool_map.insert(make_pair(pool_name, pCachePool));
  }

  return 0;
}

/* 获取缓存池 pool_name 中一条Redis连接. */
CacheConn* CacheManager::GetCacheConn(const char* pool_name)
{
  map<string, CachePool*>::iterator it = m_cache_pool_map.find(pool_name);
  if (it != m_cache_pool_map.end()) {
    return it->second->GetCacheConn();
  } else {
    return NULL;
  }
}

/* 返回Redis连接资源. */
void CacheManager::RelCacheConn(CacheConn* pCacheConn)
{
  if (!pCacheConn) {
    return;
  }

  map<string, CachePool*>::iterator it = m_cache_pool_map.find(pCacheConn->GetPoolName());
  if (it != m_cache_pool_map.end()) {
    return it->second->RelCacheConn(pCacheConn);
  }
}

/* db_proxy_server - AutoPool.h */
#ifndef __AUTOPOOl_H__
#define __AUTOPOOl_H__

class CDBConn;
class CacheConn;

/* RAII手法
 * 构造函数自动取一条 MySQL 连接(MySQL的连接资源),使用完之后自动释放.
 * 构造函数自动取一条 Redis 连接(Redis的缓存资源),使用完之后自动释放.
 */
class CAutoDB
{
public:
    CAutoDB(const char* pDBName, CDBConn** pDBConn);
    ~CAutoDB();
private:
    CDBConn* m_pDBConn;
};

class CAutoCache
{
    CAutoCache(const char* pCacheName, CacheConn** pCacheConn);
    ~CAutoCache();
private:
    CacheConn* m_pCacheConn;
};
#endif /*defined(__AUTOPOOl_H__) */

/* db_proxy_server - AutoPool.cpp */
#include "AutoPool.h"
#include "DBPool.h"
#include "CachePool.h"

CAutoDB::CAutoDB(const char* pDBName, CDBConn** pDBConn)
{
    m_pDBConn = CDBManager::getInstance()->GetDBConn(pDBName);
    *pDBConn = m_pDBConn;
}

CAutoDB::~CAutoDB()
{
    if (m_pDBConn != NULL) {
        CDBManager::getInstance()->RelDBConn(m_pDBConn);
        m_pDBConn = NULL;
    }
}

CAutoCache::CAutoCache(const char* pCacheName, CacheConn** pCacheConn)
{
    m_pCacheConn = CacheManager::getInstance()->GetCacheConn(pCacheName);
    *pCacheConn = m_pCacheConn;
}

CAutoCache::~CAutoCache()
{
    if (m_pCacheConn != NULL) {
        CacheManager::getInstance()->RelCacheConn(m_pCacheConn);
        m_pCacheConn = NULL;
    }
}

/* db_proxy_server - HandlerMap.h */
#ifndef HANDLERMAP_H_
#define HANDLERMAP_H_

#include "../base/util.h"
#include "ProxyTask.h"

typedef map<uint32_t, pdu_handler_t> HandlerMap_t;

/* 加载 commandId 对应的处理函数 */
class CHandlerMap {
public:
  virtual ~CHandlerMap();

  static CHandlerMap* getInstance();
  void Init();

  pdu_handler_t GetHandler(uint32_t pdu_type);

private:
  CHandlerMap();

private:
  static CHandlerMap* s_handler_instance;
  HandlerMap_t m_handler_map;
};

#endif /* HANDLERMAP_H_ */

/* db_proxy_server - HandlerMap.cpp */
#include "HandlerMap.h"
#include "business/Login.h"
#include "business/MessageContent.h"
#include "business/RecentSession.h"
#include "business/UserAction.h"
#include "business/MessageCounter.h"
#include "business/GroupAction.h"
#include "business/DepartAction.h"
#include "business/FileAction.h"
#include "IM.BaseDefine.pb.h"

using namespace IM::BaseDefine;

CHandlerMap* CHandlerMap::s_handler_instance = NULL;

/* 构造函数 */
CHandlerMap::CHandlerMap()
{

}

/* 析构函数 */
CHandlerMap::~CHandlerMap()
{

}

/* 返回指向CHandlerMap的单例指针 */
CHandlerMap* CHandlerMap::getInstance()
{
  if (!s_handler_instance) {
    s_handler_instance = new CHandlerMap();
    s_handler_instance->Init();
  }

  return s_handler_instance;
}

/* 初始化函数,加载了各种commandId 对应的处理函数 */
void CHandlerMap::Init()
{
  // Login validate
  m_handler_map.insert(make_pair(uint32_t(CID_OTHER_VALIDATE_REQ), DB_PROXY::doLogin));
  m_handler_map.insert(make_pair(uint32_t(CID_LOGIN_REQ_PUSH_SHIELD), DB_PROXY::doPushShield));
  m_handler_map.insert(make_pair(uint32_t(CID_LOGIN_REQ_QUERY_PUSH_SHIELD), DB_PROXY::doQueryPushShield));

  // recent session
  m_handler_map.insert(make_pair(uint32_t(CID_BUDDY_LIST_RECENT_CONTACT_SESSION_REQUEST), DB_PROXY::getRecentSession));
  m_handler_map.insert(make_pair(uint32_t(CID_BUDDY_LIST_REMOVE_SESSION_REQ), DB_PROXY::deleteRecentSession));

  // users
  m_handler_map.insert(make_pair(uint32_t(CID_BUDDY_LIST_USER_INFO_REQUEST), DB_PROXY::getUserInfo));
  m_handler_map.insert(make_pair(uint32_t(CID_BUDDY_LIST_ALL_USER_REQUEST), DB_PROXY::getChangedUser));
  m_handler_map.insert(make_pair(uint32_t(CID_BUDDY_LIST_DEPARTMENT_REQUEST), DB_PROXY::getChgedDepart));
  m_handler_map.insert(make_pair(uint32_t(CID_BUDDY_LIST_CHANGE_SIGN_INFO_REQUEST), DB_PROXY::changeUserSignInfo));

  // message content
  m_handler_map.insert(make_pair(uint32_t(CID_MSG_DATA), DB_PROXY::sendMessage));
  m_handler_map.insert(make_pair(uint32_t(CID_MSG_LIST_REQUEST), DB_PROXY::getMessage));
  m_handler_map.insert(make_pair(uint32_t(CID_MSG_UNREAD_CNT_REQUEST), DB_PROXY::getUnreadMsgCounter));
  m_handler_map.insert(make_pair(uint32_t(CID_MSG_READ_ACK), DB_PROXY::clearUnreadMsgCounter));
  m_handler_map.insert(make_pair(uint32_t(CID_MSG_GET_BY_MSG_ID_REQ), DB_PROXY::getMessageById));
  m_handler_map.insert(make_pair(uint32_t(CID_MSG_GET_LATEST_MSG_ID_REQ), DB_PROXY::getLatestMsgId));

  // device token
  m_handler_map.insert(make_pair(uint32_t(CID_LOGIN_REQ_DEVICETOKEN), DB_PROXY::setDevicesToken));
  m_handler_map.insert(make_pair(uint32_t(CID_OTHER_GET_DEVICE_TOKEN_REQ), DB_PROXY::getDevicesToken));

  //push 推送设置
  m_handler_map.insert(make_pair(uint32_t(CID_GROUP_SHIELD_GROUP_REQUEST), DB_PROXY::setGroupPush));
  m_handler_map.insert(make_pair(uint32_t(CID_OTHER_GET_SHIELD_REQ), DB_PROXY::getGroupPush));

  // group
  m_handler_map.insert(make_pair(uint32_t(CID_GROUP_NORMAL_LIST_REQUEST), DB_PROXY::getNormalGroupList));
  m_handler_map.insert(make_pair(uint32_t(CID_GROUP_INFO_REQUEST), DB_PROXY::getGroupInfo));
  m_handler_map.insert(make_pair(uint32_t(CID_GROUP_CREATE_REQUEST), DB_PROXY::createGroup));
  m_handler_map.insert(make_pair(uint32_t(CID_GROUP_CHANGE_MEMBER_REQUEST), DB_PROXY::modifyMember));

  // file
  m_handler_map.insert(make_pair(uint32_t(CID_FILE_HAS_OFFLINE_REQ), DB_PROXY::hasOfflineFile));
  m_handler_map.insert(make_pair(uint32_t(CID_FILE_ADD_OFFLINE_REQ), DB_PROXY::addOfflineFile));
  m_handler_map.insert(make_pair(uint32_t(CID_FILE_DEL_OFFLINE_REQ), DB_PROXY::delOfflineFile));
}

/* 通过commandId获取处理函数
 * @param pdu_type commandId
 * @return 处理函数的函数指针
 */
pdu_handler_t CHandlerMap::GetHandler(uint32_t pdu_type)
{
  HandlerMap_t::iterator it = m_handler_map.find(pdu_type);
  if (it != m_handler_map.end()) {
    return it->second;
  } else {
    return NULL;
  }
}

/* db_proxy_server - ProxyTask.h */
#ifndef __PROXY_TASK_H__
#define __PROXY_TASK_H__
#include "Task.h"
#include "util.h"
#include "ImPduBase.h"

/* CImPdu是一个封装 PduHeader_t 和 m_buf 的PDU报文协议对象.
 *
 * CImPdu:
 * Im  - Instant Message 即时通讯软件,
 * Pdu - Protocol Data Unit 协议数据单元,通俗的说就是一个包单位.
 * 该数据结构分为包头和包体两部分.对象CImPdu的两个成员变量.
 *
 * 包头:
 * typedef struct {
 *     uint32_t length;    // the whole pdu length
 *     uint16_t version;   // pdu version number
 *     uint16_t	flag;      // not used
 *     uint16_t	service_id;//
 *     uint16_t	command_id;// 通过包头的command_id知道该包是什么数据.
 *     uint16_t	seq_num;   // 包序号
 *     uint16_t reversed;  // 保留
 * } PduHeader_t;
 *
 * 包体:
 * CSimpleBuffer  m_buf;
 */

typedef void (*pdu_handler_t)(CImPdu* pPdu, uint32_t conn_uuid);

/* CProxyTask 是一个任务对象,是所有业务逻辑的执行入口 */
class CProxyTask:public CTask
{
public:
  CProxyTask(uint32_t conn_uuid, pdu_handler_t pdu_handler, CImPdu* pPdu);
  virtual ~CProxyTask();

  virtual void run();
private:
  uint32_t      m_conn_uuid;   // 通过uuid获得对应数据包的连接对象.
  pdu_handler_t m_pdu_handler; // pdu_handler_t 是函数指针.
  CImPdu*       m_pPdu;        // m_pPdu 是一个数据包(包括 包头 和 包体).
};

#endif

/* db_proxy_server - ProxyTask.cpp */
#include "ProxyTask.h"
#include "ProxyConn.h"

CProxyTask::CProxyTask(uint32_t conn_uuid, pdu_handler_t pdu_handler, CImPdu* pPdu)
{
  m_conn_uuid = conn_uuid;
  m_pdu_handler = pdu_handler;
  m_pPdu = pPdu;
}

CProxyTask::~CProxyTask()
{
  if (m_pPdu) {
    delete m_pPdu;
  }
}

/* uuid获得对应数据包的连接对象,
 * m_pdu_handler对应业务逻辑的处理函数,
 * run 执行任务,所有的业务逻辑都是由 m_pdu_handler 开始执行 */
void CProxyTask::run()
{
  if (!m_pPdu) {
    // tell CProxyConn to close connection with m_conn_uuid
    CProxyConn::AddResponsePdu(m_conn_uuid, NULL);
  } else {
    if (m_pdu_handler) {
      m_pdu_handler(m_pPdu, m_conn_uuid);
    }
  }
}

/* db_proxy_server - ProxyConn.h */
#ifndef PROXYCONN_H_
#define PROXYCONN_H_

#include <curl/curl.h>
#include "../base/util.h"
#include "imconn.h"

/* uuid获得对应数据包的连接对象. ResponsePdu_t 是应答包 */
typedef struct {
  uint32_t conn_uuid;
  CImPdu*  pPdu;
} ResponsePdu_t;

/* CProxyConn 是代理连接对象. 使用PDU协议处理请求和发送应答消息. */
class CProxyConn : public CImConn {
public:
  CProxyConn();
  virtual ~CProxyConn();

  virtual void Close();

  virtual void OnConnect(net_handle_t handle);
  virtual void OnRead();
  virtual void OnClose();
  virtual void OnTimer(uint64_t curr_tick);

  void HandlePduBuf(uchar_t* pdu_buf, uint32_t pdu_len);

  static void AddResponsePdu(uint32_t conn_uuid, CImPdu* pPdu);	// 工作线程调用
  static void SendResponsePduList(); // 主线程调用
private:
  //由于处理请求和发送回复在两个线程,socket的handle可能重用,
  //所以需要用一个一直增加的uuid来表示一个连接.
  static uint32_t	s_uuid_alloctor;
  uint32_t        m_uuid;

  static CLock s_list_lock;
  static list<ResponsePdu_t*>	s_response_pdu_list; // 主线程发送回复消息
};

int init_proxy_conn(uint32_t thread_num);
CProxyConn* get_proxy_conn_by_uuid(uint32_t uuid);

#endif /* PROXYCONN_H_ */

/* db_proxy_server - ProxyConn.cpp */
#include "ProxyConn.h"
#include "ProxyTask.h"
#include "HandlerMap.h"
#include "atomic.h"
#include "IM.Other.pb.h"
#include "IM.BaseDefine.pb.h"
#include "IM.Server.pb.h"
#include "ThreadPool.h"
#include "SyncCenter.h"

/* typedef hash_map<net_handle_t, CImConn*> ConnMap_t;
 * typedef hash_map<uint32_t, CImConn*> UserMap_t;
 * CHandlerMap 是封装了typedef map<uint32_t, pdu_handler_t> HandlerMap_t;成员变量的类对象.
 * pdu_handler_t 是函数指针 - typedef void (*pdu_handler_t)(CImPdu* pPdu, uint32_t conn_uuid);
 */
static ConnMap_t g_proxy_conn_map; // 其他服务器与db_proxy_server服务器的连接map.
static UserMap_t g_uuid_conn_map;  // 工作线程连接标识uuid与连接CImConn的map.
static CHandlerMap* s_handler_map; // commandId指令标识与pPdu函数指针map.

uint32_t CProxyConn::s_uuid_alloctor = 0;
CLock CProxyConn::s_list_lock;
list<ResponsePdu_t*> CProxyConn::s_response_pdu_list; // 代理服务器回复的应答消息队列.
static CThreadPool g_thread_pool;

/* OnTimer() 是向连接db_proxy_server代理服务器的其他服务器发送心跳.
 * proxy_timer_callback() 作用是向所有连接db_proxy_server的其他服务器发送心跳.
 */
void proxy_timer_callback(void* callback_data, uint8_t msg, uint32_t handle, void* pParam)
{
  uint64_t cur_time = get_tick_count();
  for (ConnMap_t::iterator it = g_proxy_conn_map.begin(); it != g_proxy_conn_map.end();)
  {
    ConnMap_t::iterator it_old = it;
    it++;

    CProxyConn* pConn = (CProxyConn*)it_old->second;
    pConn->OnTimer(cur_time);
  }
}

/* SendResponsePduList() 是根据应答消息队列连接的不同标识,分别发送消息应答.
 * proxy_loop_callback() 将会被加入到EventLoop中被当做其他任务队列被检测执行.
 */
void proxy_loop_callback(void* callback_data, uint8_t msg, uint32_t handle, void* pParam)
{
  CProxyConn::SendResponsePduList();
}

/*
 * 用于优雅的关闭连接：
 * 服务器收到SIGTERM信号后,发送CImPduStopReceivePacket数据包给每个连接,
 * 通知消息服务器不要往自己发送数据包请求,
 * 然后注册4s后调用的回调函数,回调时再退出进程
 */
void exit_callback(void* callback_data, uint8_t msg, uint32_t handle, void* pParam)
{
  log("exit_callback...");
  exit(0);
}

/* sig_handler() 组织cPdu报文发给每个连接,
 * netlib_register_timer() 注册定时器任务, 在eventloop循环中会被检测执行.
 */
static void sig_handler(int sig_no)
{
  if (sig_no == SIGTERM) {
    log("receive SIGTERM, prepare for exit");
    CImPdu cPdu;
    IM::Server::IMStopReceivePacket msg;
    msg.set_result(0);
    cPdu.SetPBMsg(&msg);
    cPdu.SetServiceId(IM::BaseDefine::SID_OTHER);
    cPdu.SetCommandId(IM::BaseDefine::CID_OTHER_STOP_RECV_PACKET);
    for (ConnMap_t::iterator it = g_proxy_conn_map.begin(); it != g_proxy_conn_map.end(); it++) {
      CProxyConn* pConn = (CProxyConn*)it->second;
      pConn->SendPdu(&cPdu);
    }
    // Add By ZhangYuanhao
    // Before stop we need to stop the sync thread,otherwise maybe will not sync the internal data any more
    CSyncCenter::getInstance()->stopSync();

    // callback after 4 second to exit process;
    netlib_register_timer(exit_callback, NULL, 4000);
  }
}

/* CHandlerMap::getInstance() 初始化所有命令标识与cPdu处理函数.
 * g_thread_pool.Init(thread_num); 初始化线程池.
 * proxy_loop_callback 回调函数,是根据应答消息队列连接的不同标识,分别发送消息应答.
 * signal(SIGTERM, sig_handler); 处理终止信号.
 * proxy_timer_callback 回调函数,发送心跳包到连接db_proxy_server的其他服务器
 */
int init_proxy_conn(uint32_t thread_num)
{
  s_handler_map = CHandlerMap::getInstance();
  g_thread_pool.Init(thread_num);

  netlib_add_loop(proxy_loop_callback, NULL);

  signal(SIGTERM, sig_handler);

  return netlib_register_timer(proxy_timer_callback, NULL, 1000);
}

CProxyConn* get_proxy_conn_by_uuid(uint32_t uuid)
{
  CProxyConn* pConn = NULL;
  UserMap_t::iterator it = g_uuid_conn_map.find(uuid);
  if (it != g_uuid_conn_map.end()) {
    pConn = (CProxyConn *)it->second;
  }

  return pConn;
}

//////////////////////////
/* m_uuid 是为了区分不同的工作线程 */
CProxyConn::CProxyConn()
{
  m_uuid = ++CProxyConn::s_uuid_alloctor;
  if (m_uuid == 0) {
    m_uuid = ++CProxyConn::s_uuid_alloctor;
  }

  g_uuid_conn_map.insert(make_pair(m_uuid, this));
}

CProxyConn::~CProxyConn()
{

}

void CProxyConn::Close()
{
  if (m_handle != NETLIB_INVALID_HANDLE) {
    netlib_close(m_handle);
    g_proxy_conn_map.erase(m_handle);

    g_uuid_conn_map.erase(m_uuid);
  }

  ReleaseRef();
}

/* 将其他服务器与db_proxy_server的连接保存在g_proxy_conn_map中,
 * netlib_option 设置连接套接字handle的属性. 
 */
void CProxyConn::OnConnect(net_handle_t handle)
{
  m_handle = handle;

  g_proxy_conn_map.insert(make_pair(handle, this));

  netlib_option(handle, NETLIB_OPT_SET_CALLBACK, (void*)imconn_callback);
  netlib_option(handle, NETLIB_OPT_SET_CALLBACK_DATA, (void*)&g_proxy_conn_map);
  netlib_option(handle, NETLIB_OPT_GET_REMOTE_IP, (void*)&m_peer_ip);
  netlib_option(handle, NETLIB_OPT_GET_REMOTE_PORT, (void*)&m_peer_port);

  log("connect from %s:%d, handle=%d", m_peer_ip.c_str(), m_peer_port, m_handle);
}

// 由于数据包是在另一个线程处理的,所以不能在主线程delete数据包,所以需要Override这个方法
/* 读取消息所有缓存中的数据,HandlePduBuf是处理所有的消息.
 * HandlePduBuf读取一条pdu报文, 根据pdu中的commandId命令标识, 取得对应的pdu报文中的处理函数,
 * 将处理函数组成task任务加入到线程池中待处理.
 */
void CProxyConn::OnRead()
{
  for (;;) {
    uint32_t free_buf_len = m_in_buf.GetAllocSize() - m_in_buf.GetWriteOffset();
    if (free_buf_len < READ_BUF_SIZE)
      m_in_buf.Extend(READ_BUF_SIZE);

    int ret = netlib_recv(m_handle, m_in_buf.GetBuffer() + m_in_buf.GetWriteOffset(), READ_BUF_SIZE);
    if (ret <= 0)
      break;

    m_recv_bytes += ret;
    m_in_buf.IncWriteOffset(ret);
    m_last_recv_tick = get_tick_count();
  }

  uint32_t pdu_len = 0;
  try {
    while ( CImPdu::IsPduAvailable(m_in_buf.GetBuffer(), m_in_buf.GetWriteOffset(), pdu_len) ) {
      HandlePduBuf(m_in_buf.GetBuffer(), pdu_len);
      m_in_buf.Read(NULL, pdu_len);
    }
  } catch (CPduException& ex) {
    log("!!!catch exception, err_code=%u, err_msg=%s, close the connection ",
        ex.GetErrorCode(), ex.GetErrorMsg());
    OnClose();
  }

}


void CProxyConn::OnClose()
{
  Close();
}

/* 发送心跳包cPdu */
void CProxyConn::OnTimer(uint64_t curr_tick)
{
  if (curr_tick > m_last_send_tick + SERVER_HEARTBEAT_INTERVAL) {

    CImPdu cPdu;
    IM::Other::IMHeartBeat msg;
    cPdu.SetPBMsg(&msg);
    cPdu.SetServiceId(IM::BaseDefine::SID_OTHER);
    cPdu.SetCommandId(IM::BaseDefine::CID_OTHER_HEARTBEAT);
    SendPdu(&cPdu);
  }

  if (curr_tick > m_last_recv_tick + SERVER_TIMEOUT) {
    log("proxy connection timeout %s:%d", m_peer_ip.c_str(), m_peer_port);
    Close();
  }
}

/* HandlePduBuf读取一条pdu报文, 根据pdu中的commandId命令标识, 取得对应的pdu报文中的处理函数,
 * 将处理函数组成task任务加入到线程池中待处理.
 */
void CProxyConn::HandlePduBuf(uchar_t* pdu_buf, uint32_t pdu_len)
{
  CImPdu* pPdu = NULL;
  pPdu = CImPdu::ReadPdu(pdu_buf, pdu_len);
  if (pPdu->GetCommandId() == IM::BaseDefine::CID_OTHER_HEARTBEAT) {
    return;
  }

  pdu_handler_t handler = s_handler_map->GetHandler(pPdu->GetCommandId());

  if (handler) {
    CTask* pTask = new CProxyTask(m_uuid, handler, pPdu);
    g_thread_pool.AddTask(pTask);
  } else {
    log("no handler for packet type: %d", pPdu->GetCommandId());
  }
}

/*
 * static method
 * add response pPdu to send list for another thread to send
 * if pPdu == NULL, it means you want to close connection with conn_uuid
 * e.g. parse packet failed
 */
/* 加入应答报文 */
void CProxyConn::AddResponsePdu(uint32_t conn_uuid, CImPdu* pPdu)
{
  ResponsePdu_t* pResp = new ResponsePdu_t;
  pResp->conn_uuid = conn_uuid;
  pResp->pPdu = pPdu;

  s_list_lock.lock();
  s_response_pdu_list.push_back(pResp);
  s_list_lock.unlock();
}

/* 将所有s_response_pdu_list队列中的报文数据一条一条的发出去(即发送应答报文)
 * 报文中的uuid字段可以确定发送的连接pConn, 用该pConn发送应答报文.
 */
void CProxyConn::SendResponsePduList()
{
  s_list_lock.lock();
  while (!s_response_pdu_list.empty()) {
    ResponsePdu_t* pResp = s_response_pdu_list.front();
    s_response_pdu_list.pop_front();
    s_list_lock.unlock();

    CProxyConn* pConn = get_proxy_conn_by_uuid(pResp->conn_uuid);
    if (pConn) {
      if (pResp->pPdu) {
        pConn->SendPdu(pResp->pPdu);
      } else {
        log("close connection uuid=%d by parse pdu error\b", pResp->conn_uuid);
        pConn->Close();
      }
    }

    if (pResp->pPdu)
      delete pResp->pPdu;
    delete pResp;

    s_list_lock.lock();
  }

  s_list_lock.unlock();
}

/* db_proxy_server - SyncCenter.h */
#ifndef __CACHEMANAGER_H__
#define __CACHEMANAGER_H__

#include <list>
#include <map>
#include "ostype.h"
#include "Lock.h"
#include "Condition.h"
#include "ImPduBase.h"
#include "public_define.h"
#include "IM.BaseDefine.pb.h"

class CSyncCenter
{
public:
  static CSyncCenter* getInstance();

  uint32_t getLastUpdate() {
    CAutoLock auto_lock(&last_update_lock_);
    return m_nLastUpdate;
  }
  uint32_t getLastUpdateGroup() {
    CAutoLock auto_lock(&last_update_lock_);
    return m_nLastUpdateGroup;
  }
  string getDeptName(uint32_t nDeptId);
  void startSync();
  void stopSync();
  void init();
  void updateTotalUpdate(uint32_t nUpdated);

private:
  void updateLastUpdateGroup(uint32_t nUpdated);

  CSyncCenter();
  ~CSyncCenter();
  static void* doSyncGroupChat(void* arg);

private:
  void getDept(uint32_t nDeptId, DBDeptInfo_t** pDept);
  DBDeptMap_t* m_pDeptInfo;

  static CSyncCenter* m_pInstance;
  uint32_t m_nLastUpdateGroup;
  uint32_t m_nLastUpdate;

  CCondition* m_pCondGroupChat;
  CLock*      m_pLockGroupChat;
  static bool m_bSyncGroupChatRuning;
  bool m_bSyncGroupChatWaitting;
#ifdef _WIN32
  DWORD m_nGroupChatThreadId;
#else
  pthread_t	m_nGroupChatThreadId;
#endif
  CLock last_update_lock_;
};

#endif /*defined(__CACHEMANAGER_H__) */

/* db_proxy_server - SyncCenter.cpp */
#include <stdlib.h>
#include <sys/signal.h>
#include "SyncCenter.h"
#include "Lock.h"
#include "HttpClient.h"
#include "json/json.h"
#include "DBPool.h"
#include "CachePool.h"
#include "business/Common.h"
#include "business/UserModel.h"
#include "business/GroupModel.h"
#include "business/SessionModel.h"

static CLock* g_pLock = new CLock();
static CRWLock *g_pRWDeptLock = new CRWLock();

CSyncCenter* CSyncCenter::m_pInstance = NULL;
bool CSyncCenter::m_bSyncGroupChatRuning = false;
/**
 *  单例
 *
 *  @return 返回CSyncCenter的单例指针
 */
CSyncCenter* CSyncCenter::getInstance()
{
  CAutoLock autoLock(g_pLock);
  if(m_pInstance == NULL)
  {
    m_pInstance = new CSyncCenter();
  }
  return m_pInstance;
}

/**
 *  构造函数
 */
CSyncCenter::CSyncCenter()
  :m_nGroupChatThreadId(0),
  m_nLastUpdateGroup(time(NULL)),
  m_bSyncGroupChatWaitting(true),
  m_pLockGroupChat(new CLock())
   //m_pLock(new CLock())
{
  m_pCondGroupChat = new CCondition(m_pLockGroupChat);
}

/**
 *  析构函数
 */
CSyncCenter::~CSyncCenter()
{
  if(m_pLockGroupChat != NULL)
  {
    delete m_pLockGroupChat;
  }
  if(m_pCondGroupChat != NULL)
  {
    delete m_pCondGroupChat;
  }
}

/* 获取部门信息 */
void CSyncCenter::getDept(uint32_t nDeptId, DBDeptInfo_t** pDept)
{
  auto it = m_pDeptInfo->find(nDeptId);
  if (it != m_pDeptInfo->end()) {
    *pDept = it->second;
  }
}

/* 获取部门名字 */
string CSyncCenter::getDeptName(uint32_t nDeptId)
{
  CAutoRWLock autoLock(g_pRWDeptLock);
  string strDeptName;
  DBDeptInfo_t* pDept = NULL;;
  getDept(nDeptId, &pDept);
  if (pDept != NULL) {
    strDeptName =  pDept->strName;
  }
  return strDeptName;
}
/**
 *  开启内网数据同步以及群组聊天记录同步
 */
void CSyncCenter::startSync()
{
#ifdef _WIN32
  (void)CreateThread(NULL, 0, doSyncGroupChat, NULL, 0, &m_nGroupChatThreadId);
#else
  (void)pthread_create(&m_nGroupChatThreadId, NULL, doSyncGroupChat, NULL);
#endif
}

/**
 *  停止同步，为了"优雅"的同步，使用了条件变量
 */
void CSyncCenter::stopSync()
{
  m_bSyncGroupChatWaitting = false;
  m_pCondGroupChat->notify();
  while (m_bSyncGroupChatRuning ) {
    usleep(500);
  }
}

/*
 * 初始化函数，从cache里面加载上次同步的时间信息等
 */
void CSyncCenter::init()
{
  // Load total update time
  CacheManager* pCacheManager = CacheManager::getInstance();
  // increase message count
  CacheConn* pCacheConn = pCacheManager->GetCacheConn("unread");
  if (pCacheConn)
  {
    string strTotalUpdate = pCacheConn->get("total_user_updated");

    string strLastUpdateGroup = pCacheConn->get("last_update_group");
    pCacheManager->RelCacheConn(pCacheConn);
    if(strTotalUpdate != "")
    {
      m_nLastUpdate = string2int(strTotalUpdate);
    }
    else
    {
      updateTotalUpdate(time(NULL));
    }
    if(strLastUpdateGroup.empty())
    {
      m_nLastUpdateGroup = string2int(strLastUpdateGroup);
    }
    else
    {
      updateLastUpdateGroup(time(NULL));
    }
  }
  else
  {
    log("no cache connection to get total_user_updated");
  }
}
/**
 *  更新上次同步内网信息时间
 *
 *  @param nUpdated 时间
 */

void CSyncCenter::updateTotalUpdate(uint32_t nUpdated)
{
  CacheManager* pCacheManager = CacheManager::getInstance();
  CacheConn* pCacheConn = pCacheManager->GetCacheConn("unread");
  if (pCacheConn) {
    last_update_lock_.lock();
    m_nLastUpdate = nUpdated;
    last_update_lock_.unlock();
    string strUpdated = int2string(nUpdated);
    pCacheConn->set("total_user_update", strUpdated);
    pCacheManager->RelCacheConn(pCacheConn);
  }
  else
  {
    log("no cache connection to get total_user_updated");
  }
}

/**
 *  更新上次同步群组信息时间
 *
 *  @param nUpdated 时间
 */
void CSyncCenter::updateLastUpdateGroup(uint32_t nUpdated)
{
  CacheManager* pCacheManager = CacheManager::getInstance();
  CacheConn* pCacheConn = pCacheManager->GetCacheConn("unread");
  if (pCacheConn) {
    last_update_lock_.lock();
    m_nLastUpdateGroup = nUpdated;
    string strUpdated = int2string(nUpdated);
    last_update_lock_.unlock();

    pCacheConn->set("last_update_group", strUpdated);
    pCacheManager->RelCacheConn(pCacheConn);
  }
  else
  {
    log("no cache connection to get total_user_updated");
  }
}

/**
 *  同步群组聊天信息
 *
 *  @param arg NULL
 *
 *  @return NULL
 */
/* do ...while 一直在循环 - 除非函数stopSync()被调用,发送信号改变了循环结束状态 */
void* CSyncCenter::doSyncGroupChat(void* arg)
{
  m_bSyncGroupChatRuning = true;
  CDBManager* pDBManager = CDBManager::getInstance();
  map<uint32_t, uint32_t> mapChangedGroup;
  do {
    mapChangedGroup.clear();
    CDBConn* pDBConn = pDBManager->GetDBConn("teamtalk_slave");
    if(pDBConn)
    {
      string strSql = "select id, lastChated from IMGroup where status=0 and lastChated >=" + int2string(m_pInstance->getLastUpdateGroup());
      CResultSet* pResult = pDBConn->ExecuteQuery(strSql.c_str());
      if(pResult)
      {
        while (pResult->Next()) {
          uint32_t nGroupId = pResult->GetInt("id");
          uint32_t nLastChat = pResult->GetInt("lastChated");
          if(nLastChat != 0)
          {
            mapChangedGroup[nGroupId] = nLastChat;
          }
        }
        delete pResult;
      }
      pDBManager->RelDBConn(pDBConn);
    }
    else
    {
      log("no db connection for teamtalk_slave");
    }
    m_pInstance->updateLastUpdateGroup(time(NULL));
    for (auto it=mapChangedGroup.begin(); it!=mapChangedGroup.end(); ++it)
    {
      uint32_t nGroupId =it->first;
      list<uint32_t> lsUsers;
      uint32_t nUpdate = it->second;
      CGroupModel::getInstance()->getGroupUser(nGroupId, lsUsers);
      for (auto it1=lsUsers.begin(); it1!=lsUsers.end(); ++it1)
      {
        uint32_t nUserId = *it1;
        uint32_t nSessionId = INVALID_VALUE;
        nSessionId = CSessionModel::getInstance()->getSessionId(nUserId, nGroupId, IM::BaseDefine::SESSION_TYPE_GROUP, true);
        if(nSessionId != INVALID_VALUE)
        {
          CSessionModel::getInstance()->updateSession(nSessionId, nUpdate);
        }
        else
        {
          CSessionModel::getInstance()->addSession(nUserId, nGroupId, IM::BaseDefine::SESSION_TYPE_GROUP);
        }
      }
    }
    // while (!m_pInstance->m_pCondSync->waitTime(5*1000));
  } while (m_pInstance->m_bSyncGroupChatWaitting && !(m_pInstance->m_pCondGroupChat->waitTime(5*1000)));
  // while(m_pInstance->m_bSyncGroupChatWaitting);
  m_bSyncGroupChatRuning = false;
  return NULL;
}


/* db_proxy_server - db_proxy_server.cpp */
#include "netlib.h"
#include "ConfigFileReader.h"
#include "version.h"
#include "ThreadPool.h"
#include "DBPool.h"
#include "CachePool.h"
#include "ProxyConn.h"
#include "HttpClient.h"
#include "EncDec.h"
#include "business/AudioModel.h"
#include "business/MessageModel.h"
#include "business/SessionModel.h"
#include "business/RelationModel.h"
#include "business/UserModel.h"
#include "business/GroupModel.h"
#include "business/GroupMessageModel.h"
#include "business/FileModel.h"
#include "SyncCenter.h"

string strAudioEnc;
// this callback will be replaced by imconn_callback() in OnConnect()
/* 在函数CProxyConn::OnConnect()中netlib_option会设置该CBaseSocket对象的回调函数为imconn_callback,
 * 即连接套接字可读时,在CBaseSocket::OnRead()内的回调函数调用的是imconn.cpp:imconn_callback()方法.
 */
void proxy_serv_callback(void* callback_data, uint8_t msg, uint32_t handle, void* pParam)
{
  if (msg == NETLIB_MSG_CONNECT)
  {
    CProxyConn* pConn = new CProxyConn();
    pConn->OnConnect(handle);
  }
  else
  {
    log("!!!error msg: %d", msg);
  }
}

int main(int argc, char* argv[])
{
  if ((argc == 2) && (strcmp(argv[1], "-v") == 0)) {
    printf("Server Version: DBProxyServer/%s\n", VERSION);
    printf("Server Build: %s %s\n", __DATE__, __TIME__);
    return 0;
  }

  signal(SIGPIPE, SIG_IGN);
  srand(time(NULL));

  CacheManager* pCacheManager = CacheManager::getInstance();
  if (!pCacheManager) {
    log("CacheManager init failed");
    return -1;
  }

  CDBManager* pDBManager = CDBManager::getInstance();
  if (!pDBManager) {
    log("DBManager init failed");
    return -1;
  }
  puts("db init success");
  // 主线程初始化单例，不然在工作线程可能会出现多次初始化
  if (!CAudioModel::getInstance()) {
    return -1;
  }

  if (!CGroupMessageModel::getInstance()) {
    return -1;
  }

  if (!CGroupModel::getInstance()) {
    return -1;
  }

  if (!CMessageModel::getInstance()) {
    return -1;
  }

  if (!CSessionModel::getInstance()) {
    return -1;
  }

  if(!CRelationModel::getInstance())
  {
    return -1;
  }

  if (!CUserModel::getInstance()) {
    return -1;
  }

  if (!CFileModel::getInstance()) {
    return -1;
  }


  CConfigFileReader config_file("dbproxyserver.conf");

  char* listen_ip = config_file.GetConfigName("ListenIP");
  char* str_listen_port = config_file.GetConfigName("ListenPort");
  char* str_thread_num = config_file.GetConfigName("ThreadNum");
  char* str_file_site = config_file.GetConfigName("MsfsSite");
  char* str_aes_key = config_file.GetConfigName("aesKey");
  char* unix_socket_path = config_file.GetConfigName("UnixSocket");


  if (!listen_ip || !str_listen_port || !str_thread_num || !str_file_site || !str_aes_key) {
    log("missing ListenIP/ListenPort/ThreadNum/MsfsSite/aesKey, exit...");
    return -1;
  }

  if(strlen(str_aes_key) != 32)
  {
    log("aes key is invalied");
    return -2;
  }
  string strAesKey(str_aes_key, 32);
  CAes cAes = CAes(strAesKey);
  string strAudio = "[语音]";
  char* pAudioEnc;
  uint32_t nOutLen;
  if(cAes.Encrypt(strAudio.c_str(), strAudio.length(), &pAudioEnc, nOutLen) == 0)
  {
    strAudioEnc.clear();
    strAudioEnc.append(pAudioEnc, nOutLen);
    cAes.Free(pAudioEnc);
  }

  uint16_t listen_port = atoi(str_listen_port);
  uint32_t thread_num = atoi(str_thread_num);

  string strFileSite(str_file_site);
  CAudioModel::getInstance()->setUrl(strFileSite);

  int ret = netlib_init();

  if (ret == NETLIB_ERROR)
    return ret;

  /// yunfan add 2014.9.28
  // for 603 push
  curl_global_init(CURL_GLOBAL_ALL);
  /// yunfan add end

  init_proxy_conn(thread_num);
  CSyncCenter::getInstance()->init();
  CSyncCenter::getInstance()->startSync();

  CStrExplode listen_ip_list(listen_ip, ';');
  for (uint32_t i = 0; i < listen_ip_list.GetItemCnt(); i++)
  {
    ret = netlib_listen(listen_ip_list.GetItem(i), listen_port, proxy_serv_callback, NULL);
    if (ret == NETLIB_ERROR)
      return ret;
  }

  if(unix_socket_path)
  {
    netlib_unix_listen(unix_socket_path,proxy_serv_callback,NULL);
  }

  printf("server start listen on: %s:%d\n", listen_ip,  listen_port);
  printf("now enter the event loop...\n");
  writePid();
  netlib_eventloop(10);

  return 0;
}

/* db_proxy_server - business - Login.h */
#ifndef LOGIN_H_
#define LOGIN_H_

#include "ImPduBase.h"

namespace DB_PROXY {
/*  @param pPdu      收到的packet包指针
 *  @param conn_uuid 该包过来的socket 描述符
 */
  void doLogin(CImPdu* pPdu, uint32_t conn_uuid);
};

#endif /* LOGIN_H_ */

/* db_proxy_server - business - Login.cpp */
#include <list>
#include "../ProxyConn.h"
#include "../HttpClient.h"
#include "../SyncCenter.h"
#include "Login.h"
#include "UserModel.h"
#include "TokenValidator.h"
#include "json/json.h"
#include "Common.h"
#include "IM.Server.pb.h"
#include "Base64.h"
#include "InterLogin.h"
#include "ExterLogin.h"

CInterLoginStrategy g_loginStrategy;

hash_map<string, list<uint32_t> > g_hmLimits;
CLock g_cLimitLock;
namespace DB_PROXY {

/*  @param pPdu      收到的packet包指针
 *  @param conn_uuid 该包过来的socket 描述符
 *
 * 用户登录, 检测密码无误则:
 * 取出用户信息, msgResp将被设置为包体,
 * 将登陆应答包pPduResp加入到消息队列,
 * init_proxy_conn()函数将发送响应包给客户端.
 *
 * C数组的序列化和序列化API
 * 反序列化: bool ParseFromArray(const void* data, int size);
 * 序列化  : bool SerializeToArray(void* data, int size) const;
 */
void doLogin(CImPdu* pPdu, uint32_t conn_uuid)
{
  CImPdu* pPduResp = new CImPdu;

  IM::Server::IMValidateReq msg;
  IM::Server::IMValidateRsp msgResp;

  if(msg.ParseFromArray(pPdu->GetBodyData(), pPdu->GetBodyLength()))
  {
    string strDomain = msg.user_name();
    string strPass = msg.password();

    msgResp.set_user_name(strDomain);
    msgResp.set_attach_data(msg.attach_data());

    do
    {
      CAutoLock cAutoLock(&g_cLimitLock);
      list<uint32_t>& lsErrorTime = g_hmLimits[strDomain];
      uint32_t tmNow = time(NULL);

      //清理超过30分钟的错误时间点记录
      /*
         清理放在这里还是放在密码错误后添加的时候呢？
         放在这里，每次都要遍历，会有一点点性能的损失。
         放在后面，可能会造成30分钟之前有10次错的，但是本次是对的就没办法再访问了。
       */
      auto itTime=lsErrorTime.begin();
      for(; itTime!=lsErrorTime.end();++itTime)
      {
        if(tmNow - *itTime > 30*60)
        {
          break;
        }
      }
      if(itTime != lsErrorTime.end())
      {
        lsErrorTime.erase(itTime, lsErrorTime.end());
      }

      // 判断30分钟内密码错误次数是否大于10
      if(lsErrorTime.size() > 10)
      {
        itTime = lsErrorTime.begin();
        if(tmNow - *itTime <= 30*60)
        {
          msgResp.set_result_code(6);
          msgResp.set_result_string("用户名/密码错误次数太多");
          pPduResp->SetPBMsg(&msgResp);
          pPduResp->SetSeqNum(pPdu->GetSeqNum());
          pPduResp->SetServiceId(IM::BaseDefine::SID_OTHER);
          pPduResp->SetCommandId(IM::BaseDefine::CID_OTHER_VALIDATE_RSP);
          CProxyConn::AddResponsePdu(conn_uuid, pPduResp);
          return ;
        }
      }
    } while(false);

    log("%s request login.", strDomain.c_str());

    //////////
    IM::BaseDefine::UserInfo cUser;

    if(g_loginStrategy.doLogin(strDomain, strPass, cUser))
    {
      IM::BaseDefine::UserInfo* pUser = msgResp.mutable_user_info();
      pUser->set_user_id(cUser.user_id());
      pUser->set_user_gender(cUser.user_gender());
      pUser->set_department_id(cUser.department_id());
      pUser->set_user_nick_name(cUser.user_nick_name());
      pUser->set_user_domain(cUser.user_domain());
      pUser->set_avatar_url(cUser.avatar_url());

      pUser->set_email(cUser.email());
      pUser->set_user_tel(cUser.user_tel());
      pUser->set_user_real_name(cUser.user_real_name());
      pUser->set_status(0);

      pUser->set_sign_info(cUser.sign_info());

      msgResp.set_result_code(0);
      msgResp.set_result_string("成功");

      //如果登陆成功，则清除错误尝试限制
      CAutoLock cAutoLock(&g_cLimitLock);
      list<uint32_t>& lsErrorTime = g_hmLimits[strDomain];
      lsErrorTime.clear();
    }
    else
    {
      //密码错误，记录一次登陆失败
      uint32_t tmCurrent = time(NULL);
      CAutoLock cAutoLock(&g_cLimitLock);
      list<uint32_t>& lsErrorTime = g_hmLimits[strDomain];
      lsErrorTime.push_front(tmCurrent);

      log("get result false");
      msgResp.set_result_code(1);
      msgResp.set_result_string("用户名/密码错误");
    }
  }
  else
  {
    msgResp.set_result_code(2);
    msgResp.set_result_string("服务端内部错误");
  }

  pPduResp->SetPBMsg(&msgResp); //设置包体数据信息(PB: packet body)
  pPduResp->SetSeqNum(pPdu->GetSeqNum());
  pPduResp->SetServiceId(IM::BaseDefine::SID_OTHER);
  pPduResp->SetCommandId(IM::BaseDefine::CID_OTHER_VALIDATE_RSP);
  CProxyConn::AddResponsePdu(conn_uuid, pPduResp);
}

};

/* db_proxy_server - business - LoginStrategy.h */
#ifndef __LOGINSTRATEGY_H__
#define __LOGINSTRATEGY_H__

#include <iostream>

#include "IM.BaseDefine.pb.h"

class CLoginStrategy
{
public:
  virtual bool doLogin(const std::string& strName, const std::string& strPass, IM::BaseDefine::UserInfo& user) = 0;
};

#endif /*defined(__LOGINSTRATEGY_H__) */

/* db_proxy_server - business - InterLogin.h */
#ifndef __INTERLOGIN_H__
#define __INTERLOGIN_H__
#include "LoginStrategy.h"

/* 内部数据库验证策略 */
class CInterLoginStrategy :public CLoginStrategy
{
public:
  virtual bool doLogin(const std::string& strName, const std::string& strPass, IM::BaseDefine::UserInfo& user);
};

#endif /*defined(__INTERLOGIN_H__) */

/* db_proxy_server - business - InterLogin.cpp */
#include "InterLogin.h"
#include "../DBPool.h"
#include "EncDec.h"

/* 内部数据库验证策略.
 * 查询数据库中用户信息(没有使用MySQL预处理语句查询数据库).核查用户密码.
 */
bool CInterLoginStrategy::doLogin(const std::string &strName, const std::string &strPass, IM::BaseDefine::UserInfo& user)
{
  bool bRet = false;
  CDBManager* pDBManger = CDBManager::getInstance();
  CDBConn* pDBConn = pDBManger->GetDBConn("teamtalk_slave");
  if (pDBConn) {

    string tmpName(pDBConn->EscapeString(strName.c_str(),strName.size()));

    string strSql = "select * from IMUser where name='" + tmpName + "' and status=0";
    //string strSql = "select * from IMUser where name=? and status=?";
    /*
       CPrepareStatement* stmt = new CPrepareStatement();
       if (stmt->Init(pDBConn->GetMysql(), strSql))
       {
       uint32_t nStatus = 0;
       uint32_t index = 0;
       stmt->SetParam(index++, strName);
       stmt->SetParam(index++, nStatus);
       CResultSet* pResultSet = stmt->ExecuteQuery();
     */

    CResultSet* pResultSet = pDBConn->ExecuteQuery(strSql.c_str());
    if(pResultSet)
    {
      string strResult, strSalt;
      uint32_t nId, nGender, nDeptId, nStatus;
      string strNick, strAvatar, strEmail, strRealName, strTel, strDomain,strSignInfo;
      while (pResultSet->Next()) {
        nId = pResultSet->GetInt("id");
        strResult = pResultSet->GetString("password");
        strSalt = pResultSet->GetString("salt");

        strNick = pResultSet->GetString("nick");
        nGender = pResultSet->GetInt("sex");
        strRealName = pResultSet->GetString("name");
        strDomain = pResultSet->GetString("domain");
        strTel = pResultSet->GetString("phone");
        strEmail = pResultSet->GetString("email");
        strAvatar = pResultSet->GetString("avatar");
        nDeptId = pResultSet->GetInt("departId");
        nStatus = pResultSet->GetInt("status");
        strSignInfo = pResultSet->GetString("sign_info");

      }

      string strInPass = strPass + strSalt;
      char szMd5[33];
      CMd5::MD5_Calculate(strInPass.c_str(), strInPass.length(), szMd5);
      string strOutPass(szMd5);
      if(strOutPass == strResult)
      {
        bRet = true;
        user.set_user_id(nId);
        user.set_user_nick_name(strNick);
        user.set_user_gender(nGender);
        user.set_user_real_name(strRealName);
        user.set_user_domain(strDomain);
        user.set_user_tel(strTel);
        user.set_email(strEmail);
        user.set_avatar_url(strAvatar);
        user.set_department_id(nDeptId);
        user.set_status(nStatus);
        user.set_sign_info(strSignInfo);

      }
      delete  pResultSet;

    }
    // }
    // delete stmt;
    pDBManger->RelDBConn(pDBConn);
  }
  return bRet;
}

/* db_proxy_server - business - ExterLogin.h */
#ifndef __EXTERLOGIN_H__
#define __EXTERLOGIN_H__
#include "LoginStrategy.h"

class CExterLoginStrategy:public CLoginStrategy
{
public:
    virtual bool doLogin(const std::string& strName, const std::string& strPass, IM::BaseDefine::UserInfo& user);
};
#endif /*defined(__EXTERLOGIN_H__) */

/* db_proxy_server - business - ExterLogin.cpp */
#include "ExterLogin.h"

/* 需要通过外部接口进行验证 (暂时没有实现) */
const std::string strLoginUrl = "http://xxxx";
bool CExterLoginStrategy::doLogin(const std::string &strName, const std::string &strPass, IM::BaseDefine::UserInfo& user)
{
    bool bRet = false;
    return bRet;
}

/* db_proxy_server - business - UserModel.h */
#ifndef __USERMODEL_H__
#define __USERMODEL_H__

#include "IM.BaseDefine.pb.h"
#include "ImPduBase.h"
#include "public_define.h"

/* getChangedId 获取信息变更的用户id(多个).
 * getUsers 根据用户id(多个),获取用户信息表.
 * getUser 根据用户id(单个),获取用户信息.
 * updateUser 更新用户信息.
 * insertUser 插入一条用户数据.
 * clearUserCounter 清空用户记录.
 * setCallReport 插入一条用户调用记录.
 * updateUserSignInfo 更新用户个人签名.
 * getUserSingInfo 获取用户个人签名.
 * updatePushShield 设置APP应用夜间消息屏蔽.
 * getPushShield 获取APP应用夜间消息屏蔽状态.
 */
class CUserModel
{
public:
  static CUserModel* getInstance();
  ~CUserModel();
  void getChangedId(uint32_t& nLastTime, list<uint32_t>& lsIds);
  void getUsers(list<uint32_t> lsIds, list<IM::BaseDefine::UserInfo>& lsUsers);
  bool getUser(uint32_t nUserId, DBUserInfo_t& cUser);

  bool updateUser(DBUserInfo_t& cUser);
  bool insertUser(DBUserInfo_t& cUser);
//void getUserByNick(const list<string>& lsNicks, list<IM::BaseDefine::UserInfo>& lsUsers);
  void clearUserCounter(uint32_t nUserId, uint32_t nPeerId, IM::BaseDefine::SessionType nSessionType);
  void setCallReport(uint32_t nUserId, uint32_t nPeerId, IM::BaseDefine::ClientType nClientType);

  bool updateUserSignInfo(uint32_t user_id, const string& sign_info);
  bool getUserSingInfo(uint32_t user_id, string* sign_info);
  bool updatePushShield(uint32_t user_id, uint32_t shield_status);
  bool getPushShield(uint32_t user_id, uint32_t* shield_status);

private:
  CUserModel();
private:
  static CUserModel* m_pInstance;
};

#endif /*defined(__USERMODEL_H__) */

/* db_proxy_server - business - UserModel.cpp */
#include "UserModel.h"
#include "../DBPool.h"
#include "../CachePool.h"
#include "Common.h"
#include "SyncCenter.h"

CUserModel* CUserModel::m_pInstance = NULL;

CUserModel::CUserModel()
{
}

CUserModel::~CUserModel()
{
}

CUserModel* CUserModel::getInstance()
{
  if(m_pInstance == NULL)
  {
    m_pInstance = new CUserModel();
  }
  return m_pInstance;
}

/* 获取信息变更的用户id(多个). */
void CUserModel::getChangedId(uint32_t& nLastTime, list<uint32_t> &lsIds)
{
  CDBManager* pDBManager = CDBManager::getInstance();
  CDBConn* pDBConn = pDBManager->GetDBConn("teamtalk_slave");
  if (pDBConn)
  {
    string strSql ;
    if(nLastTime == 0)
    {
      strSql = "select id, updated from IMUser where status != 3";
    }
    else
    {
      strSql = "select id, updated from IMUser where updated>=" + int2string(nLastTime);
    }
    CResultSet* pResultSet = pDBConn->ExecuteQuery(strSql.c_str());
    if(pResultSet)
    {
      while (pResultSet->Next()) {
        uint32_t nId = pResultSet->GetInt("id");
        uint32_t nUpdated = pResultSet->GetInt("updated");
        if(nLastTime < nUpdated)
        {
          nLastTime = nUpdated;
        }
        lsIds.push_back(nId);
      }
      delete pResultSet;
    }
    else
    {
      log(" no result set for sql:%s", strSql.c_str());
    }
    pDBManager->RelDBConn(pDBConn);
  }
  else
  {
    log("no db connection for teamtalk_slave");
  }
}

/* 根据用户id(多个),获取用户信息表. */
void CUserModel::getUsers(list<uint32_t> lsIds, list<IM::BaseDefine::UserInfo> &lsUsers)
{
  if (lsIds.empty()) {
    log("list is empty");
    return;
  }
  CDBManager* pDBManager = CDBManager::getInstance();
  CDBConn* pDBConn = pDBManager->GetDBConn("teamtalk_slave");
  if (pDBConn)
  {
    string strClause;
    bool bFirst = true;
    for (auto it = lsIds.begin(); it!=lsIds.end(); ++it)
    {
      if(bFirst)
      {
        bFirst = false;
        strClause += int2string(*it);
      }
      else
      {
        strClause += ("," + int2string(*it));
      }
    }
    string  strSql = "select * from IMUser where id in (" + strClause + ")";
    CResultSet* pResultSet = pDBConn->ExecuteQuery(strSql.c_str());
    if(pResultSet)
    {
      while (pResultSet->Next())
      {
        IM::BaseDefine::UserInfo cUser;
        cUser.set_user_id(pResultSet->GetInt("id"));
        cUser.set_user_gender(pResultSet->GetInt("sex"));
        cUser.set_user_nick_name(pResultSet->GetString("nick"));
        cUser.set_user_domain(pResultSet->GetString("domain"));
        cUser.set_user_real_name(pResultSet->GetString("name"));
        cUser.set_user_tel(pResultSet->GetString("phone"));
        cUser.set_email(pResultSet->GetString("email"));
        cUser.set_avatar_url(pResultSet->GetString("avatar"));
        cUser.set_sign_info(pResultSet->GetString("sign_info"));

        cUser.set_department_id(pResultSet->GetInt("departId"));
        cUser.set_department_id(pResultSet->GetInt("departId"));
        cUser.set_status(pResultSet->GetInt("status"));
        lsUsers.push_back(cUser);
      }
      delete pResultSet;
    }
    else
    {
      log(" no result set for sql:%s", strSql.c_str());
    }
    pDBManager->RelDBConn(pDBConn);
  }
  else
  {
    log("no db connection for teamtalk_slave");
  }
}

/* 根据用户id(单个),获取用户信息. */
bool CUserModel::getUser(uint32_t nUserId, DBUserInfo_t &cUser)
{
  bool bRet = false;
  CDBManager* pDBManager = CDBManager::getInstance();
  CDBConn* pDBConn = pDBManager->GetDBConn("teamtalk_slave");
  if (pDBConn)
  {
    string strSql = "select * from IMUser where id="+int2string(nUserId);
    CResultSet* pResultSet = pDBConn->ExecuteQuery(strSql.c_str());
    if(pResultSet)
    {
      while (pResultSet->Next())
      {
        cUser.nId = pResultSet->GetInt("id");
        cUser.nSex = pResultSet->GetInt("sex");
        cUser.strNick = pResultSet->GetString("nick");
        cUser.strDomain = pResultSet->GetString("domain");
        cUser.strName = pResultSet->GetString("name");
        cUser.strTel = pResultSet->GetString("phone");
        cUser.strEmail = pResultSet->GetString("email");
        cUser.strAvatar = pResultSet->GetString("avatar");
        cUser.sign_info = pResultSet->GetString("sign_info");
        cUser.nDeptId = pResultSet->GetInt("departId");
        cUser.nStatus = pResultSet->GetInt("status");
        bRet = true;
      }
      delete pResultSet;
    }
    else
    {
      log("no result set for sql:%s", strSql.c_str());
    }
    pDBManager->RelDBConn(pDBConn);
  }
  else
  {
    log("no db connection for teamtalk_slave");
  }
  return bRet;
}

/* 更新用户信息. */
bool CUserModel::updateUser(DBUserInfo_t &cUser)
{
  bool bRet = false;
  CDBManager* pDBManager = CDBManager::getInstance();
  CDBConn* pDBConn = pDBManager->GetDBConn("teamtalk_master");
  if (pDBConn)
  {
    uint32_t nNow = (uint32_t)time(NULL);
    string strSql = "update IMUser set `sex`=" + int2string(cUser.nSex)+ ", `nick`='" + cUser.strNick +"', `domain`='"+ cUser.strDomain + "', `name`='" + cUser.strName + "', `phone`='" + cUser.strTel + "', `email`='" + cUser.strEmail+ "', `avatar`='" + cUser.strAvatar + "', `sign_info`='" + cUser.sign_info +"', `departId`='" + int2string(cUser.nDeptId) + "', `status`=" + int2string(cUser.nStatus) + ", `updated`="+int2string(nNow) + " where id="+int2string(cUser.nId);
    bRet = pDBConn->ExecuteUpdate(strSql.c_str());
    if(!bRet)
    {
      log("updateUser: update failed:%s", strSql.c_str());
    }
    pDBManager->RelDBConn(pDBConn);
  }
  else
  {
    log("no db connection for teamtalk_master");
  }
  return bRet;
}

/* 插入一条用户数据. */
bool CUserModel::insertUser(DBUserInfo_t &cUser)
{
  bool bRet = false;
  CDBManager* pDBManager = CDBManager::getInstance();
  CDBConn* pDBConn = pDBManager->GetDBConn("teamtalk_master");
  if (pDBConn)
  {
    string strSql = "insert into IMUser(`id`,`sex`,`nick`,`domain`,`name`,`phone`,`email`,`avatar`,`sign_info`,`departId`,`status`,`created`,`updated`) values(?,?,?,?,?,?,?,?,?,?,?,?)";
    CPrepareStatement* stmt = new CPrepareStatement();
    if (stmt->Init(pDBConn->GetMysql(), strSql))
    {
      uint32_t nNow = (uint32_t) time(NULL);
      uint32_t index = 0;
      uint32_t nGender = cUser.nSex;
      uint32_t nStatus = cUser.nStatus;
      stmt->SetParam(index++, cUser.nId);
      stmt->SetParam(index++, nGender);
      stmt->SetParam(index++, cUser.strNick);
      stmt->SetParam(index++, cUser.strDomain);
      stmt->SetParam(index++, cUser.strName);
      stmt->SetParam(index++, cUser.strTel);
      stmt->SetParam(index++, cUser.strEmail);
      stmt->SetParam(index++, cUser.strAvatar);

      stmt->SetParam(index++, cUser.sign_info);
      stmt->SetParam(index++, cUser.nDeptId);
      stmt->SetParam(index++, nStatus);
      stmt->SetParam(index++, nNow);
      stmt->SetParam(index++, nNow);
      bRet = stmt->ExecuteUpdate();

      if (!bRet)
      {
        log("insert user failed: %s", strSql.c_str());
      }
    }
    delete stmt;
    pDBManager->RelDBConn(pDBConn);
  }
  else
  {
    log("no db connection for teamtalk_master");
  }
  return bRet;
}

/* 根据用户 id 清空用户记录. */
void CUserModel::clearUserCounter(uint32_t nUserId, uint32_t nPeerId, IM::BaseDefine::SessionType nSessionType)
{
  if(IM::BaseDefine::SessionType_IsValid(nSessionType))
  {
    CacheManager* pCacheManager = CacheManager::getInstance();
    CacheConn* pCacheConn = pCacheManager->GetCacheConn("unread");
    if (pCacheConn)
    {
      // Clear P2P msg Counter
      if(nSessionType == IM::BaseDefine::SESSION_TYPE_SINGLE)
      {
        int nRet = pCacheConn->hdel("unread_" + int2string(nUserId), int2string(nPeerId));
        if(!nRet)
        {
          log("hdel failed %d->%d", nPeerId, nUserId);
        }
      }
      // Clear Group msg Counter
      else if(nSessionType == IM::BaseDefine::SESSION_TYPE_GROUP)
      {
        string strGroupKey = int2string(nPeerId) + GROUP_TOTAL_MSG_COUNTER_REDIS_KEY_SUFFIX;
        map<string, string> mapGroupCount;
        bool bRet = pCacheConn->hgetAll(strGroupKey, mapGroupCount);
        if(bRet)
        {
          string strUserKey = int2string(nUserId) + "_" + int2string(nPeerId) + GROUP_USER_MSG_COUNTER_REDIS_KEY_SUFFIX;
          string strReply = pCacheConn->hmset(strUserKey, mapGroupCount);
          if(strReply.empty()) {
            log("hmset %s failed !", strUserKey.c_str());
          }
        }
        else
        {
          log("hgetall %s failed!", strGroupKey.c_str());
        }

      }
      pCacheManager->RelCacheConn(pCacheConn);
    }
    else
    {
      log("no cache connection for unread");
    }
  }
  else{
    log("invalid sessionType. userId=%u, fromId=%u, sessionType=%u", nUserId, nPeerId, nSessionType);
  }
}

/* 插入一条用户调用记录. */
void CUserModel::setCallReport(uint32_t nUserId, uint32_t nPeerId, IM::BaseDefine::ClientType nClientType)
{
  if(IM::BaseDefine::ClientType_IsValid(nClientType))
  {
    CDBManager* pDBManager = CDBManager::getInstance();
    CDBConn* pDBConn = pDBManager->GetDBConn("teamtalk_master");
    if(pDBConn)
    {
      string strSql = "insert into IMCallLog(`userId`, `peerId`, `clientType`,`created`,`updated`) values(?,?,?,?,?)";
      CPrepareStatement* stmt = new CPrepareStatement();
      if (stmt->Init(pDBConn->GetMysql(), strSql))
      {
        uint32_t nNow = (uint32_t) time(NULL);
        uint32_t index = 0;
        uint32_t nClient = (uint32_t) nClientType;
        stmt->SetParam(index++, nUserId);
        stmt->SetParam(index++, nPeerId);
        stmt->SetParam(index++, nClient);
        stmt->SetParam(index++, nNow);
        stmt->SetParam(index++, nNow);
        bool bRet = stmt->ExecuteUpdate();

        if (!bRet)
        {
          log("insert report failed: %s", strSql.c_str());
        }
      }
      delete stmt;
      pDBManager->RelDBConn(pDBConn);
    }
    else
    {
      log("no db connection for teamtalk_master");
    }

  }
  else
  {
    log("invalid clienttype. userId=%u, peerId=%u, clientType=%u", nUserId, nPeerId, nClientType);
  }
}

/* 更新用户个人签名. */
bool CUserModel::updateUserSignInfo(uint32_t user_id, const string& sign_info)
{

  if (sign_info.length() > 128) {
    log("updateUserSignInfo: sign_info.length()>128.\n");
    return false;
  }
  bool rv = false;
  CDBManager* db_manager = CDBManager::getInstance();
  CDBConn* db_conn = db_manager->GetDBConn("teamtalk_master");
  if (db_conn) {
    uint32_t now = (uint32_t)time(NULL);
    string str_sql = "update IMUser set `sign_info`='" + sign_info + "', `updated`=" + int2string(now) + " where id="+int2string(user_id);
    rv = db_conn->ExecuteUpdate(str_sql.c_str());
    if(!rv) {
      log("updateUserSignInfo: update failed:%s", str_sql.c_str());
    }else{
      CSyncCenter::getInstance()->updateTotalUpdate(now);

    }
    db_manager->RelDBConn(db_conn);
  } else {
    log("updateUserSignInfo: no db connection for teamtalk_master");
  }
  return rv;
}

/* 获取用户个人签名. */
bool CUserModel::getUserSingInfo(uint32_t user_id, string* sign_info)
{
  bool rv = false;
  CDBManager* db_manager = CDBManager::getInstance();
  CDBConn* db_conn = db_manager->GetDBConn("teamtalk_slave");
  if (db_conn) {
    string str_sql = "select sign_info from IMUser where id="+int2string(user_id);
    CResultSet* result_set = db_conn->ExecuteQuery(str_sql.c_str());
    if(result_set) {
      if (result_set->Next()) {
        *sign_info = result_set->GetString("sign_info");
        rv = true;
      }
      delete result_set;
    } else {
      log("no result set for sql:%s", str_sql.c_str());
    }
    db_manager->RelDBConn(db_conn);
  } else {
    log("no db connection for teamtalk_slave");
  }
  return rv;
}

/* 设置APP应用夜间消息屏蔽. */
bool CUserModel::updatePushShield(uint32_t user_id, uint32_t shield_status)
{
  bool rv = false;

  CDBManager* db_manager = CDBManager::getInstance();
  CDBConn* db_conn = db_manager->GetDBConn("teamtalk_master");
  if (db_conn) {
    uint32_t now = (uint32_t)time(NULL);
    string str_sql = "update IMUser set `push_shield_status`="+ int2string(shield_status) + ", `updated`=" + int2string(now) + " where id="+int2string(user_id);
    rv = db_conn->ExecuteUpdate(str_sql.c_str());
    if(!rv) {
      log("updatePushShield: update failed:%s", str_sql.c_str());
    }
    db_manager->RelDBConn(db_conn);
  } else {
    log("updatePushShield: no db connection for teamtalk_master");
  }

  return rv;
}

/* 获取APP应用夜间消息屏蔽状态. */
bool CUserModel::getPushShield(uint32_t user_id, uint32_t* shield_status)
{
  bool rv = false;

  CDBManager* db_manager = CDBManager::getInstance();
  CDBConn* db_conn = db_manager->GetDBConn("teamtalk_slave");
  if (db_conn) {
    string str_sql = "select push_shield_status from IMUser where id="+int2string(user_id);
    CResultSet* result_set = db_conn->ExecuteQuery(str_sql.c_str());
    if(result_set) {
      if (result_set->Next()) {
        *shield_status = result_set->GetInt("push_shield_status");
        rv = true;
      }
      delete result_set;
    } else {
      log("getPushShield: no result set for sql:%s", str_sql.c_str());
    }
    db_manager->RelDBConn(db_conn);
  } else {
    log("getPushShield: no db connection for teamtalk_slave");
  }

  return rv;
}

/* db_proxy_server - business - UserAction.h */
#ifndef __USER_ACTION_H__
#define __USER_ACTION_H__

#include "ImPduBase.h"

/*  @param pPdu      收到的packet包指针
 *  @param conn_uuid 该包过来的socket 描述符
 *
 * getUserInfo 由某个用户根据一个用户id表获取多个其他用户信息.
 * getChangedUser 获取信息有变更的用户列表.
 * changeUserSignInfo 更新用户个性签名.
 * doPushShield 设置APP应用夜间消息屏蔽.
 * doQueryPushShield 获取APP应用夜间消息屏蔽状态.
 */
namespace DB_PROXY {
  void getUserInfo(CImPdu* pPdu, uint32_t conn_uuid);
  void getChangedUser(CImPdu* pPdu, uint32_t conn_uuid);
  void changeUserSignInfo(CImPdu* pPdu, uint32_t conn_uuid);
  void doPushShield(CImPdu* pPdu, uint32_t conn_uuid);
  void doQueryPushShield(CImPdu* pPdu, uint32_t conn_uuid);
};

#endif /* __USER_ACTION_H__ */

/* db_proxy_server - business - UserAction.cpp */
#include <list>
#include <map>
#include "../ProxyConn.h"
#include "../DBPool.h"
#include "../SyncCenter.h"
#include "public_define.h"
#include "UserModel.h"
#include "IM.Login.pb.h"
#include "IM.Buddy.pb.h"
#include "IM.BaseDefine.pb.h"

namespace DB_PROXY {

/* 由某个用户根据一个用户id表获取多个其他用户信息. */
void getUserInfo(CImPdu* pPdu, uint32_t conn_uuid)
{
  IM::Buddy::IMUsersInfoReq msg;
  IM::Buddy::IMUsersInfoRsp msgResp;
  if(msg.ParseFromArray(pPdu->GetBodyData(), pPdu->GetBodyLength()))
  {
    CImPdu* pPduRes = new CImPdu;

    uint32_t from_user_id = msg.user_id();
    uint32_t userCount = msg.user_id_list_size();
    std::list<uint32_t> idList;
    for(uint32_t i = 0; i < userCount;++i) {
      idList.push_back(msg.user_id_list(i));
    }
    std::list<IM::BaseDefine::UserInfo> lsUser;
    CUserModel::getInstance()->getUsers(idList, lsUser);
    msgResp.set_user_id(from_user_id);
    for(list<IM::BaseDefine::UserInfo>::iterator it=lsUser.begin();
        it!=lsUser.end(); ++it)
    {
      IM::BaseDefine::UserInfo* pUser = msgResp.add_user_info_list();
      //*pUser = *it;

      pUser->set_user_id(it->user_id());
      pUser->set_user_gender(it->user_gender());
      pUser->set_user_nick_name(it->user_nick_name());
      pUser->set_avatar_url(it->avatar_url());

      pUser->set_sign_info(it->sign_info());
      pUser->set_department_id(it->department_id());
      pUser->set_email(it->email());
      pUser->set_user_real_name(it->user_real_name());
      pUser->set_user_tel(it->user_tel());
      pUser->set_user_domain(it->user_domain());
      pUser->set_status(it->status());
    }
    log("userId=%u, userCnt=%u", from_user_id, userCount);
    msgResp.set_attach_data(msg.attach_data());
    pPduRes->SetPBMsg(&msgResp);
    pPduRes->SetSeqNum(pPdu->GetSeqNum());
    pPduRes->SetServiceId(IM::BaseDefine::SID_BUDDY_LIST);
    pPduRes->SetCommandId(IM::BaseDefine::CID_BUDDY_LIST_USER_INFO_RESPONSE);
    CProxyConn::AddResponsePdu(conn_uuid, pPduRes);
  }
  else
  {
    log("parse pb failed");
  }
}

/* 获取信息有变更的用户列表. */
void getChangedUser(CImPdu* pPdu, uint32_t conn_uuid)
{
  IM::Buddy::IMAllUserReq msg;
  IM::Buddy::IMAllUserRsp msgResp;
  if(msg.ParseFromArray(pPdu->GetBodyData(), pPdu->GetBodyLength()))
  {
    CImPdu* pPduRes = new CImPdu;

    uint32_t nReqId = msg.user_id();
    uint32_t nLastTime = msg.latest_update_time();
    uint32_t nLastUpdate = CSyncCenter::getInstance()->getLastUpdate();

    list<IM::BaseDefine::UserInfo> lsUsers;
    if( nLastUpdate > nLastTime)
    {
      list<uint32_t> lsIds;
      CUserModel::getInstance()->getChangedId(nLastTime, lsIds);
      CUserModel::getInstance()->getUsers(lsIds, lsUsers);
    }

    msgResp.set_user_id(nReqId);
    msgResp.set_latest_update_time(nLastTime);
    for (list<IM::BaseDefine::UserInfo>::iterator it=lsUsers.begin();
        it!=lsUsers.end(); ++it) {
      IM::BaseDefine::UserInfo* pUser = msgResp.add_user_list();
      //*pUser = *it;
      pUser->set_user_id(it->user_id());
      pUser->set_user_gender(it->user_gender());
      pUser->set_user_nick_name(it->user_nick_name());
      pUser->set_avatar_url(it->avatar_url());
      pUser->set_sign_info(it->sign_info());
      pUser->set_department_id(it->department_id());
      pUser->set_email(it->email());
      pUser->set_user_real_name(it->user_real_name());
      pUser->set_user_tel(it->user_tel());
      pUser->set_user_domain(it->user_domain());
      pUser->set_status(it->status());
    }
    log("userId=%u,nLastUpdate=%u, last_time=%u, userCnt=%u", nReqId,nLastUpdate, nLastTime, msgResp.user_list_size());
    msgResp.set_attach_data(msg.attach_data());
    pPduRes->SetPBMsg(&msgResp);
    pPduRes->SetSeqNum(pPdu->GetSeqNum());
    pPduRes->SetServiceId(IM::BaseDefine::SID_BUDDY_LIST);
    pPduRes->SetCommandId(IM::BaseDefine::CID_BUDDY_LIST_ALL_USER_RESPONSE);
    CProxyConn::AddResponsePdu(conn_uuid, pPduRes);
  }
  else
  {
    log("parse pb failed");
  }
}

/* 更新用户个性签名. */
void changeUserSignInfo(CImPdu* pPdu, uint32_t conn_uuid)
{
  IM::Buddy::IMChangeSignInfoReq req;
  IM::Buddy::IMChangeSignInfoRsp resp;
  if(req.ParseFromArray(pPdu->GetBodyData(), pPdu->GetBodyLength())) {
    uint32_t user_id = req.user_id();
    const string& sign_info = req.sign_info();

    bool result = CUserModel::getInstance()->updateUserSignInfo(user_id, sign_info);

    resp.set_user_id(user_id);
    resp.set_result_code(result ? 0 : 1);
    if (result) {
      resp.set_sign_info(sign_info);
      log("changeUserSignInfo sucess, user_id=%u, sign_info=%s", user_id, sign_info.c_str());
    } else {
      log("changeUserSignInfo false, user_id=%u, sign_info=%s", user_id, sign_info.c_str());
    }

    CImPdu* pdu_resp = new CImPdu();
    resp.set_attach_data(req.attach_data());
    pdu_resp->SetPBMsg(&resp);
    pdu_resp->SetSeqNum(pPdu->GetSeqNum());
    pdu_resp->SetServiceId(IM::BaseDefine::SID_BUDDY_LIST);
    pdu_resp->SetCommandId(IM::BaseDefine::CID_BUDDY_LIST_CHANGE_SIGN_INFO_RESPONSE);
    CProxyConn::AddResponsePdu(conn_uuid, pdu_resp);

  } else {
    log("changeUserSignInfo: IMChangeSignInfoReq ParseFromArray failed!!!");
  }
}
  
/* 设置夜间APP应用消息屏蔽. */
void doPushShield(CImPdu* pPdu, uint32_t conn_uuid) {
  IM::Login::IMPushShieldReq req;
  IM::Login::IMPushShieldRsp resp;
  if(req.ParseFromArray(pPdu->GetBodyData(), pPdu->GetBodyLength())) {
    uint32_t user_id = req.user_id();
    uint32_t shield_status = req.shield_status();
    // const string& sign_info = req.sign_info();

    bool result = CUserModel::getInstance()->updatePushShield(user_id, shield_status);

    resp.set_user_id(user_id);
    resp.set_result_code(result ? 0 : 1);
    if (result) {
      resp.set_shield_status(shield_status);
      log("doPushShield sucess, user_id=%u, shield_status=%u", user_id, shield_status);
    } else {
      log("doPushShield false, user_id=%u, shield_status=%u", user_id, shield_status);
    }


    CImPdu* pdu_resp = new CImPdu();
    resp.set_attach_data(req.attach_data());
    pdu_resp->SetPBMsg(&resp);
    pdu_resp->SetSeqNum(pPdu->GetSeqNum());
    pdu_resp->SetServiceId(IM::BaseDefine::SID_LOGIN);
    pdu_resp->SetCommandId(IM::BaseDefine::CID_LOGIN_RES_PUSH_SHIELD);
    CProxyConn::AddResponsePdu(conn_uuid, pdu_resp);

  } else {
    log("doPushShield: IMPushShieldReq ParseFromArray failed!!!");
  }
}

/* 获取夜间APP应用消息屏蔽状态. */
void doQueryPushShield(CImPdu* pPdu, uint32_t conn_uuid) {
  IM::Login::IMQueryPushShieldReq req;
  IM::Login::IMQueryPushShieldRsp resp;
  if(req.ParseFromArray(pPdu->GetBodyData(), pPdu->GetBodyLength())) {
    uint32_t user_id = req.user_id();
    uint32_t shield_status = 0;

    bool result = CUserModel::getInstance()->getPushShield(user_id, &shield_status);

    resp.set_user_id(user_id);
    resp.set_result_code(result ? 0 : 1);
    if (result) {
      resp.set_shield_status(shield_status);
      log("doQueryPushShield sucess, user_id=%u, shield_status=%u", user_id, shield_status);
    } else {
      log("doQueryPushShield false, user_id=%u", user_id);
    }

    CImPdu* pdu_resp = new CImPdu();
    resp.set_attach_data(req.attach_data());
    pdu_resp->SetPBMsg(&resp);
    pdu_resp->SetSeqNum(pPdu->GetSeqNum());
    pdu_resp->SetServiceId(IM::BaseDefine::SID_LOGIN);
    pdu_resp->SetCommandId(IM::BaseDefine::CID_LOGIN_RES_QUERY_PUSH_SHIELD);
    CProxyConn::AddResponsePdu(conn_uuid, pdu_resp);
  } else {
    log("doQueryPushShield: IMQueryPushShieldReq ParseFromArray failed!!!");
  }
}

};

/* db_proxy_server - business - SessionModel.h */
#ifndef __SESSIONMODEL_H__
#define __SESSIONMODEL_H__

#include "ImPduBase.h"
#include "IM.BaseDefine.pb.h"

/* getRecentSession 获取最近联系人列表
 * getSessionId 获取用户与其他用户会话接口的id.
 * updateSession 根据id更新会话接口的会话时间.
 * removeSession 根据id删除会话接口.(实际只是更新了会话状态).
 * addSession 插入新的会话接口(如果之前已经删除该会话,重新更新该会话id状态).
 * fillSessionMsg 在用户所有的会话接口中填充聊天内容.
 */
class CSessionModel
{
public:
  static CSessionModel* getInstance();
  ~CSessionModel() {}

  void getRecentSession(uint32_t userId, uint32_t lastTime, list<IM::BaseDefine::ContactSessionInfo>& lsContact);
  uint32_t getSessionId(uint32_t nUserId, uint32_t nPeerId, uint32_t nType, bool isAll);
  bool updateSession(uint32_t nSessionId, uint32_t nUpdateTime);
  bool removeSession(uint32_t nSessionId);
  uint32_t addSession(uint32_t nUserId, uint32_t nPeerId, uint32_t nType);

private:
  CSessionModel() {};
  void fillSessionMsg(uint32_t nUserId, list<IM::BaseDefine::ContactSessionInfo>& lsContact);
private:
  static CSessionModel* m_pInstance;
};

#endif /*defined(__SESSIONMODEL_H__) */

/* db_proxy_server - business - SessionModel.cpp */
#include "SessionModel.h"
#include "DBPool.h"
#include "MessageModel.h"
#include "GroupMessageModel.h"

CSessionModel* CSessionModel::m_pInstance = NULL;

CSessionModel* CSessionModel::getInstance()
{
  if (!m_pInstance) {
    m_pInstance = new CSessionModel();
  }

  return m_pInstance;
}

/* 获取最近联系人列表 */
void CSessionModel::getRecentSession(uint32_t nUserId, uint32_t lastTime, list<IM::BaseDefine::ContactSessionInfo>& lsContact)
{
  CDBManager* pDBManager = CDBManager::getInstance();
  CDBConn* pDBConn = pDBManager->GetDBConn("teamtalk_slave");
  if (pDBConn)
  {
    string strSql = "select * from IMRecentSession where userId = " + int2string(nUserId) + " and status = 0 and updated >" + int2string(lastTime) + " order by updated desc limit 100";

    CResultSet* pResultSet = pDBConn->ExecuteQuery(strSql.c_str());
    if (pResultSet)
    {
      while (pResultSet->Next())
      {
        IM::BaseDefine::ContactSessionInfo cRelate;
        uint32_t nPeerId = pResultSet->GetInt("peerId");
        cRelate.set_session_id(nPeerId);
        cRelate.set_session_status(::IM::BaseDefine::SessionStatusType(pResultSet->GetInt("status")));

        IM::BaseDefine::SessionType nSessionType = IM::BaseDefine::SessionType(pResultSet->GetInt("type"));
        if(IM::BaseDefine::SessionType_IsValid(nSessionType))
        {
          cRelate.set_session_type(IM::BaseDefine::SessionType(nSessionType));
          cRelate.set_updated_time(pResultSet->GetInt("updated"));
          lsContact.push_back(cRelate);
        }
        else
        {
          log("invalid sessionType. userId=%u, peerId=%u, sessionType=%u", nUserId, nPeerId, nSessionType);
        }
      }
      delete pResultSet;
    }
    else
    {
      log("no result set for sql: %s", strSql.c_str());
    }
    pDBManager->RelDBConn(pDBConn);
    if(!lsContact.empty())
    {
      fillSessionMsg(nUserId, lsContact);
    }
  }
  else
  {
    log("no db connection for teamtalk_slave");
  }
}

/* 获取用户与其他用户会话接口的id. */
uint32_t CSessionModel::getSessionId(uint32_t nUserId, uint32_t nPeerId, uint32_t nType, bool isAll)
{
  CDBManager* pDBManager = CDBManager::getInstance();
  CDBConn* pDBConn = pDBManager->GetDBConn("teamtalk_slave");
  uint32_t nSessionId = INVALID_VALUE;
  if(pDBConn)
  {
    string strSql;
    if (isAll) {
      strSql= "select id from IMRecentSession where userId=" + int2string(nUserId) + " and peerId=" + int2string(nPeerId) + " and type=" + int2string(nType);
    }
    else
    {
      strSql= "select id from IMRecentSession where userId=" + int2string(nUserId) + " and peerId=" + int2string(nPeerId) + " and type=" + int2string(nType) + " and status=0";
    }

    CResultSet* pResultSet = pDBConn->ExecuteQuery(strSql.c_str());
    if(pResultSet)
    {
      while (pResultSet->Next()) {
        nSessionId = pResultSet->GetInt("id");
      }
      delete pResultSet;
    }
    pDBManager->RelDBConn(pDBConn);
  }
  else
  {
    log("no db connection for teamtalk_slave");
  }
  return nSessionId;
}

/* 根据id更新会话接口的会话时间. */
bool CSessionModel::updateSession(uint32_t nSessionId, uint32_t nUpdateTime)
{
  bool bRet = false;
  CDBManager* pDBManager = CDBManager::getInstance();
  CDBConn* pDBConn = pDBManager->GetDBConn("teamtalk_master");
  if (pDBConn)
  {
    string strSql = "update IMRecentSession set `updated`="+int2string(nUpdateTime) + " where id="+int2string(nSessionId);
    bRet = pDBConn->ExecuteUpdate(strSql.c_str());
    pDBManager->RelDBConn(pDBConn);
  }
  else
  {
    log("no db connection for teamtalk_master");
  }
  return bRet;
}

/* 根据id删除会话接口.(实际只是更新了会话状态). */
bool CSessionModel::removeSession(uint32_t nSessionId)
{
  bool bRet = false;
  CDBManager* pDBManager = CDBManager::getInstance();
  CDBConn* pDBConn = pDBManager->GetDBConn("teamtalk_master");
  if (pDBConn)
  {
    uint32_t nNow = (uint32_t) time(NULL);
    string strSql = "update IMRecentSession set status = 1, updated="+int2string(nNow)+" where id=" + int2string(nSessionId);
    bRet = pDBConn->ExecuteUpdate(strSql.c_str());
    pDBManager->RelDBConn(pDBConn);
  }
  else
  {
    log("no db connection for teamtalk_master");
  }
  return bRet;
}

/* 插入新的会话接口(如果之前已经删除该会话,重新更新该会话id状态). */
uint32_t CSessionModel::addSession(uint32_t nUserId, uint32_t nPeerId, uint32_t nType)
{
  uint32_t nSessionId = INVALID_VALUE;

  nSessionId = getSessionId(nUserId, nPeerId, nType, true);
  uint32_t nTimeNow = time(NULL);
  CDBManager* pDBManager = CDBManager::getInstance();
  CDBConn* pDBConn = pDBManager->GetDBConn("teamtalk_master");
  if (pDBConn)
  {
    if(INVALID_VALUE != nSessionId)
    {
      string strSql = "update IMRecentSession set status=0, updated=" + int2string(nTimeNow) + " where id=" + int2string(nSessionId);
      bool bRet = pDBConn->ExecuteUpdate(strSql.c_str());
      if(!bRet)
      {
        nSessionId = INVALID_VALUE;
      }
      log("has relation ship set status");
    }
    else
    {
      string strSql = "insert into IMRecentSession (`userId`,`peerId`,`type`,`status`,`created`,`updated`) values(?,?,?,?,?,?)";
      // 必须在释放连接前delete CPrepareStatement对象，否则有可能多个线程操作mysql对象，会crash
      CPrepareStatement* stmt = new CPrepareStatement();
      if (stmt->Init(pDBConn->GetMysql(), strSql))
      {
        uint32_t nStatus = 0;
        uint32_t index = 0;
        stmt->SetParam(index++, nUserId);
        stmt->SetParam(index++, nPeerId);
        stmt->SetParam(index++, nType);
        stmt->SetParam(index++, nStatus);
        stmt->SetParam(index++, nTimeNow);
        stmt->SetParam(index++, nTimeNow);
        bool bRet = stmt->ExecuteUpdate();
        if (bRet)
        {
          nSessionId = pDBConn->GetInsertId();
        }
        else
        {
          log("insert message failed. %s", strSql.c_str());
        }
      }
      delete stmt;
    }
    pDBManager->RelDBConn(pDBConn);
  }
  else
  {
    log("no db connection for teamtalk_master");
  }
  return nSessionId;
}

/* 在用户所有的会话接口中填充聊天内容. */
void CSessionModel::fillSessionMsg(uint32_t nUserId, list<IM::BaseDefine::ContactSessionInfo>& lsContact)
{
  for (auto it=lsContact.begin(); it!=lsContact.end();)
  {
    uint32_t nMsgId = 0;
    string strMsgData;
    IM::BaseDefine::MsgType nMsgType;
    uint32_t nFromId = 0;
    if( it->session_type() == IM::BaseDefine::SESSION_TYPE_SINGLE)
    {
      nFromId = it->session_id();
      CMessageModel::getInstance()->getLastMsg(it->session_id(), nUserId, nMsgId, strMsgData, nMsgType);
    }
    else
    {
      CGroupMessageModel::getInstance()->getLastMsg(it->session_id(), nMsgId, strMsgData, nMsgType, nFromId);
    }
    if(!IM::BaseDefine::MsgType_IsValid(nMsgType))
    {
      it = lsContact.erase(it);
    }
    else
    {
      it->set_latest_msg_from_user_id(nFromId);
      it->set_latest_msg_id(nMsgId);
      it->set_latest_msg_data(strMsgData);
      it->set_latest_msg_type(nMsgType);
      ++it;
    }
  }
}

/* db_proxy_server - business - RecentSession.h */
#ifndef FRIEND_SHIP_H_
#define FRIEND_SHIP_H_

#include "ImPduBase.h"

namespace DB_PROXY {
  void getRecentSession(CImPdu* pPdu, uint32_t conn_uuid);
  void deleteRecentSession(CImPdu* pPdu, uint32_t conn_uuid);
};

#endif /* FRIEND_SHIP_H_ */

/* db_proxy_server - business - RecentSession.cpp */
#include <list>
#include <vector>
#include "../ProxyConn.h"
#include "../DBPool.h"
#include "../CachePool.h"
#include "SessionModel.h"
#include "RecentSession.h"
#include "UserModel.h"
#include "GroupModel.h"
#include "IM.Buddy.pb.h"

using namespace std;

namespace DB_PROXY {
/**
 *  获取最近会话接口(多个会话)
 *
 *  @param pPdu      收到的packet包指针
 *  @param conn_uuid 该包过来的socket 描述符
 */
void getRecentSession(CImPdu* pPdu, uint32_t conn_uuid)
{
  IM::Buddy::IMRecentContactSessionReq msg;
  IM::Buddy::IMRecentContactSessionRsp msgResp;
  if(msg.ParseFromArray(pPdu->GetBodyData(), pPdu->GetBodyLength()))
  {
    CImPdu* pPduResp = new CImPdu;

    uint32_t nUserId = msg.user_id();
    uint32_t nLastTime = msg.latest_update_time();

    //获取最近联系人列表
    list<IM::BaseDefine::ContactSessionInfo> lsContactList;
    CSessionModel::getInstance()->getRecentSession(nUserId, nLastTime, lsContactList);
    msgResp.set_user_id(nUserId);
    for(auto it=lsContactList.begin(); it!=lsContactList.end(); ++it)
    {
      IM::BaseDefine::ContactSessionInfo* pContact = msgResp.add_contact_session_list();
      //*pContact = *it;
      pContact->set_session_id(it->session_id());
      pContact->set_session_type(it->session_type());
      pContact->set_session_status(it->session_status());
      pContact->set_updated_time(it->updated_time());
      pContact->set_latest_msg_id(it->latest_msg_id());
      pContact->set_latest_msg_data(it->latest_msg_data());
      pContact->set_latest_msg_type(it->latest_msg_type());
      pContact->set_latest_msg_from_user_id(it->latest_msg_from_user_id());
    }

    log("userId=%u, last_time=%u, count=%u", nUserId, nLastTime, msgResp.contact_session_list_size());

    msgResp.set_attach_data(msg.attach_data());
    pPduResp->SetPBMsg(&msgResp);
    pPduResp->SetSeqNum(pPdu->GetSeqNum());
    pPduResp->SetServiceId(IM::BaseDefine::SID_BUDDY_LIST);
    pPduResp->SetCommandId(IM::BaseDefine::CID_BUDDY_LIST_RECENT_CONTACT_SESSION_RESPONSE);
    CProxyConn::AddResponsePdu(conn_uuid, pPduResp);
  }
  else
  {
    log("parse pb failed");
  }
}

/**
 *  删除会话接口(单个会话)
 *
 *  @param pPdu      收到的packet包指针
 *  @param conn_uuid 该包过来的socket 描述符
 */
void deleteRecentSession(CImPdu* pPdu, uint32_t conn_uuid)
{
  IM::Buddy::IMRemoveSessionReq msg;
  IM::Buddy::IMRemoveSessionRsp msgResp;

  if(msg.ParseFromArray(pPdu->GetBodyData(), pPdu->GetBodyLength()))
  {
    CImPdu* pPduResp = new CImPdu;

    uint32_t nUserId = msg.user_id();
    uint32_t nPeerId = msg.session_id();
    IM::BaseDefine::SessionType nType = msg.session_type();
    if(IM::BaseDefine::SessionType_IsValid(nType))
    {
      bool bRet = false;
      uint32_t nSessionId = CSessionModel::getInstance()->getSessionId(nUserId, nPeerId, nType, false);
      if (nSessionId != INVALID_VALUE) {
        bRet = CSessionModel::getInstance()->removeSession(nSessionId);
        // if remove session success, we need to clear the unread msg count
        if (bRet)
        {
          //删除用户聊天记录
          CUserModel::getInstance()->clearUserCounter(nUserId, nPeerId, nType);
        }
      }
      log("userId=%d, peerId=%d, result=%s", nUserId, nPeerId, bRet?"success":"failed");

      msgResp.set_attach_data(msg.attach_data());
      msgResp.set_user_id(nUserId);
      msgResp.set_session_id(nPeerId);
      msgResp.set_session_type(nType);
      msgResp.set_result_code(bRet?0:1);
      pPduResp->SetPBMsg(&msgResp);
      pPduResp->SetSeqNum(pPdu->GetSeqNum());
      pPduResp->SetServiceId(IM::BaseDefine::SID_BUDDY_LIST);
      pPduResp->SetCommandId(IM::BaseDefine::CID_BUDDY_LIST_REMOVE_SESSION_RES);
      CProxyConn::AddResponsePdu(conn_uuid, pPduResp);
    }
    else
    {
      log("invalied session_type. userId=%u, peerId=%u, seseionType=%u", nUserId, nPeerId, nType);
    }
  }
  else{
    log("parse pb failed");
  }
}

};

/* db_proxy_server - business - RelationModel.h */
#ifndef RELATION_SHIP_H_
#define RELATION_SHIP_H_

#include <list>

#include "util.h"
#include "ImPduBase.h"
#include "IM.BaseDefine.pb.h"

using namespace std;

/* getRelationId 获取会话关系id. (即用户与用户之间的会话关系, 用户与群组之间的会话关系)
 * updateRelation 更新会话时间.
 * removeRelation 删除会话.
 * addRelation 增加会话关系id.
 */
class CRelationModel {
public:
  virtual ~CRelationModel();

  static CRelationModel* getInstance();
  uint32_t getRelationId(uint32_t nUserAId, uint32_t nUserBId, bool bAdd);
  bool updateRelation(uint32_t nRelationId, uint32_t nUpdateTime);
  bool removeRelation(uint32_t nRelationId);

private:
  CRelationModel();
  uint32_t addRelation(uint32_t nSmallId, uint32_t nBigId);

private:
  static CRelationModel*	m_pInstance;
};

#endif

/* db_proxy_server - business - RelationModel.h */
#include <vector>
#include "../DBPool.h"
#include "RelationModel.h"
#include "MessageModel.h"
#include "GroupMessageModel.h"
using namespace std;

CRelationModel* CRelationModel::m_pInstance = NULL;

CRelationModel::CRelationModel()
{

}

CRelationModel::~CRelationModel()
{

}

CRelationModel* CRelationModel::getInstance()
{
  if (!m_pInstance) {
    m_pInstance = new CRelationModel();
  }

  return m_pInstance;
}

/* 获取会话关系id. (即用户与用户之间的会话关系, 用户与群组之间的会话关系)
 * 如果查询不到该id, 则说明该会话关系是新增的,调用addRelation添加该会话记录
 */
uint32_t CRelationModel::getRelationId(uint32_t nUserAId, uint32_t nUserBId, bool bAdd)
{
  uint32_t nRelationId = INVALID_VALUE;
  if (nUserAId == 0 || nUserBId == 0) {
    log("invalied user id:%u->%u", nUserAId, nUserBId);
    return nRelationId;
  }
  CDBManager* pDBManager = CDBManager::getInstance();
  CDBConn* pDBConn = pDBManager->GetDBConn("teamtalk_slave");
  if (pDBConn)
  {
    uint32_t nBigId = nUserAId > nUserBId ? nUserAId : nUserBId;
    uint32_t nSmallId = nUserAId > nUserBId ? nUserBId : nUserAId;
    string strSql = "select id from IMRelationShip where smallId=" + int2string(nSmallId) + " and bigId="+ int2string(nBigId) + " and status = 0";

    CResultSet* pResultSet = pDBConn->ExecuteQuery(strSql.c_str());
    if (pResultSet)
    {
      while (pResultSet->Next())
      {
        nRelationId = pResultSet->GetInt("id");
      }
      delete pResultSet;
    }
    else
    {
      log("there is no result for sql:%s", strSql.c_str());
    }
    pDBManager->RelDBConn(pDBConn);
    if (nRelationId == INVALID_VALUE && bAdd)
    {
      nRelationId = addRelation(nSmallId, nBigId);
    }
  }
  else
  {
    log("no db connection for teamtalk_slave");
  }
  return nRelationId;
}

/* 增加会话关系id.
 * 如果sql语句能查询到该会话id记录,则更新该记录status状态
 * 否则插入一条新记录,表示增加新的会话关系记录.
 */
uint32_t CRelationModel::addRelation(uint32_t nSmallId, uint32_t nBigId)
{
  uint32_t nRelationId = INVALID_VALUE;
  CDBManager* pDBManager = CDBManager::getInstance();
  CDBConn* pDBConn = pDBManager->GetDBConn("teamtalk_master");
  if (pDBConn)
  {
    uint32_t nTimeNow = (uint32_t)time(NULL);
    string strSql = "select id from IMRelationShip where smallId=" + int2string(nSmallId) + " and bigId="+ int2string(nBigId);
    CResultSet* pResultSet = pDBConn->ExecuteQuery(strSql.c_str());
    if(pResultSet && pResultSet->Next())
    {
      nRelationId = pResultSet->GetInt("id");
      strSql = "update IMRelationShip set status=0, updated=" + int2string(nTimeNow) + " where id=" + int2string(nRelationId);
      bool bRet = pDBConn->ExecuteUpdate(strSql.c_str());
      if(!bRet)
      {
        nRelationId = INVALID_VALUE;
      }
      log("has relation ship set status");
      delete pResultSet;
    }
    else
    {
      strSql = "insert into IMRelationShip (`smallId`,`bigId`,`status`,`created`,`updated`) values(?,?,?,?,?)";
      // 必须在释放连接前delete CPrepareStatement对象，否则有可能多个线程操作mysql对象，会crash
      CPrepareStatement* stmt = new CPrepareStatement();
      if (stmt->Init(pDBConn->GetMysql(), strSql))
      {
        uint32_t nStatus = 0;
        uint32_t index = 0;
        stmt->SetParam(index++, nSmallId);
        stmt->SetParam(index++, nBigId);
        stmt->SetParam(index++, nStatus);
        stmt->SetParam(index++, nTimeNow);
        stmt->SetParam(index++, nTimeNow);
        bool bRet = stmt->ExecuteUpdate();
        if (bRet)
        {
          nRelationId = pDBConn->GetInsertId();
        }
        else
        {
          log("insert message failed. %s", strSql.c_str());
        }
      }
      if(nRelationId != INVALID_VALUE)
      {
        // 初始化msgId
        if(!CMessageModel::getInstance()->resetMsgId(nRelationId))
        {
          log("reset msgId failed. smallId=%u, bigId=%u.", nSmallId, nBigId);
        }
      }
      delete stmt;
    }
    pDBManager->RelDBConn(pDBConn);
  }
  else
  {
    log("no db connection for teamtalk_master");
  }
  return nRelationId;
}
  
/* 更新会话时间.*/
bool CRelationModel::updateRelation(uint32_t nRelationId, uint32_t nUpdateTime)
{
  bool bRet = false;
  CDBManager* pDBManager = CDBManager::getInstance();
  CDBConn* pDBConn = pDBManager->GetDBConn("teamtalk_master");
  if (pDBConn)
  {
    string strSql = "update IMRelationShip set `updated`="+int2string(nUpdateTime) + " where id="+int2string(nRelationId);
    bRet = pDBConn->ExecuteUpdate(strSql.c_str());
    pDBManager->RelDBConn(pDBConn);
  }
  else
  {
    log("no db connection for teamtalk_master");
  }
  return bRet;
}

/* 删除会话. 更新会话关系id的状态 */
bool CRelationModel::removeRelation(uint32_t nRelationId)
{
  bool bRet = false;
  CDBManager* pDBManager = CDBManager::getInstance();
  CDBConn* pDBConn = pDBManager->GetDBConn("teamtalk_master");
  if (pDBConn)
  {
    uint32_t nNow = (uint32_t) time(NULL);
    string strSql = "update IMRelationShip set status = 1, updated="+int2string(nNow)+" where id=" + int2string(nRelationId);
    bRet = pDBConn->ExecuteUpdate(strSql.c_str());
    pDBManager->RelDBConn(pDBConn);
  }
  else
  {
    log("no db connection for teamtalk_master");
  }
  return bRet;
}

