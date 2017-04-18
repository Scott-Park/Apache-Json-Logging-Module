#include "httpd.h"
#include "http_connection.h"
#include "http_config.h"
#include "http_core.h"
#include "http_log.h"
#include "http_request.h"

#include <time.h>
#include <jansson.h>

#define DEFAULT_MAX_SIZE 1024
#define MIN(a,b) (a)<(b)?(a):(b)

typedef struct mod_json_conf_t {
  apr_pool_t         *pool;
  apr_size_t         max_size;
  apr_array_header_t *secure;
  const char         *log_file;
} mod_json_conf_t;

typedef struct {
  apr_pool_t *pool;
  char       *req_buf;
  apr_file_t *log_fd;
} mod_json_log_t;

/* Define module name */
module AP_MODULE_DECLARE_DATA mod_json_module;

apr_status_t logdata(ap_filter_t *f, char *json_str, apr_size_t jstr_len)
{
  mod_json_log_t *mplog = f->ctx;

  apr_size_t wbytes;
  char *p;
  char *logLine = apr_pcalloc(f->r->pool, jstr_len+1);
  p = logLine;
  p = memcpy(p, json_str, jstr_len) + jstr_len;
  *p++ = '\n';

  apr_status_t rc = apr_file_write_full(mplog->log_fd, logLine, jstr_len+1, &wbytes);

  if(rc != APR_SUCCESS) {
    logLine = NULL;
    apr_file_flush(mplog->log_fd);
    apr_file_close(mplog->log_fd);
    p = NULL;
    logLine = NULL;

    return rc;
  }

  apr_file_flush(mplog->log_fd);
  apr_file_close(mplog->log_fd);
  p = NULL;
  logLine = NULL;

  return APR_SUCCESS;
}

static void dumpit(request_rec *r, apr_bucket *b, char *buf, apr_size_t *current_size) {

  mod_json_conf_t *mpcf = (mod_json_conf_t *)ap_get_module_config(r->per_dir_config, &mod_json_module);

    if (*current_size < mpcf->max_size && !(APR_BUCKET_IS_METADATA(b))) {
        const char * ibuf;
        apr_size_t nbytes;
        if (apr_bucket_read(b, &ibuf, &nbytes, APR_BLOCK_READ) == APR_SUCCESS) {
            if (nbytes) {
                nbytes = MIN(nbytes, mpcf->max_size - *current_size);
                strncpy(buf, ibuf, nbytes);
                *current_size += nbytes;
            }
        }
    }
    else {
        if (APR_BUCKET_IS_EOS(b)) {
          return;
        }
    }

}

static
apr_status_t mod_json_input_filter(ap_filter_t *f, apr_bucket_brigade *bb,
  ap_input_mode_t mode, apr_read_type_e block, apr_off_t readbytes)
{
  mod_json_conf_t *mpcf = (mod_json_conf_t *)ap_get_module_config(f->r->per_dir_config, &mod_json_module);
  mod_json_log_t *mplog = f->ctx;

  const apr_array_header_t    *fields;
  int                         i;
  apr_table_entry_t           *e = 0;
  char                        req_time[APR_CTIME_LEN];
  apr_bucket                  *b;
  apr_status_t                ret;
  apr_size_t                  buf_len = 0;
  apr_status_t                status;
  char                        *q;

  json_t *j_obj = json_object();

  if(mplog == NULL){
    /* Create mod_json_log_context */
    apr_pool_t *pool;
    if((status = apr_pool_create(&pool, f->r->pool)) != APR_SUCCESS){
      return status;
    }

    f->ctx = mplog = (mod_json_log_t *)apr_pcalloc(pool, sizeof(mod_json_log_t));
    mplog->pool = pool;
    mplog->req_buf = apr_pcalloc(mplog->pool, mpcf->max_size + 1);
    mplog->log_fd = NULL;

    /* open log file */
    if(mpcf->log_file != NULL){
      /* get current date */
      char date_buf[12] = {0,};
      time_t t = time(NULL);
      struct tm *tm_today = localtime(&t);
      strftime(date_buf, 11, "%Y-%m-%d", tm_today);
      apr_size_t file_len = strlen(date_buf) + strlen(mpcf->log_file);
      char *fileName = apr_pcalloc(f->r->pool, file_len+1);
      sprintf(fileName, "%s-%s", mpcf->log_file, date_buf);

      apr_status_t rc = apr_file_open(&mplog->log_fd,
        fileName,
        APR_FOPEN_CREATE | APR_FOPEN_WRITE | APR_FOPEN_APPEND,
        APR_OS_DEFAULT,
        mplog->pool);
    }
    else{
      /* if log_file is not setted, set default */
      return APR_SUCCESS;
    }

  }

  fields = apr_table_elts(f->r->headers_in);
  e = (apr_table_entry_t *) fields->elts;
  for(i = 0; i < fields->nelts; i++) {
    if(!e[i].key){
      continue;
    }
    json_object_set_new(j_obj, (char *)e[i].key, json_string((const char *)e[i].val));
  }

  #if AP_SERVER_MAJORVERSION_NUMBER > 1 && AP_SERVER_MINORVERSION_NUMBER > 2
        char *ip = f->r->connection->client_ip;
  #else
        char *ip = f->r->connection->remote_ip;
  #endif

  json_object_set_new(j_obj, "Remote-addr", json_string((const char *)ip));
  ap_recent_ctime(req_time, f->r->request_time);
  json_object_set_new(j_obj, "Request-date", json_string((const char *)req_time));
  json_object_set_new(j_obj, "Method", json_string((const char *)f->r->method));
  json_object_set_new(j_obj, "Uri", json_string((const char *)f->r->uri));
  json_object_set_new(j_obj, "Content-Type", json_string((const char *)f->r->content_type));
  json_object_set_new(j_obj, "Request", json_string((const char *)f->r->the_request));
  json_object_set_new(j_obj, "Server", json_string((const char *)"Apache"));

  if(f->r->status <= 0){
    json_object_set_new(j_obj, "Status", json_string((const char *)"-"));
  }
  else{
    json_object_set_new(j_obj, "Status", json_integer(f->r->status));
  }

  if ((ret = ap_get_brigade(f->next, bb, mode, block, readbytes)) != APR_SUCCESS)
      return ret;

  /* dump post data when method equal post */

  char *buf = mplog->req_buf;

    /* dump body */
  for (b = APR_BRIGADE_FIRST(bb); b != APR_BRIGADE_SENTINEL(bb); b = APR_BUCKET_NEXT(b)){
    if(buf_len < DEFAULT_MAX_SIZE){
      dumpit(f->r, b, buf + buf_len, &buf_len);
    }
  }

  if(apr_strnatcmp(f->r->method, (const char *)"POST") == 0) {
    /* conver astric */
    char **secs = (mpcf->secure->nelts > 0)?(char **)mpcf->secure->elts : NULL;
    if(secs != NULL) {
      for(i = 0; i < mpcf->secure->nelts; i++) {
        q = strstr(buf, secs[i]);
        if(q) {
          q += strlen(secs[i]);
          if(*q == '='){
            q += 1;
            while(q < buf + buf_len) {
              if(*q == '&') {
                break;
              }
              *q = '*';
              q++;
            }
          }
        }
      }
    }


    json_object_set_new(j_obj, "Post-body", json_string((const char *)mplog->req_buf));
  }

  char *json_str = json_dumps(j_obj, JSON_COMPACT);
  apr_size_t jstr_len = strlen(json_str);

  if(mplog->log_fd != NULL){
    logdata(f, json_str, jstr_len);
  }

  json_str = NULL;
  json_decref(j_obj);

  return APR_SUCCESS;
}

/* Initialize attributes */
static void *mod_json_init(apr_pool_t *pool, char *d)
{
  mod_json_conf_t *mpcf;

  mpcf = (mod_json_conf_t *)apr_pcalloc(pool, sizeof(mod_json_conf_t));
  mpcf->max_size = DEFAULT_MAX_SIZE;
  mpcf->secure = apr_array_make(pool, 0, sizeof(char *));
  mpcf->pool = pool;
  mpcf->log_file = "";

  return mpcf;
}

/* Adds a named filter into the filter chain on the specified request record */
static void mod_json_add_filter(request_rec *req)
{
  ap_add_input_filter("mod_json_IN", NULL, req, req->connection);
}

/* Create a hook in the request handler, so we get called when a request arrives */
static void mod_json_register_hooks(apr_pool_t *p)
{
  ap_hook_insert_filter(mod_json_add_filter, NULL, NULL, APR_HOOK_FIRST);
  ap_register_input_filter("mod_json_IN", mod_json_input_filter, NULL, AP_FTYPE_RESOURCE);
}


/* Save setted parameters to structure */
static const char *mod_json_set_secure(cmd_parms *cmd, void *conf, const char *arg)
{
  mod_json_conf_t *mpcf = (mod_json_conf_t *)conf;
  *(const char **)apr_array_push(mpcf->secure) = arg;

  return NULL;
}

static const char *mod_json_set_logpath(cmd_parms *cmd, void *conf, const char *arg)
{
  mod_json_conf_t *mpcf = (mod_json_conf_t *)conf;
  mpcf->log_file = (char *)arg;

  return NULL;
}

/* Define commands on the httpd.conf */
static const command_rec mod_json_cmds[] = {
  AP_INIT_ITERATE("mp_secure", mod_json_set_secure, NULL, RSRC_CONF, "Add parameters to hide"),
  AP_INIT_TAKE1("mp_log", mod_json_set_logpath, NULL, RSRC_CONF, "A file to log post data"),
  { NULL }
};

/* Initial module definition */
module AP_MODULE_DECLARE_DATA mod_json_module = {
  STANDARD20_MODULE_STUFF,
  mod_json_init,             /* create per-direction config structures */
  NULL,                       /* merge  per-direction config structures */
  NULL,                       /* create per-server config structures */
  NULL,                       /* merge  per-server config structures */
  mod_json_cmds,             /* table of config file commands       */
  mod_json_register_hooks    /* register hooks                      */
};
