
#include <nginx.h>
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include <ctype.h>
#include <assert.h>

#include "ngx_http_extended_status_module.h"

extern  ngx_uint_t  ngx_num_workers;

static char  * ngx_http_set_status(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

static ngx_command_t  ngx_http_status_commands[] = {

    { ngx_string("extended_status"),
      NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_http_set_status,
      0,
      0,
      NULL },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_extended_status_module_ctx = {
    NULL,                                  /* preconfiguration */
    NULL,                                  /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    NULL,                                  /* create location configuration */
    NULL                                   /* merge location configuration */
};


ngx_module_t  ngx_http_extended_status_module = {
    NGX_MODULE_V1,
    &ngx_http_extended_status_module_ctx,      /* module context */
    ngx_http_status_commands,              /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_int_t  
get_int_from_query(ngx_http_request_t *r, char *name, size_t len)
{
    ngx_str_t   val;

    if (ngx_http_arg(r, (u_char *) name, len, &val) == NGX_OK) {
        if (val.len == 0)
            return -1;
        
        return ngx_atoi(val.data, val.len);
    }
    else
        return -1;
}


static char *  
sortingColumns(ngx_http_request_t *r)
{
    u_char  *p, *last;
    u_char  *data;
    char  *colnum, *current;
    ngx_uint_t  len;
    ngx_int_t   colcnt = 0;

    if (r->args.len == 0) {
        return "9r-10r";  /* default */
    }
    
    colnum = current = ngx_pcalloc(r->pool, 8);
    if (colnum == NULL) {
        return "9r-10r";
    }

    p = r->args.data;
    last = p + r->args.len;
    len = 4;  /* 4 = sizeof("sort") - 1  */

    for ( /* void */ ; p < last; p++) {

        p = ngx_strlcasestrn(p, last - 1, (u_char *)"sort", len - 1);

        if (p == NULL) {
            return "9r-10r"; 
        }

        if ((p == r->args.data || *(p - 1) == '&') && *(p + len) == '=') {

            data = p + len + 1;

            p = ngx_strlchr(p, last, '&');

            if (p == NULL) {
                p = r->args.data + r->args.len;
            }    

            /*
              3: Maximum size of a column number (ex. 1, 3r 10r)
              8: Maximum size of two column numbers + 1(for NULL) (ex. 1-2, 7r-3, 10r-11r)
             */
            if (p - data <= 3 && (p - data + 1) < (8 - (current - colnum)))  {
               
                if (colnum != current) {
                    *current++ = '-' ;
                    colcnt += 1;
                }
                else
                    colcnt = 1 ;

                ngx_memcpy(current, data, p - data);
                current += p - data;
            }
        }
        if (2 <= colcnt)
            break;
    }
    
    if (colnum == current)
        return "9r-10r";
    else
        return colnum;
}


/* coped from ngx_http_gzip_ratio_variable()@ngx_http_gzip_filter_module.c  */
static  float
get_gzip_ratio(size_t zin, size_t zout)
{
    ngx_uint_t  zint, zfrac;
    float       ratio = 0.0;

    if (zin == 0 || zout == 0)
        return ratio;

    zint = (ngx_uint_t) (zin / zout);
    zfrac = (ngx_uint_t) ((zin * 100 / zout) % 100);
    
    if ((zin * 1000 / zout) % 10 > 4) {
        zfrac++;

	if (zfrac > 99)	{
	    zint++;
	    zfrac = 0;
	}
    }

    ratio = zint + ((float) zfrac / 100.0);

    return ratio;
}


static ngx_int_t  
how_long_ago_used(time_t  last_sec)
{
    ngx_time_t  *tp;
    ngx_int_t    sec;

    tp = ngx_timeofday();
    sec = tp->sec - last_sec;
    sec = sec < 0 ? 0 : sec;

    return sec;
}


static ngx_int_t  
set_refresh_header_field(ngx_http_request_t  *r)
{
    ngx_int_t  refresh;

    refresh = get_int_from_query(r, "refresh", 7);

    if (MIN_REFRESH_VALUE < refresh && refresh <= MAX_REFRESH_VALUE) {
        ngx_table_elt_t  *h;
	u_char           *refresh_value;

	h = ngx_list_push(&r->headers_out.headers);
	if (NULL == h)
	    return NGX_HTTP_INTERNAL_SERVER_ERROR;
	refresh_value = ngx_pnalloc(r->pool, 32);
	if (refresh_value == NULL) 
	    return NGX_HTTP_INTERNAL_SERVER_ERROR;
	else
	    memset(refresh_value, 0, 32);

	h->hash = 1;
	h->key.len = sizeof("Refresh") - 1;
	h->key.data = (u_char *) "Refresh";
	ngx_sprintf(refresh_value, "%d", refresh);
	h->value.data = refresh_value;
	h->value.len = strlen((const char *) h->value.data);
	    
	r->headers_out.refresh = h;
    }

    return 0;
}


static u_char  *
get_hostname(ngx_http_request_t  *r)
{
    u_char  *hostname = NULL;

    hostname = ngx_pnalloc(r->pool, ngx_cycle->hostname.len + 1);
    if (hostname == NULL)
        return NULL;

    ngx_cpystrn(hostname, ngx_cycle->hostname.data, ngx_cycle->hostname.len + 1);  

    return hostname;
}


static ngx_chain_t *
put_header(ngx_http_request_t  *r)
{
    ngx_chain_t  *c;
    ngx_buf_t  *b;

    b = ngx_create_temp_buf(r->pool, sizeof(HTML_HEADER));
    if (b == NULL) 
        return NULL;
    c = ngx_pcalloc(r->pool, sizeof(ngx_chain_t));
    if (c == NULL) 
        return NULL;

    b->last = ngx_sprintf(b->last, HTML_HEADER);
    c->buf = b;
    c->next = NULL;

    return c;
}


static ngx_chain_t *
put_server_info(ngx_http_request_t  *r)
{
    ngx_chain_t  *c;
    ngx_buf_t  *b;
    u_char  *hostname; 
    size_t  size ;

    size = sizeof(SERVER_INFO) + ngx_cycle->hostname.len + sizeof(NGINX_VERSION) + sizeof("<hr /><br>");
    b = ngx_create_temp_buf(r->pool, size);
    if (b == NULL) 
        return NULL;
    c = ngx_pcalloc(r->pool, sizeof(ngx_chain_t));
    if (c == NULL) 
        return NULL;

    hostname = get_hostname(r);
    if (hostname == NULL)
        return NULL;

    b->last = ngx_sprintf(b->last, SERVER_INFO, hostname, NGINX_VERSION);
    b->last = ngx_sprintf(b->last, "<hr /><br>"); 

    c->buf = b;
    c->next = NULL;

    return c;
}


static ngx_chain_t *
put_basic_status(ngx_http_request_t  *r)
{
    ngx_chain_t  *c;
    ngx_buf_t  *b;
    ngx_atomic_int_t  ap, hn, ac, rq, rd, wr;
    size_t  size;

    ap = *ngx_stat_accepted;
    hn = *ngx_stat_handled;
    ac = *ngx_stat_active;
    rq = *ngx_stat_requests;
    rd = *ngx_stat_reading;
    wr = *ngx_stat_writing;

    size = sizeof("<b>Active connections: %uA </b>\n<br><br>\n") + NGX_ATOMIC_T_LEN;
    size += sizeof("<table border=0><tr><th>server accepts</th><th>handled</th><th>requests</th></tr>\n");
    size += sizeof("<tr align=right><td> %uA </td><td> %uA </td><td> %uA </td></tr></table><br>\n") + NGX_ATOMIC_T_LEN * 3;
    size += sizeof("<table border=0><tr><th>Reading:</th><td> %uA </td><th>Writing:</th><td> %uA </td><th>Waiting:</th><td> %uA </td></tr></table>\n") 
        + NGX_ATOMIC_T_LEN * 3;
	
    b = ngx_create_temp_buf(r->pool, size);
    if (b == NULL) 
        return NULL;
    c = ngx_pcalloc(r->pool, sizeof(ngx_chain_t));
    if (c == NULL) 
        return NULL;

    b->last = ngx_sprintf(b->last, "<b>Active connections: %uA </b>\n<br><br>\n", ac);
    b->last = ngx_sprintf(b->last, "<table border=0><tr><th>server accepts</th><th>handled</th><th>requests</th></tr>\n");
    b->last = ngx_sprintf(b->last, "<tr align=right><td> %uA </td><td> %uA </td><td> %uA </td></tr></table><br>\n", ap, hn, rq);
    b->last = ngx_sprintf(b->last, "<table border=0><tr><th>Reading:</th><td> %uA </td><th>Writing:</th><td> %uA </td><th>Waiting:</th><td> %uA </td></tr></table>\n", 
                          rd, wr, ac - (rd + wr));
    c->buf = b;
    c->next = NULL;
    
    return c;
}


static inline ngx_uint_t
dec_qps_index(ngx_uint_t index)
{
    return index == 0 ? RECENT_PERIOD - 1 : index - 1;
}


static ngx_chain_t *
put_worker_status(ngx_http_request_t *r)
{
    worker_score  *ws;
    ngx_time_t    *tp;
    ngx_chain_t   *c;
    ngx_buf_t     *b;
    uint32_t       query_cnt_1 = 0;
    uint32_t       query_cnt_2 = 0;
    uint32_t       current;
    uint32_t       past;
    uint32_t       index;
    uint32_t       tmp_idx;
    uint32_t       hz = sysconf(_SC_CLK_TCK);
    uint32_t       i, j;
    size_t  size;
    size_t  sizePerWorker;

    if (PERIOD_L <= PERIOD_S || RECENT_PERIOD <= PERIOD_L)
        return NGX_OK;

    tp = ngx_timeofday();
    current = (uint32_t) tp->sec;
    current -= 1;
    index = current & RECENT_MASK;

    size = sizeof(WORKER_TABLE_HEADER);

    sizePerWorker = sizeof("<tr><td align=center>%4d</td>") + 4;
    sizePerWorker += sizeof("<td> %5d </td>") + 5; /* size of /proc/sys/kernel/pid_max */
    sizePerWorker += sizeof("<td align=right> %d </td>") + NGX_INT64_LEN;
    sizePerWorker += sizeof("<td align=center><b> %c </b></td>");
    sizePerWorker += sizeof("<td> %.2f </td>") + 5; 
    sizePerWorker += sizeof("<td align=right> %.2f </td></tr>") + NGX_INT64_LEN; 

    size += sizePerWorker * ngx_num_workers;
    size += sizeof("</table>\n<br><br>");
    size += sizeof("<b>Requests/sec: %.02f (last %2d seconds), %.02f (last %2d seconds) &nbsp; &nbsp; at %s</b><br>");
    size += 7 + 2 + 7 + 2;
    size += sizeof(CURRENT_TIME);
        
    b = ngx_create_temp_buf(r->pool, size);
    if (b == NULL) 
        return NULL;

    c = ngx_pcalloc(r->pool, sizeof(ngx_chain_t));
    if (c == NULL) 
        return NULL;

    b->last = ngx_sprintf(b->last, WORKER_TABLE_HEADER);
    for (i = 0; i < ngx_num_workers; i++) {
	ws = (worker_score *) ((char *)workers + WORKER_SCORE_LEN * i);

	b->last = ngx_sprintf(b->last, "<tr><td align=center>%4d</td>", i);	
	b->last = ngx_sprintf(b->last, "<td> %5d </td>", ws->pid);    
	b->last = ngx_sprintf(b->last, "<td align=right> %d </td>", ws->access_count);
	b->last = ngx_sprintf(b->last, "<td align=center><b> %c </b></td>", ws->mode);    
	b->last = ngx_sprintf(b->last, "<td> %.2f </td>",   
                              (ws->times.tms_utime + ws->times.tms_stime + 
                               ws->times.tms_cutime + ws->times.tms_cstime) / (float) hz);
	b->last = ngx_sprintf(b->last, "<td align=right> %.2f </td></tr>", (float) ws->bytes_sent / MBYTE);

	tmp_idx = index;
	past = current;
	for (j = 0; j < PERIOD_L; j++) {
	    if (past == ws->recent_request_cnt [tmp_idx].time) {
	        query_cnt_2 += ws->recent_request_cnt [tmp_idx].cnt;
		if (j < PERIOD_S)
		    query_cnt_1 += ws->recent_request_cnt [tmp_idx].cnt;
	    }

	    tmp_idx = dec_qps_index(tmp_idx);	    
	    past -= 1;
	}
    }
    b->last = ngx_sprintf(b->last, "</table>\n<br><br>");	    
    b->last = ngx_sprintf(b->last, "<b>Requests/sec: %.02f (last %2d seconds), %.02f (last %2d seconds) &nbsp; &nbsp; at %s</b><br>", 
                          (float)query_cnt_1 / (float)PERIOD_S, PERIOD_S, 
                          (float)query_cnt_2 / (float)PERIOD_L, PERIOD_L, 
                          CURRENT_TIME);
    c->buf = b;
    c->next = NULL;

    return c;
}


static ngx_chain_t *
put_connection_status(ngx_http_request_t *r)
{
    ngx_msec_int_t  response_time;	
    conn_score     *cs;
    ngx_uint_t      i, j, k;
    int             active;
    ngx_chain_t   *c, *c1, *c2;
    ngx_buf_t     *b;
    size_t   sizePerConn;
    size_t   sizePerWorker;

    response_time = get_int_from_query(r, "res", 3);
    if (response_time < 0)
        response_time = DEFAULT_REQ_VALUE;
    active = get_int_from_query(r, "active", 6);
    

    sizePerConn = sizeof("<tr><td align=center>%4d-%04d</td>") + 4 + 4;
    sizePerConn += sizeof("<td align=right> %d </td>") + NGX_INT64_LEN;
    sizePerConn += sizeof("<td align=center><b>%c</b></td>");
    sizePerConn += sizeof("<td align=right> %d </td>") + NGX_INT64_LEN;
    sizePerConn += sizeof("<td> %s </td>") + SCORE__CLIENT_LEN;
    sizePerConn += sizeof("<td> %s </td>") + SCORE__VHOST_LEN;
    sizePerConn += sizeof("<td align=right> %.02f </td>") + 5;
    sizePerConn += sizeof("<td align=right> %d </td>") + NGX_INT64_LEN;
    sizePerConn += sizeof("<td align=right> %ui </td>") + 3;
    sizePerConn += sizeof("<td align=right> %d </td>") + NGX_INT64_LEN;
    sizePerConn += sizeof("<td align=right> %d </td>") + NGX_INT64_LEN;  
    sizePerConn += sizeof("<td> %s </td></tr>") + SCORE__REQUEST_LEN;
    sizePerWorker = sizePerConn * ngx_cycle->connection_n;
       
    /* 7 = sizeof("10r-10r") - 1 */
    b = ngx_create_temp_buf(r->pool, sizeof(CONNECTION_TABLE_HEADER) + 7 + sizePerWorker);  
    if (b == NULL) 
        return NULL;
    c = c1 = ngx_pcalloc(r->pool, sizeof(ngx_chain_t));
    if (c == NULL) 
        return NULL;

    c->buf = b;
    c->next = NULL;

    b->last = ngx_sprintf(b->last, CONNECTION_TABLE_HEADER, sortingColumns(r));
    for (i = 0; i < ngx_num_workers; i++) {
        for ( j = 0 ; j < ngx_cycle->connection_n ; j++ ) {
	    k = i * ngx_cycle->connection_n + j ;
	    cs = (conn_score *) ((char *)conns + sizeof(conn_score) * k);

	    if (cs->response_time < response_time || 
                '\0' ==  cs->client [0] || 
                '\0' == cs->request [0] || 
                '\0' == cs->vhost [0])
	        continue;
	    if (0 < active && 0 == cs->active)
	        continue;

	    b->last = ngx_sprintf(b->last, "<tr><td align=center>%4d-%04d</td>", i, j);
	    
	    b->last = ngx_sprintf(b->last, "<td align=right> %d </td>", cs->access_count);
	    b->last = ngx_sprintf(b->last, "<td align=center><b>%c</b></td>", cs->mode);	    
	    b->last = ngx_sprintf(b->last, "<td align=right> %d </td>", cs->bytes_sent);
	    
	    b->last = ngx_sprintf(b->last, "<td> %s </td>", cs->client);
	    b->last = ngx_sprintf(b->last, "<td> %s </td>", cs->vhost);
	
	    if (0 != cs->zin && 0 != cs->zout)
	        b->last = ngx_sprintf(b->last, "<td align=right> %.02f </td>", get_gzip_ratio(cs->zin, cs->zout));
	    else
	        b->last = ngx_sprintf(b->last, "<td align=center> - </td>");

	    b->last = ngx_sprintf(b->last, "<td align=right> %d </td>", how_long_ago_used(cs->last_used));
	    b->last = ngx_sprintf(b->last, "<td align=right> %ui </td>", cs->status);

	    b->last = ngx_sprintf(b->last, "<td align=right> %d </td>", cs->response_time);

	    if (0 <= cs->upstream_response_time)
	        b->last = ngx_sprintf(b->last, "<td align=right> %d </td>", cs->upstream_response_time);	
	    else
	        b->last = ngx_sprintf(b->last, "<td align=center><b>-</b></td>");	

	    b->last = ngx_sprintf(b->last, "<td> %s </td></tr>", cs->request);
	}
        
        if (i + 1 < ngx_num_workers)
            b = ngx_create_temp_buf(r->pool, sizePerWorker);
        else
            b = ngx_create_temp_buf(r->pool, sizeof("</tbody></table><hr /><br>\n"));
        if (b == NULL) 
            return NULL;
        c2 = ngx_pcalloc(r->pool, sizeof(ngx_chain_t));
        if (c2 == NULL) 
            return NULL;

        c2->buf = b;
        c2->next = NULL;
        c1->next = c2;
        c1 = c2;
    }

    b->last = ngx_sprintf(b->last, "</tbody></table><hr /><br>\n");

    return c;
}


static ngx_chain_t  *
put_footer(ngx_http_request_t *r)
{
    ngx_chain_t  *c;
    ngx_buf_t  *b;
    size_t  size;

    size = sizeof(SHORTENED_TABLE);
    size += sizeof("<hr />");
    size += sizeof(MODE_LIST);
    size += sizeof(HTML_TAIL);
    
    b = ngx_create_temp_buf(r->pool, size);
    if (b == NULL) 
        return NULL;
    c = ngx_pcalloc(r->pool, sizeof(ngx_chain_t));
    if (c == NULL) 
        return NULL;

    b->last = ngx_sprintf(b->last, SHORTENED_TABLE);
    b->last = ngx_sprintf(b->last, "<hr />");
    b->last = ngx_sprintf(b->last, MODE_LIST);

    b->last = ngx_sprintf(b->last, HTML_TAIL);

    c->buf = b ;
    c->next = NULL;

    return c;
} 


static inline ngx_chain_t *
get_lastChain( ngx_chain_t  *c)
{
    ngx_chain_t  *last = c;

    assert(last != NULL);

    while ( last->next != NULL )
        last = last->next;

    return last;
}


static inline off_t
get_contentLength(ngx_chain_t  *c)
{
    off_t  l = 0;

    while (c != NULL) {
        l += ngx_buf_size(c->buf);
        c = c->next;
    }
    
    return l;
}


static ngx_int_t 
ngx_http_status_handler(ngx_http_request_t *r)
{
    ngx_chain_t  *fc, *mc, *lc;
    ngx_int_t    rc;

    if (NGX_HTTP_GET != r->method)
        return NGX_HTTP_NOT_ALLOWED;

    rc = ngx_http_discard_request_body(r);
    if (rc != NGX_OK) 
        return rc;

    r->headers_out.content_type.len  = sizeof( "text/html; charset=ISO-8859-1" ) - 1;
    r->headers_out.content_type.data = (u_char *) "text/html; charset=ISO-8859-1";

    rc = set_refresh_header_field(r);
    if ( rc != NGX_OK)
        return rc;

    fc = put_header(r);
    if (fc == NULL)
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    lc = get_lastChain(fc);

    mc = put_server_info(r);
    if (mc == NULL)
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    lc->next = mc;
    lc = get_lastChain(mc);

    mc = put_basic_status(r);
    if (mc == NULL)
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    lc->next = mc;
    lc = get_lastChain(mc);

    mc = put_worker_status(r);
    if (mc == NULL)
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    lc->next = mc;
    lc = get_lastChain(mc);

    mc = put_connection_status(r);
    if (mc == NULL)
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    lc->next = mc;
    lc = get_lastChain(mc);

    mc = put_footer(r);
    if (mc == NULL)
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    lc->next = mc;
    lc = get_lastChain(mc);

    lc->buf->last_buf = 1;

    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_length_n = get_contentLength(fc);

    rc = ngx_http_send_header(r);
    if (NGX_ERROR == rc || NGX_OK < rc || r->header_only) 
        return rc;

    return ngx_http_output_filter(r, fc);
}


static char *
ngx_http_set_status(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_core_loc_conf_t  *clcf;

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_http_status_handler;

    return NGX_CONF_OK;
}
