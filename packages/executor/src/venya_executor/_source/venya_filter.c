/*
 * venya_filter.c — Venya Stage 1 output filtering (C extension).
 *
 * OpenSSL EVP SHA-256, requires libcrypto at runtime.
 *
 * Build:  python setup.py build_ext --inplace
 * Import: from venya_filter import filter_output, compute_detection_hashes
 */

#include <Python.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>

/* ========================================================================
 * SHA-256 — OpenSSL EVP interface
 * ======================================================================== */

/* Compute SHA-256 of data, return hex string (caller frees with PyMem_Free). */
static char* sha256_hex(const uint8_t *data, size_t len) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) return NULL;
    uint8_t digest[EVP_MAX_MD_SIZE];
    unsigned int digest_len = 0;
    
    if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1 ||
        EVP_DigestUpdate(ctx, data, len) != 1 ||
        EVP_DigestFinal_ex(ctx, digest, &digest_len) != 1) {
        EVP_MD_CTX_free(ctx);
        return NULL;
    }
    EVP_MD_CTX_free(ctx);
    
    char *hex = (char*)PyMem_Malloc(65);
    if (!hex) return NULL;
    static const char h[] = "0123456789abcdef";
    for (unsigned int i = 0; i < digest_len; i++) {
        hex[i*2] = h[digest[i] >> 4];
        hex[i*2+1] = h[digest[i] & 0xf];
    }
    hex[64] = '\0';
    return hex;
}

/* ========================================================================
 * FNV-1a hash (fast pre-filter)
 * ======================================================================== */

static uint32_t fnv1a_hash(const uint8_t *data, size_t len) {
    uint32_t h = 2166136261u;
    for (size_t i = 0; i < len; i++) {
        h ^= data[i];
        h *= 16777619u;
    }
    return h;
}

/* ========================================================================
 * Base64 encoding (RFC 4648)
 * ======================================================================== */

static char* b64_encode(const uint8_t *in, size_t len, size_t *out_len) {
    size_t n = 4*((len+2)/3)+1;
    char *o = (char*)malloc(n);
    if(!o){*out_len=0;return NULL;}
    size_t i=0,j=0;
    static const char T[]="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    for(;i+2<len;i+=3){
        o[j++]=T[in[i]>>2];o[j++]=T[((in[i]&3)<<4)|(in[i+1]>>4)];
        o[j++]=T[((in[i+1]&0xf)<<2)|(in[i+2]>>6)];o[j++]=T[in[i+2]&0x3f];
    }
    if(i<len){
        o[j++]=T[in[i]>>2];
        if(i+1<len){o[j++]=T[((in[i]&3)<<4)|(in[i+1]>>4)];o[j++]=T[((in[i+1]&0xf)<<2)];o[j++]='=';}
        else{o[j++]=T[(in[i]&3)<<4];o[j++]='=';o[j++]='=';}
    }
    o[j]='\0'; *out_len=j; return o;
}

/* ========================================================================
 * compute_detection_hashes
 * ======================================================================== */

static PyObject* py_compute_detection_hashes(PyObject *self, PyObject *args) {
    PyObject *py_secret;
    if(!PyArg_ParseTuple(args,"O",&py_secret)) return NULL;
    const char *buf; Py_ssize_t bl;
    if(PyBytes_AsStringAndSize(py_secret,(char**)&buf,&bl)<0) return NULL;

    PyObject *list = PyList_New(0);

    /* [0] raw */
    { char *h=sha256_hex((const uint8_t*)buf,(size_t)bl);
      if(!h) return NULL; PyList_Append(list,PyUnicode_FromString(h)); PyMem_Free(h); }

    /* [1] base64 */
    { size_t bl2; char *b64=b64_encode((const uint8_t*)buf,(size_t)bl,&bl2);
      if(b64){ char *h=sha256_hex((const uint8_t*)b64,bl2);
        if(h){PyList_Append(list,PyUnicode_FromString(h));PyMem_Free(h);} free(b64); }}

    /* [2] hex */
    { char *hx=(char*)malloc((size_t)bl*2+1);
      if(hx){ static const char h[]="0123456789abcdef";
        for(Py_ssize_t i=0;i<bl;i++){ uint8_t b=(uint8_t)buf[i]; hx[i*2]=h[b>>4]; hx[i*2+1]=h[b&0xf]; }
        hx[(size_t)bl*2]='\0';
        char *sh=sha256_hex((const uint8_t*)hx,(size_t)bl*2);
        if(sh){PyList_Append(list,PyUnicode_FromString(sh));PyMem_Free(sh);} free(hx); }}

    /* [3] trimmed */
    { const char *p=buf; Py_ssize_t s=0,e=bl;
      while(s<e&&(p[s]==' '||p[s]=='\t'||p[s]=='\n'||p[s]=='\r')) s++;
      while(e>s&&(p[e-1]==' '||p[e-1]=='\t'||p[e-1]=='\n'||p[e-1]=='\r')) e--;
      if(s>0||e<bl){ char *h=sha256_hex((const uint8_t*)(p+s),(size_t)(e-s));
        if(h){PyList_Append(list,PyUnicode_FromString(h));PyMem_Free(h);} }}

    return list;
}

/* ========================================================================
 * filter_output — core Stage 1 filter (pure C, no Python calls in hot loop)
 * ======================================================================== */

typedef struct { char key[64]; char sid[64]; } HashEntry;
typedef struct { char key[64]; char sid[64]; size_t len; } FLEntry;

typedef struct { uint32_t hash; size_t len; char sid[64]; size_t next; } FNVEntry;
typedef struct {
    uint32_t *buckets; FNVEntry *entries; size_t ne,nc;
} FNVTable;

/* First-byte pre-filter: byte_value → array of fnv.entry indices */
typedef struct {
    size_t *indices; size_t count,cap;
} ByteIndex;

typedef struct {
    HashEntry *ht; size_t hn,hc; FLEntry *fl; size_t fn,fc;
    FNVTable fnv; ByteIndex byte_idx[256];
} FS;

static FS* fs_new(void) {
    FS *f=calloc(1,sizeof(*f));
    f->hc=32; f->ht=calloc(f->hc,sizeof(HashEntry));
    f->fc=16; f->fl=calloc(f->fc,sizeof(FLEntry));
    f->fnv.nc=4096; f->fnv.buckets=calloc(f->fnv.nc,sizeof(uint32_t));
    f->fnv.ne=0; f->fnv.entries=calloc(f->fnv.nc,sizeof(FNVEntry));
    for(int i=0;i<256;i++){f->byte_idx[i].indices=NULL;f->byte_idx[i].count=0;f->byte_idx[i].cap=0;}
    return f;
}
static void fs_del(FS *f){
    if(!f)return;
    free(f->ht); free(f->fl);
    if(f->fnv.buckets) free(f->fnv.buckets);
    if(f->fnv.entries) free(f->fnv.entries);
    for(int i=0;i<256;i++){
        if(f->byte_idx[i].indices) free(f->byte_idx[i].indices);
    }
    free(f);
}

static int fnv_table_add(FS *f,const uint8_t *data,size_t len,const char *sid){
    uint32_t h=fnv1a_hash(data,len);
    /* Check for duplicate across ALL entries (maintain consistency with fs_add_f) */
    for(size_t i=0;i<f->fnv.ne;++i)
        if(f->fnv.entries[i].hash==h && f->fnv.entries[i].len==len) return 0;
    /* Validate capacity — prevent buffer overflow */
    if(f->fnv.ne >= f->fnv.nc) {
        PyErr_Format(PyExc_RuntimeError,
            "FNV table capacity exceeded (%zu entries, max %zu). "
            "Consider increasing buffer size or reducing secret count.",
            f->fnv.ne, f->fnv.nc);
        return -1;
    }
    /* Grow table if needed — REMOVED: pre-sized table never needs growth */
    /*
    if(f->fnv.ne>=f->fnv.nc){
        size_t n=f->fnv.nc*2;
        uint32_t *br=realloc(f->fnv.buckets,n*sizeof(uint32_t));
        FNVEntry *er=realloc(f->fnv.entries,n*sizeof(FNVEntry));
        if(!br||!er){free(br);free(er);return -1;}
        size_t old_nc = f->fnv.nc;
        f->fnv.buckets=br; f->fnv.entries=er; f->fnv.nc=n;
        memset(br + old_nc, 0, (n - old_nc) * sizeof(uint32_t));
    }
    */
    size_t idx=f->fnv.ne;
    f->fnv.entries[idx].hash=h;
    f->fnv.entries[idx].len=len;
    f->fnv.entries[idx].next=0;  /* Initialize chain pointer */
    memcpy(f->fnv.entries[idx].sid,sid,64);
    f->fnv.entries[idx].next=f->fnv.buckets[h%f->fnv.nc];
    f->fnv.buckets[h%f->fnv.nc]=(uint32_t)(idx+1);  /* 1-based index */
    f->fnv.ne++;
    /* Populate first-byte index */
    if(len>0){
        uint8_t b=data[0];
        ByteIndex *bi=&f->byte_idx[b];
        if(bi->count>=bi->cap){
            size_t n=bi->cap?bi->cap*2:16;
            size_t *ir=realloc(bi->indices,n*sizeof(size_t));
            if(!ir)return -1;
            bi->indices=ir; bi->cap=n;
        }
        bi->indices[bi->count++]=idx;
    }
    return 0;
}
static const FNVEntry* fnv_table_get(FS *f,const uint8_t *data,size_t len){
    uint32_t h=fnv1a_hash(data,len);
    size_t bucket=h%f->fnv.nc;
    size_t idx=f->fnv.buckets[bucket]-1;  /* Convert 1-based to 0-based */
    while(idx<f->fnv.ne){
        if(f->fnv.entries[idx].hash==h && f->fnv.entries[idx].len==len)
            return &f->fnv.entries[idx];
        idx=f->fnv.entries[idx].next-1;  /* Follow chain (convert 1-based to 0-based) */
        if(idx==(size_t)-1 || idx>=f->fnv.ne) break;  /* Safety check */
    }
    return NULL;
}

static int fs_add_h(FS *f,const char *k,const char *s){
    if(f->hn>=f->hc){size_t n=f->hc*2;HashEntry *r=realloc(f->ht,n*sizeof(HashEntry));
        if(!r)return -1;f->ht=r;f->hc=n;}
    memcpy(f->ht[f->hn].key,k,64);memcpy(f->ht[f->hn].sid,s,64);f->hn++;return 0;
}
static int fs_add_f(FS *f,const char *k,const char *s,size_t l){
    if(f->fn>=f->fc){size_t n=f->fc*2;FLEntry *r=realloc(f->fl,n*sizeof(FLEntry));
        if(!r)return -1;f->fl=r;f->fc=n;}
    memcpy(f->fl[f->fn].key,k,64);memcpy(f->fl[f->fn].sid,s,64);f->fl[f->fn].len=l;f->fn++;return 0;
}
static const char* fs_get(FS *f,const char *k){
    for(size_t i=0;i<f->hn;++i) if(CRYPTO_memcmp(f->ht[i].key,k,64)==0) return f->ht[i].sid;
    return NULL;
}

static size_t redact(uint8_t *b,size_t p,const char *s,size_t max_p){
    if(p + 19 > max_p) return p;
    static const char M[]="[REDACTED:"; memcpy(b+p,M,10);p+=10;
    size_t l=strlen(s);if(l>8)l=8;memcpy(b+p,s,l);p+=l;b[p++]=']';return p;
}

static PyObject* py_filter_output(PyObject *self, PyObject *args) {
    PyObject *py_out,*py_ent; int ws=20,mm=8;
    if(!PyArg_ParseTuple(args,"OO|ii",&py_out,&py_ent,&ws,&mm)) return NULL;
    const char *data; Py_ssize_t len;
    if(PyBytes_AsStringAndSize(py_out,(char**)&data,&len)<0) return NULL;
    if(len == 0) {
        PyObject *empty_ids = PyList_New(0);
        return Py_BuildValue("y#O", "", 0, empty_ids);
    }

    FS *f=fs_new(); if(!f) return NULL;

    Py_ssize_t ne=PyList_Size(py_ent);
    for(Py_ssize_t ei=0;ei<ne;++ei){
        PyObject *e=PyList_GetItem(py_ent,ei);
        PyObject *ps=PyDict_GetItemString(e,"secret_id");
        PyObject *ph=PyDict_GetItemString(e,"hashes");
        PyObject *pv=PyDict_GetItemString(e,"secret_value");
        if(!ps||!ph||!PyUnicode_Check(ps)) continue;
        PyObject *so=PyUnicode_AsUTF8String(ps); if(!so){fs_del(f);return NULL;}
        char sid[64];memset(sid,0,64);strncpy(sid,PyBytes_AsString(so),63);Py_DECREF(so);

        Py_ssize_t nh=PyList_Size(ph);
        for(Py_ssize_t hi=0;hi<nh;++hi){
            PyObject *hv=PyList_GetItem(ph,hi);
            PyObject *hs=PyUnicode_AsUTF8String(hv);
            if(hs){fs_add_h(f,PyBytes_AsString(hs),sid);Py_DECREF(hs);}
        }
        if(pv&&PyBytes_Check(pv)){
            const char *vp;Py_ssize_t vl;
            PyBytes_AsStringAndSize(pv,(char**)&vp,&vl);
            if(vl==0) continue;
            /* Raw variant */
            {char *h=sha256_hex((const uint8_t*)vp,(size_t)vl);
             if(h){fs_add_f(f,h,sid,(size_t)vl);PyMem_Free(h);}
             if(fnv_table_add(f,(const uint8_t*)vp,(size_t)vl,sid)<0){fs_del(f);return NULL;}}
            /* Base64 variant */
            {size_t bl;
             char *b64=b64_encode((const uint8_t*)vp,(size_t)vl,&bl);
             if(b64){char *h=sha256_hex((const uint8_t*)b64,bl);
               if(h){fs_add_f(f,h,sid,bl);PyMem_Free(h);}
               if(fnv_table_add(f,(const uint8_t*)b64,bl,sid)<0){free(b64);fs_del(f);return NULL;}}
             free(b64);}
            /* Hex variant */
            {char *hx=(char*)malloc((size_t)vl*2+1);
             if(hx){static const char h[]="0123456789abcdef";
               for(Py_ssize_t i=0;i<vl;i++){uint8_t b=(uint8_t)vp[i];hx[i*2]=h[b>>4];hx[i*2+1]=h[b&0xf];}
               hx[(size_t)vl*2]='\0';char *sh=sha256_hex((const uint8_t*)hx,(size_t)vl*2);
               if(sh){fs_add_f(f,sh,sid,(size_t)vl*2);PyMem_Free(sh);}
               if(fnv_table_add(f,(const uint8_t*)hx,(size_t)vl*2,sid)<0){free(hx);fs_del(f);return NULL;}}
             free(hx);}
            /* Trimmed variant */
            {Py_ssize_t s=0,e=vl;
             while(s<e&&(vp[s]==' '||vp[s]=='\t'||vp[s]=='\n'||vp[s]=='\r')) s++;
             while(e>s&&(vp[e-1]==' '||vp[e-1]=='\t'||vp[e-1]=='\n'||vp[e-1]=='\r')) e--;
             if(s>0||e<vl){char *h=sha256_hex((const uint8_t*)(vp+s),(size_t)(e-s));
               if(h){fs_add_f(f,h,sid,(size_t)(e-s));PyMem_Free(h);}
               if(fnv_table_add(f,(const uint8_t*)(vp+s),(size_t)(e-s),sid)<0){fs_del(f);return NULL;}}}
        }
    }

    /* Filter — FNV-1a pre-filter + SHA-256 verification, no Python calls */
    uint8_t *res=malloc((size_t)len+2048); size_t rl=0;
    char last[64];memset(last,0,64);
    size_t i=0;
    size_t max_output = (size_t)len + 2048;

    while(i<(size_t)len){
        int hit=0;
        size_t we_max=i+(size_t)ws; if(we_max>(size_t)len) we_max=(size_t)len;

        /* Sliding window: first-byte skip → FNV-1a + SHA-256 incremental → finalize on match */
        for(size_t w=i;w<i+(size_t)mm&&w<we_max;++w){
            /* First-byte pre-filter: skip entire window start if no candidates */
            uint8_t wfb=(uint8_t)data[w];
            if(f->byte_idx[wfb].count==0) continue;
            uint32_t fnv=0x811c9dc5u;
            EVP_MD_CTX *sctx=NULL;
            int sctx_init=0;
            for(size_t e=w;e<=we_max;++e){
                fnv^=(uint32_t)(uint8_t)data[e]; fnv*=0x01000193u;
                size_t elen=e-w+1;
                /* Initialize SHA-256 context at min_match length, update incrementally */
                if(elen>=(size_t)mm){
                    if(!sctx_init){
                        sctx=EVP_MD_CTX_new();
                        if(sctx){
                            EVP_DigestInit_ex(sctx,EVP_sha256(),NULL);
                            EVP_DigestUpdate(sctx,(const uint8_t*)(data+w),mm);
                            sctx_init=1;
                        }
                    }else{
                        EVP_DigestUpdate(sctx,(const uint8_t*)(data+e),1);
                    }
                }
                if(elen<(size_t)mm) continue;
                /* Skip SHA-256 entirely when FNV-1a doesn't match */
                if(!fnv_table_get(f,(const uint8_t*)(data+w),elen)) continue;
                /* FNV matched — finalize incremental SHA-256 and verify */
                if(sctx){
                    uint8_t dg[EVP_MAX_MD_SIZE]; unsigned int dg_len;
                    EVP_DigestFinal_ex(sctx,dg,&dg_len); EVP_MD_CTX_free(sctx); sctx=NULL; sctx_init=0;
                    char hx[65]; static const char h[]="0123456789abcdef";
                    for(unsigned int d=0;d<dg_len;d++){hx[d*2]=h[dg[d]>>4];hx[d*2+1]=h[dg[d]&0xf];}
                    hx[64]='\0';
                    const char *sid=fs_get(f,hx);
                    if(sid){
                        while(i<w){if(rl<max_output-1)res[rl++]=(uint8_t)data[i];i++;}
                        if(memcmp(last,sid,64)!=0){rl=redact(res,rl,sid,max_output);memcpy(last,sid,64);}
                        i=e+1;hit=1; goto dw;
                    }
                }
            }
            if(sctx){EVP_MD_CTX_free(sctx);}
        }
    dw:;
        if(hit) continue;

        /* Full-length matches — FNV-1a → SHA-256 cascade */
        for(size_t fi=0;fi<f->fn;++fi){
            size_t sl=f->fl[fi].len; if(sl==0) continue;
            if(i+sl>(size_t)len) continue;
            
            /* FNV-1a pre-filter */
            const FNVEntry *fe=fnv_table_get(f,(const uint8_t*)(data+i),sl);
            if(!fe) continue;
            /* SHA-256 verification */
            char *h=sha256_hex((const uint8_t*)(data+i),sl);
            if(!h) continue;
            if(CRYPTO_memcmp(h,f->fl[fi].key,64)!=0){PyMem_Free(h);continue;}
            PyMem_Free(h);
            if(memcmp(last,fe->sid,64)!=0){rl=redact(res,rl,fe->sid,max_output);memcpy(last,fe->sid,64);}
            i+=sl;hit=1;goto df;
        }
    df:;
        if(hit) continue;
        if(rl >= max_output - 1) {
            PyErr_WarnFormat(PyExc_RuntimeWarning, 0,
                "venya_filter: output truncated (%zu/%zu bytes)", rl, max_output);
            break;
        }
        res[rl++]=(uint8_t)data[i]; i++;
    }

    /* Extract unique IDs */
    PyObject *ids=PyList_New(0); char seen[256][9]; int sn=0;
    size_t p=0;
    while(p+18<=rl){
        if(memcmp(res+p,"[REDACTED:",10)==0){
            char sid[9];size_t se=p+10,sl=0;
            while(se<rl&&sl<8&&res[se]!=']') sid[sl++]=(char)res[se++];
            sid[sl]='\0';
            if(sl>0){int d=0;for(int s=0;s<sn;++s)if(memcmp(seen[s],sid,8)==0){d=1;break;}
                if(!d&&sn<256){memcpy(seen[sn++],sid,9);PyList_Append(ids,PyUnicode_FromString(sid));}}
            p=se+1;
        } else p++;
    }

    PyObject *ret=Py_BuildValue("y#O",res,rl,ids); free(res); fs_del(f); return ret;
}

/* ========================================================================
 * Module
 * ======================================================================== */

static PyMethodDef methods[]={
    {"compute_detection_hashes",py_compute_detection_hashes,METH_VARARGS,""},
    {"filter_output",py_filter_output,METH_VARARGS,""},
    {NULL,NULL,0,NULL}
};
static struct PyModuleDef mod={PyModuleDef_HEAD_INIT,"_venya_filter","",-1,methods};
PyMODINIT_FUNC PyInit__venya_filter(void){return PyModule_Create(&mod);}
