---
layout: post
title:  "Injecting page-level cipher into SQLite"
date:   2016-07-26 18:56:18 +0300
categories: openssl sqlite
published: true
comments: true
---

By default, SQLite does not provide any encryption. There is [SEE - SQLite Encryption Extension], which provides RC4 and AES, but you need to buy SEE to get the sources and inject to your SQLite. Here I shortly describe how to implement missing internal and public API to allow SQLite to encrypt your data. It may be useful if you don't want to pay for SEE or if you need something more than RC4 and AES, for example your national ciphers, like russian GOST.

<!--more-->

Initially, I used [botan-sqlite] as example how to implement own encryption/decryption functionality for SQLite. After applying their patch to the latest stable amalgamation version 3.13.0 I got some linkage issues, like unresolved externals `sqlite3_key_v2` and `sqlite3_rekey_v2` and couple of internal functions had changed parameter numbers. After fixing that issues I created own simple Codec wrapping OpenSSL and using AES for encryption memory pages. By default, SQLite page size is 4096 bytes, so you can use any block cipher with key size aliquot to page size. So, we can use AES 128, AES 256, just do not forget set zero padding after cipher initialization.

{% highlight cpp %}
    EVP_CIPHER_CTX cipherCtx;
    EVP_EncryptInit(&cipherCtx, EVP_aes_128_ecb(), key, ivec);
    EVP_CIPHER_CTX_set_padding(&cipherCtx, 0);
{% endhighlight %}

So, here I can show the simplest way without any OpenSSL-related specifics, so I will show simple codec, which can take one byte key and do XOR for SQLite pages using this key before read and write.

As SQLite is open source, the patch for SQLite implemeting our "own SEE" will look like a few internal SQLite functions and four public functions (sqlite3_key_v2, sqlite3_key, sqlite3_rekey_v2, sqlite3_key) and compile SQLite with `-DSQLITE_HAS_CODEC` definition. These functions are listed below.

{% highlight cpp %}
void sqlite3_activate_see(const char *info);
void sqlite3PagerFreeCodec(void *pCodec);
void sqlite3CodecSizeChange(void *pCodec, int pageSize, int nReserve);
void* sqlite3Codec(void *pCodec, void *data, unsigned nPageNum, int nMode);
void sqlite3CodecGetKey(sqlite3* db, int nDb, void **zKey, int *nKey);
int sqlite3CodecAttach(sqlite3 *db, int nDb, const void *zKey, int nKey);
int sqlite3_key(sqlite3 *db, const void *zKey, int nKey);
int sqlite3_rekey(sqlite3 *db, const void *zKey, int nKey);
int sqlite3_key_v2(sqlite3 *db, const char *zDbName, const void *pKey, int nKey);
int sqlite3_rekey_v2(sqlite3 *db, const char *zDbName, const void *pKey, int nKey);
{% endhighlight %}

`sqlite3_activate_see` is for activating original SEE, so we need to implement this function with empty body, just to avoid linkage error. To implement other functions we need to write some code :)

Re-keying is out-of-scope of this post, so I will show how to implement two things

* Pass key into SQLite
* Encrypt and decrypt pages using this key

So, the most important functions are `sqlite3CodecAttach` and `sqlite3Codec`, the first one injects your custom object which can store some encryption context (key, pagesize etc) into SQLite, the second one is callback, called every time when SQLite needs to read or write page. So, we can inject our code to encrypt page before writing and decrypt after reading to make it transparent for the end user.

Before starting we need to define our "codec".

{% highlight cpp %}
struct KeyStorage
{
    unsigned char m_key;
    unsigned m_pageSize;
    unsigned char * m_page;
};
{% endhighlight %}

`m_key` and `m_pageSize` are for storing key and current page size, `m_page` is needed as temporary buffer for encryption. `m_page` allocated size should be equal `m_pageSize`.

{% highlight cpp %}
int sqlite3CodecAttach(sqlite3 *db, int nDb, const void *zKey, int nKey)
{
    
    struct KeyStorage *ks = (struct KeyStorage *)malloc(sizeof(struct KeyStorage));
    if (NULL != ks)
    {
        ks->m_key = ((unsigned char*)(zKey))[0];
        ks->m_pageSize = 0;
        ks->m_page = NULL;
        
        sqlite3PagerSetCodec(sqlite3BtreePager(db->aDb[nDb].pBt),
                                    sqlite3Codec,
                                    sqlite3CodecSizeChange,
                                    sqlite3PagerFreeCodec, (void *)ks);

        return SQLITE_OK;
    }
    else
    {
        return SQLITE_FAIL;
    }
}
{% endhighlight %}

The implementation of sqlite3CodecAttach is very simple, we just allocate memory for `struct KeyStorage` and call internal function sqlite3PagerSetCodec, setting three callbacks and address of allocated struct.

sqlite3Codec callback gets four arguments: your codec pointer, data to encrypt, page number and mode. "mode" determines what to do with "data" using "pCodec". The size of "data" is page size, passed to sqlite3CodecSizeChange by SQLite. Of course, we store this value in our codec object.

{% highlight cpp %}
void sqlite3CodecSizeChange(void *pCodec, int pageSize, int nReserve)
{
    if (pCodec)
    {
        struct KeyStorage *ks = (struct KeyStorage *)pCodec;
        ks->m_pageSize = pageSize;

        if (ks->m_page)
            free(ks->m_page);

        ks->m_page = malloc(pageSize);
        if (ks->m_page)
            memset(ks->m_page, 0, pageSize);
    }
}
{% endhighlight %}

In our case we implement XOR, so we just enumerate "data" and xor every byte using a key from "pCodec".

 {% highlight cpp %}
void* sqlite3Codec(void *pCodec, void *data, unsigned nPageNum, int nMode)
{
    if (pCodec == NULL)
        return data;

    struct KeyStorage *ks = (struct KeyStorage *)pCodec;
    unsigned char *p = (unsigned char *)data;
    
    switch(nMode)
    {
        case 0: // Undo a "case 7" journal file encryption
        case 2: // Reload a page
        case 3: // Load a page
            for (int i=0; i < ks->m_pageSize; i++)
            {
                p[i] ^= ks->m_key;
            }
            return data;
        case 6: // Encrypt a page for the main database file
            for (int i=0; i < ks->m_pageSize; i++)
            {
                ks->m_page[i] = p[i] ^ ks->m_key;
            }
            return ks->m_page;

        case 7: // Encrypt a page for the journal file
            for (int i=0; i < ks->m_pageSize; i++)
            {
                ks->m_page[i] = p[i] ^ ks->m_key;
            }
            return ks->m_page;            
    }

    return NULL;
}
{% endhighlight %}

The sources and build steps are here: [https://github.com/solardatov/sqlite-encryptor-sample]


[SEE - SQLite Encryption Extension]: https://www.sqlite.org/see/doc/trunk/www/index.wiki
[botan-sqlite]: https://github.com/randombit/botan-sqlite
[https://github.com/solardatov/sqlite-encryptor-sample]: https://github.com/solardatov/sqlite-encryptor-sample