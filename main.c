/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2019, Daniel Stenberg, <daniel@haxx.se>, et al.
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at https://curl.haxx.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 ***************************************************************************/
/* <DESC>
 * CA cert in memory with OpenSSL to get a HTTPS page.
 * </DESC>
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <json-c/json.h>
#include <curl/curl.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

static char *pem_found;

static size_t writefunction(void *ptr, size_t size, size_t nmemb, void *stream) {
    fwrite(ptr, size, nmemb, (FILE *) stream);
    return (nmemb * size);
}

struct MemoryStruct {
    char *memory;
    size_t size;
};

static size_t
WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp) {
    size_t realsize = size * nmemb;
    struct MemoryStruct *mem = (struct MemoryStruct *) userp;

    char *ptr = realloc(mem->memory, mem->size + realsize + 1);
    if (ptr == NULL) {
        /* out of memory! */
        printf("not enough memory (realloc returned NULL)\n");
        return 0;
    }

    mem->memory = ptr;
    memcpy(&(mem->memory[mem->size]), contents, realsize);
    mem->size += realsize;
    mem->memory[mem->size] = 0;

    return realsize;
}

static const char *get_pem(char domain[]) {
    CURL *ch;
    CURLcode rv;

    struct MemoryStruct chunk;

    chunk.memory = malloc(1);  /* will be grown as needed by the realloc above */
    chunk.size = 0;    /* no data at this point */

    curl_global_init(CURL_GLOBAL_ALL);
    ch = curl_easy_init();
    curl_easy_setopt(ch, CURLOPT_VERBOSE, 0L);
    curl_easy_setopt(ch, CURLOPT_HEADER, 0L);
    curl_easy_setopt(ch, CURLOPT_NOPROGRESS, 1L);
    curl_easy_setopt(ch, CURLOPT_NOSIGNAL, 1L);
    curl_easy_setopt(ch, CURLOPT_WRITEDATA, stdout);

    /* send all data to this function  */
    curl_easy_setopt(ch, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
    /* we pass our 'chunk' struct to the callback function */
    curl_easy_setopt(ch, CURLOPT_WRITEDATA, (void *) &chunk);

    curl_easy_setopt(ch, CURLOPT_SSLCERTTYPE, "PEM");
    curl_easy_setopt(ch, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(ch, CURLOPT_URL, domain);
    rv = curl_easy_perform(ch);

    if (rv != CURLE_OK) {
        fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(rv));
    } else {
        printf("%lu bytes retrieved\n", (unsigned long) chunk.size);
    }
    json_object *jobj = json_tokener_parse(chunk.memory);
    const char *pem;
    pem = json_object_get_string(json_object_object_get(jobj, "pem"));
    return pem;
}

char worker(char domain[]) {
    CURL *ch;
    CURLcode rv;

    struct MemoryStruct chunk;

    chunk.memory = malloc(1);  /* will be grown as needed by the realloc above */
    chunk.size = 0;    /* no data at this point */

    curl_global_init(CURL_GLOBAL_ALL);
    ch = curl_easy_init();
    curl_easy_setopt(ch, CURLOPT_VERBOSE, 0L);
    curl_easy_setopt(ch, CURLOPT_HEADER, 0L);
    curl_easy_setopt(ch, CURLOPT_NOPROGRESS, 1L);
    curl_easy_setopt(ch, CURLOPT_NOSIGNAL, 1L);
    curl_easy_setopt(ch, CURLOPT_WRITEDATA, stdout);

    /* send all data to this function  */
    curl_easy_setopt(ch, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
    /* we pass our 'chunk' struct to the callback function */
    curl_easy_setopt(ch, CURLOPT_WRITEDATA, (void *) &chunk);

    curl_easy_setopt(ch, CURLOPT_SSLCERTTYPE, "PEM");
    curl_easy_setopt(ch, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(ch, CURLOPT_URL, domain);
    rv = curl_easy_perform(ch);

    json_object *jobj = json_tokener_parse(chunk.memory);
    const char *pem;
    pem = json_object_get_string(json_object_object_get(jobj, "pem"));
    const char *sha256;
    sha256=json_object_get_string(json_object_object_get(json_object_object_get(json_object_object_get(jobj, "certificate"), "hashes"), "sha256"));
    printf("Found sha256: %s\n", sha256);
//    pem_found = *pem;
    if (rv != CURLE_OK) {
        printf("*** transfer failed ***\n");
        return 1;
    }

    /* use a fresh connection (optional)
     * this option seriously impacts performance of multiple transfers but
     * it is necessary order to demonstrate this example. recall that the
     * ssl ctx callback is only called _before_ an SSL connection is
     * established, therefore it will not affect existing verified SSL
     * connections already in the connection cache associated with this
     * handle. normally you would set the ssl ctx function before making
     * any transfers, and not use this option.
     */
    curl_easy_setopt(ch, CURLOPT_FRESH_CONNECT, 1L);

    char out[SHA256_DIGEST_LENGTH+8*10]="sha256//";
    unsigned char *d = SHA256(pem, strlen((char *) pem), 0);

    int i;
    for (i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        char temp[4];
        sprintf(temp, "%02x", d[i]);
        strcat(out, temp);
    }
    printf("helo: %s\n", out);
    char final[SHA256_DIGEST_LENGTH+8*10];
    curl_easy_setopt(ch, CURLOPT_PINNEDPUBLICKEY, final);

    rv = curl_easy_perform(ch);
    if (rv == CURLE_OK)
        printf("*** transfer succeeded ***\n");
    else
        printf("*** transfer failed ***\n");

    curl_easy_cleanup(ch);
    curl_global_cleanup();
    return rv;
}

int main(void) {
    return worker("https://api.cert.ist/urip.io");
}