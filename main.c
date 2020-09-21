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

char worker(char api[], char domain[]) {
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
    curl_easy_setopt(ch, CURLOPT_URL, api);
    rv = curl_easy_perform(ch);
    if (rv != CURLE_OK) {
        printf("*** Failed to reach api.cert.ist: %d ***\n", rv);
        return 1;
    }
    json_object *jobj = json_tokener_parse(chunk.memory);
    struct json_object *base = json_object_object_get(jobj, "public_key");
    struct json_object *pem_obj = json_object_object_get(base, "pem");
    const char *pem = json_object_get_string(pem_obj);
    printf("Found public_key pem:\n%s\n", pem);

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

    FILE *file = fopen("cert.pem", "w");
    int results = fputs(pem, file);
    if (results == EOF) {
        printf("Error results: %d", results);
    }
    fclose(file);
    curl_easy_setopt(ch, CURLOPT_URL, domain);
    curl_easy_setopt(ch, CURLOPT_PINNEDPUBLICKEY, "../urip.io.pubkey.pem");
    curl_easy_setopt(ch, CURLOPT_PINNEDPUBLICKEY, "cert.pem");

    rv = curl_easy_perform(ch);
    printf("Done with call\n");
    if (rv == CURLE_OK) {
        printf("*** transfer succeeded ***\n");
    } else if (rv == CURLE_SSL_PINNEDPUBKEYNOTMATCH) {
        printf("certs did not match\n");
    } else {
        printf("*** transfer failed *** : %d", rv);
    }
    curl_easy_cleanup(ch);
    curl_global_cleanup();
    return rv;
}

int main(void) {
    return worker("https://api.cert.ist/urip.io", "https://urip.io");
}