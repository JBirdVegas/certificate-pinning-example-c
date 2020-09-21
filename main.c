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

const char *pubkey_file = "pubkey.pem";

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

    // setup api response data holder
    struct MemoryStruct chunk;
    chunk.memory = malloc(1);
    chunk.size = 0;

    // setup libcurl
    curl_global_init(CURL_GLOBAL_ALL);
    ch = curl_easy_init();
    curl_easy_setopt(ch, CURLOPT_VERBOSE, 0L);
    curl_easy_setopt(ch, CURLOPT_HEADER, 0L);
    curl_easy_setopt(ch, CURLOPT_NOPROGRESS, 1L);
    curl_easy_setopt(ch, CURLOPT_NOSIGNAL, 1L);
    curl_easy_setopt(ch, CURLOPT_WRITEDATA, stdout);
    curl_easy_setopt(ch, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
    curl_easy_setopt(ch, CURLOPT_WRITEDATA, (void *) &chunk);
    curl_easy_setopt(ch, CURLOPT_SSLCERTTYPE, "PEM");
    curl_easy_setopt(ch, CURLOPT_SSL_VERIFYPEER, 1L);

    // call api.cert.ist to get the expected public keys
    curl_easy_setopt(ch, CURLOPT_URL, api);
    rv = curl_easy_perform(ch);
    if (rv != CURLE_OK) {
        printf("*** Failed to reach %s: %d ***\n", api, rv);
        return 1;
    }

    // parse our the public key pem from cert.ist's api
    json_object *jobj = json_tokener_parse(chunk.memory);
    struct json_object *base = json_object_object_get(jobj, "libcurl");
    struct json_object *pubkey_obj = json_object_object_get(base, "pubkey");
    struct json_object *pem_obj = json_object_object_get(pubkey_obj, "pem");
    const char *pem = json_object_get_string(pem_obj);

    // write the PEM public key to a file
    FILE *file = fopen(pubkey_file, "w");
    int results = fputs(pem, file);
    if (results == EOF) {
        printf("Error results: %d", results);
    }
    fclose(file);

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
    // tell curl to call the domain in question
    curl_easy_setopt(ch, CURLOPT_URL, domain);
    // tell curl to pin the public key we found from the API to the
    // public key curl receives during the TLS hello handshake
    curl_easy_setopt(ch, CURLOPT_PINNEDPUBLICKEY, pubkey_file);

    rv = curl_easy_perform(ch);
    if (rv == CURLE_OK) {
        printf("(%s) certs matched :D\n", domain);
    } else if (rv == CURLE_SSL_PINNEDPUBKEYNOTMATCH) {
        printf("(%s) certs did not match\n", domain);
    } else {
        printf("Something else happened, we received error code: %d\n", rv);
    }
    curl_easy_cleanup(ch);
    curl_global_cleanup();
    return rv;
}

int main(void) {
    char example = worker("https://api.cert.ist/example.com", "https://example.com");
    char certist = worker("https://api.cert.ist/cert.ist", "https://cert.ist");
    char uripio = worker("https://api.cert.ist/urip.io", "https://urip.io");
    return example + certist + uripio;
}