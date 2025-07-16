#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>

#include <iostream>
#include <vector>
#include <utility>
#include <map>
#include <algorithm>

#define BUFSZ 100000

void fromhextobin(const char *src, // origin 
    char *dist, // dist
    const int sz) // number of symbols in origin
{
    // setting dist to zero
    memset(dist, 0, sz >> 1);

    for (int i = 0; i < sz; i++)
    {
        int r = tolower(src[i]);
        // if (!r) break;
        // if (!isdigit(r) || !isalpha(r)) exit(1); // wrong format

        if (isdigit(r)) dist[i >> 1] |= src[i] - '0' << (~i & 1) * 4;
        else if (isalpha(r)) dist[i >> 1] |= src[i] - 'a' + 10 << (~i & 1) * 4;
        else
        {
            puts("syntax error");
            exit(1);
        }
    }

    // dist[sz >> 1] = '\0';
}

void xorab(const char *a, const char *b, char *res, const int sz)
{
    memset(res, 0, sz);
    for (int i = 0; i < sz; i++) res[i] = a[i] ^ b[i];
}

// returns pointer to encrypted message
char *encrypt(const char *src, // plain text (characters)
            const char *key, // plain text key
            char *res, // hex encrypted message
            int src_sz, // length of plain text message
            int key_sz, // length of key
            bool to_hex) // do we need to convert resulting string to hex (twice long!!!) 
{
    int message_size = src_sz; //strlen(src);
    int key_size = key_sz;// strlen(key);

    for (int i = 0; i < message_size; i++)
    {
        char t = src[i] ^ key[i % key_size];
        if (to_hex)
        {
            res[i << 1] = "0123456789abcdef"[t >> 4 & 0xf];
            res[i << 1 | 1] = "0123456789abcdef"[t & 0xf];
        }
        else res[i] = t;
    }
    res[message_size << to_hex] = '\0';
    return res;
}

void bintohex(const char *src, 
    char *dist, 
    int sz) // size of origin
{
    for (int i = 0; i < sz; i++)
    {
        dist[i << 1] = "0123456789abcdefghijklmnopqrstuvwxyz"[src[i] >> 4];
        dist[i << 1 | 1] = "0123456789abcdefghijklmnopqrstuvwxyz"[src[i] & 0xf];
    }
    dist[sz << 1] = '\0';
}

int get_hamming_dist(   const char *a, // first string
                        const char *b, // second string
                        const int sz)  // number of characters in each to compare
{
    int result = 0;
    // going through each byte (character)
    for (int i = 0; i < sz; i++)
    {
        // do xor to bytes
        char t = a[i] ^ b[i];

        // counting number of 1 bits
        // Hacker's delight 5-1 bit manipulation
        t = (t & 0x55) + (t >> 1 & 0x55);
        t = (t & 0x33) + (t >> 2 & 0x33);
        t = (t & 0x0f) + (t >> 4 & 0x0f);

        result += (unsigned) t;
    }

    return result;
}

bool DO_ENCRYPT = 0;

int main2(void)
{
    FILE *message_file = fopen("input.txt", "r");
    FILE *key_file = fopen("key.key", "r");
    FILE *out_file = fopen("output.txt", "w");
    static char buf[BUFSZ], buft[BUFSZ];
    static char key[BUFSZ];
    static char encrypted_message[BUFSZ];
    
    // reading key
    fgets(key, BUFSZ - 1, key_file);
    key[strcspn(key, "\n")] = '\0';
    
    int retval = fread(buf, 1, BUFSZ - 1, message_file);
    
    // if (!retval) break;
    //std::cout << "<" << buf << ">" << std::endl;
    // buf[strcspn(buf, "\n")] = '\0';
    if (DO_ENCRYPT) encrypt(buf, key, encrypted_message, strlen(buf), strlen(key), 1);
    else
    {
        fromhextobin(buf, buft, strlen(buf));
        encrypt(buft, key, encrypted_message, strlen(buf) >> 1, strlen(key), 0);
    }
    fprintf(out_file, "%s", encrypted_message);

    fclose(message_file);
    fclose(key_file);
    fclose(out_file);
    return 0;
}

// testing hamming distance function
int main(void)
{
    char a[] = "this is a test";
    char b[] = "wokka wokka!!!";

    printf("%d", get_hamming_dist(a, b, strlen(a)));
    return 0;
}