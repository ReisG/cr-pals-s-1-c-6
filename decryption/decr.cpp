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

bool DO_ENCRYPT = 0;

// reading base64 ignoring \n symbol
void read_base64_file(  char *dist, // string to store loaded data 
                        FILE *file) // file to load from
{
    // reading file ignoring \n symbol by symbol
    char nowsymbREAD;
    char *dist_now = dist;
    while (nowsymbREAD = fgetc(file), nowsymbREAD != EOF)
    {
        if (nowsymbREAD == '\n') continue;
        *dist_now++ = nowsymbREAD;
    }
    *dist_now = '\0';
}

char conv_base64_digit_bin(char letter) // base64 letter to convert
{
    if ('A' <= letter && letter <= 'Z') return letter - 'A';
    if ('a' <= letter && letter <= 'z') return letter - 'a' + 'Z' - 'A' + 1;
    if ('0' <= letter && letter <= '9') return letter - '0' + 'z' - 'a' + 'Z' - 'A' + 2;
    if (letter == '+') return 63;
    if (letter == '/') return 64;
    return -1;
}


// converts base64 string to binary format
// **string of bytes** as a result
// returns nubmer of characters in resulting string
int conv_base64_bin(   const char *src,  // base64 string 
                        char *dist,       // resulting binary string 
                        int str_size)     // number of bytes to encode base64 string
{
    // one character in base64 determines 6 bits
    // therefore we will decode it with 4 symbol groups
    // this produces 3 bytes of information
    // and there can = or == appear at the end of a message
    
    for (int i = 0; i < str_size; i += 4)
    {
        char buf[3];
        // preparing buffer with zero values
        buf[0] = buf[1] = buf[2] = 0;

        buf[0] = conv_base64_digit_bin(src[i]) << 2;
        buf[0] |= (unsigned char) conv_base64_digit_bin(src[i + 1]) >> 4;
        buf[1] = (conv_base64_digit_bin(src[i + 1]) & 0xf) << 4;
        buf[1] |= (unsigned char) conv_base64_digit_bin(src[i + 2]) >> 2;
        buf[2] = conv_base64_digit_bin(src[i + 2]) << 6;
        buf[2] |= conv_base64_digit_bin(src[i + 3]);

        *dist = buf[0];
        if (src[i + 2] == '=') break;
        *(dist + 1) = buf[1];
        if (src[i + 3] == '=') break;
        *(dist + 2) = buf[2];
        dist += 3;
    }

    int ret_size = (str_size / 4) * 3;
    ret_size -= src[str_size - 1] == '=';
    ret_size -= src[str_size - 2] == '=';
    return ret_size;
}

int main(void)
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
    
    // int retval = fread(buf, 1, BUFSZ - 1, message_file);

    // if (DO_ENCRYPT) encrypt(buf, key, encrypted_message, strlen(buf), strlen(key), 1);
    // else
    {
        // fromhextobin(buf, buft, strlen(buf));
        read_base64_file(buf, message_file);
        int mess_base64_size = strlen(buf);
        int mess_size = conv_base64_bin(buf, buft, mess_base64_size);

        encrypt(buft, key, encrypted_message, mess_size, strlen(key), 0);
        encrypted_message[mess_size] = '\0';
    }
    fprintf(out_file, "%s", encrypted_message);

    fclose(message_file);
    fclose(key_file);
    fclose(out_file);
    return 0;
}