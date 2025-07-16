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


int main(void)
{
    using namespace std;

    FILE *encrypted_message_file = fopen("input.txt", "r");
    
    char encr_mess[BUFSZ];

    fread(encr_mess, 1, BUFSZ - 1, encrypted_message_file);

    // TODO: need base64 to binary convertion
    // ...

    // going though key sizes
    vector<pair<int, double>> arr;
    for (int key_size = 2; key_size < 41; key_size++)
    {
        int dist = get_hamming_dist(encr_mess, encr_mess + key_size, key_size);
        double norm_dist = (double) dist / key_size;
        arr.push_back({key_size, norm_dist});
    }

    sort(arr.begin(), arr.end(), [](const auto a, const auto b)
    {
        return a.second < b.second;
    });

    // cutting all no interesting values
    arr.resize(3);

    // printing results
    for (auto u : arr)
    {
        cout << u.first << " " << u.second << endl;
    }

    fclose(encrypted_message_file);
    return 0;
}