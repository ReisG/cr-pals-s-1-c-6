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
void conv_base64_bin(   const char *src,  // base64 string 
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
}


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


int main(void)
{
    using namespace std;

    FILE *encrypted_message_file = fopen("input.txt", "r");
    
    char encr_mess_base64[BUFSZ], encr_mess[BUFSZ];

    // reading base64
    read_base64_file(encr_mess_base64, encrypted_message_file);
    int encr_mess_base64_size = strlen(encr_mess_base64);

    // TODO need base64 to binary convertion
    conv_base64_bin(encr_mess_base64, encr_mess, strlen(encr_mess_base64));
    int encr_mess_size = (encr_mess_base64_size / 4) * 3;
    encr_mess_size -= encr_mess_base64[encr_mess_base64_size - 1] == '=';
    encr_mess_size -= encr_mess_base64[encr_mess_base64_size - 2] == '=';


    // going though key sizes
    vector<pair<int, double>> KEY_SIZES;
    for (int key_size = 2; key_size < 41; key_size++)
    {
        int dist = get_hamming_dist(encr_mess, encr_mess + key_size, key_size);
        double norm_dist = (double) dist / key_size;
        KEY_SIZES.push_back({key_size, norm_dist});
    }

    sort(KEY_SIZES.begin(), KEY_SIZES.end(), [](const auto a, const auto b)
    {
        return a.second < b.second;
    });

    // cutting all no interesting values
    KEY_SIZES.resize(3);

    // printing results
    cout << "Key length, error level" << endl;
    for (auto u : KEY_SIZES)
    {
        cout << "- " << u.first << " " << u.second << endl;
    }

    for (auto &[KEY_SIZE, _KEY_PROBABILITY] : KEY_SIZES)
    {
        cout << ">>> WORKING WITH KEY_SIZE " << KEY_SIZE << endl;
        // need to create statistics for every letter in key
        // then we compare captured frequency distributions
        // to original english distribution.

        //const int APLH_SIZE = 'z' - 'a' + 1;
        //double alph_distr[APLH_SIZE];
        
        // looking for 2 most appearing symbols
        // we assume that is space and e
        // so for each length we will have to keys
        string KEY_VALUE;
        int total = 0;
        for (int letid = 0; letid < KEY_SIZE; letid++)
        {
            cout << ">>> >>> LETTERID " << letid << endl;
            map<char, int> letter_st_map;

            for (int i = letid; i < encr_mess_size; i += KEY_SIZE)
            {
                letter_st_map[tolower(encr_mess[i])]++;
            }

            // rearranging statistics and creating an array
            vector<pair<int, char>> letter_st_ar;
            for (auto t : letter_st_map) letter_st_ar.push_back(t);
            sort(letter_st_ar.begin(), letter_st_ar.end(), [](const auto a, const auto b)
            {
                return a.first > b.first;
            });

            // freeing memory
            // first to choose key second to fit it
            letter_st_ar.resize(2);

            // for (auto t : letter_st_ar) cout << t.first << " " << (int) t.second << endl;

            char NOW_KEY = 0; // assume that we don't use this letter in key
            // checking first one
            char F_NOW_KEY = ' ' ^ letter_st_ar[0].second;
            char S_NOW_KEY = 'e' ^ letter_st_ar[0].second;
            if (F_NOW_KEY ^ letter_st_ar[1].second == 'e') NOW_KEY = F_NOW_KEY;
            else if (S_NOW_KEY ^ letter_st_ar[1].second == ' ') NOW_KEY = S_NOW_KEY;

            if (!NOW_KEY) break;

            // we probably have found letter in key
            KEY_VALUE += NOW_KEY;

            // // counting number of occurrences
            // memset(alph_distr, 0, sizeof(alph_distr));
            // for (int i = letid; i < encr_mess_size; i += KEY_SIZE)
            // {
            //     if (encr_mess[i] == ' ') continue;
            //     alph_distr[encr_mess[i]]++;
            //     total++;
            // }

            // // normalizing result
            // for (int i = 0; i < APLH_SIZE; i++) alph_distr[i] /= total;

            // // checking if our distribution match to 

        }

        // in case we failed 
        if (KEY_VALUE.size() != KEY_SIZE) continue;
        
        // print key in case we succeed
        cout << KEY_SIZE << " <" << KEY_VALUE << ">" << endl;
    }

    fclose(encrypted_message_file);
    return 0;
}
