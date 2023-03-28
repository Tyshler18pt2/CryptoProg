#pragma once
#include <iostream>
#include <fstream>
#include <string>
#include <map>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <linux/if_alg.h>

#define ALG_CBC_AES "cbc(aes)"
#define ALG_ECB_AES "ecb(aes)"
#define ALG_CTR_AES "ctr(aes)"

class Cipher
{
public:
    enum CipherAlg {CBC_AES, ECB_AES, CTR_AES};
protected:
    std::map<int, const char *> AlgList{
        std::pair<int, const char *>(CBC_AES, ALG_CBC_AES),
        std::pair<int, const char *>(ECB_AES, ALG_ECB_AES),
        std::pair<int, const char *>(CTR_AES, ALG_CTR_AES)};
    static constexpr int BUF_SIZE = 1024 * 4;
    static constexpr int BLOCK_LEN = 16;
    static constexpr int KEY_LEN = 16;
    unsigned char IV[BLOCK_LEN]={185,112,188,52,225,91,61,19,78,148,112,48,39,199,73,232};
    unsigned char  Key[KEY_LEN];  
    int cryptosocket;
    int ciphersocket;
    CipherAlg _alg;
    void keygen(const std::string& psw);
public:
    Cipher()=delete;
    Cipher(const std::string& password, CipherAlg alg = CBC_AES);
    virtual ~Cipher();
    std::string name() {
        return std::string(AlgList[_alg]);
    }
};


class FileCipher : public Cipher
{
public:
    FileCipher()=delete;
    FileCipher(const std::string password, CipherAlg alg = CBC_AES):Cipher(password, alg) {}
    ~FileCipher() {}
    void encrypt(const std::string& source_file, const std::string& destination_file);
    void decrypt(const std::string& source_file, const std::string& destination_file);
};
