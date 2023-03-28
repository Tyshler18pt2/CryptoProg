#include <system_error>
#include <algorithm>
#include <cstring>
#include "cipher.h"



//////////////////////// Cipher //////////////////////////////////////////////////

Cipher::Cipher(const std::string& password, CipherAlg alg) : _alg(alg)
{

    keygen(password);

    cryptosocket = socket(AF_ALG, SOCK_SEQPACKET, 0);
    if (cryptosocket == -1)
        throw std::system_error(errno, std::system_category(), "Error open crypto socket");

    sockaddr_alg sa = {};
    sa.salg_family = AF_ALG;
    strcpy((char *)sa.salg_type, "skcipher");
    strcpy((char *)sa.salg_name, AlgList[_alg]);

    int status = bind(cryptosocket, (sockaddr *)&sa, sizeof sa);
    if (status == -1)
        throw std::system_error(errno, std::system_category(), "Error bind cryptosocket");

    ciphersocket = accept(cryptosocket, nullptr, 0);
    if (ciphersocket == -1)
        throw std::system_error(errno, std::system_category(), "Error accept to hashsocket");

    status = setsockopt(cryptosocket, SOL_ALG, ALG_SET_KEY, Key, KEY_LEN);
    if (status == -1)
        throw std::system_error(errno, std::system_category(), "Error set key");

}

Cipher::~Cipher()
{
    close(ciphersocket);
    close(cryptosocket);
}

void Cipher::keygen(const std::string& psw)
{
    unsigned char salt[20] = {239,71,180,122,42,39,78,63,85,114,90,107,73,187,35,193,216,16,36,252};
    int len;

    int cryptosocket = socket(AF_ALG, SOCK_SEQPACKET, 0);
    if (cryptosocket == -1)
        throw std::system_error(errno, std::system_category(), "Keygen:Error open crypto socket");

    sockaddr_alg sa = {};
    sa.salg_family = AF_ALG;
    strcpy((char *)sa.salg_type, "hash");
    strcpy((char *)sa.salg_name, "hmac(sha1)");

    int status = bind(cryptosocket, (sockaddr *)&sa, sizeof sa);
    if (status == -1)
        throw std::system_error(errno, std::system_category(), "Keygen:Error bind cryptosocket");

    int hashsocket = accept(cryptosocket, nullptr, 0);
    if (hashsocket == -1)
        throw std::system_error(errno, std::system_category(), "Keygen:Error accept to hashsocket");

    status = setsockopt(cryptosocket, SOL_ALG, ALG_SET_KEY, psw.data(), psw.size());
    if (status == -1)
        throw std::system_error(errno, std::system_category(), "Keygen:Error set password");

    for(int i=0; i<10000; i++) {
        len = send(hashsocket, salt, sizeof salt, 0);
        if (len == -1)
            throw std::system_error(errno, std::system_category(), "Keygen:Error evaluate hash data");
        len = recv(hashsocket, salt, sizeof salt, 0);
        if (len == -1)
            throw std::system_error(errno, std::system_category(), "Keygen:Error get hash value");
    }
    std::copy_n(salt, KEY_LEN, Key);
    close(hashsocket);
    close(cryptosocket);
}

//////////////////////// FileCipher ////////////////////////////////////////////

void FileCipher::encrypt(const std::string& source_file, const std::string& destination_file)
{
    //open files
    std::ifstream source;
    source.exceptions(std::ifstream::failbit | std::ifstream::badbit);
    source.open(source_file);
    source.exceptions(std::ifstream::goodbit );
    std::ofstream destination;
    destination.exceptions(std::ifstream::failbit | std::ifstream::badbit);
    destination.open(destination_file);
    destination.exceptions(std::ifstream::goodbit );
    int len,pad;
    unsigned char* in_buf = new unsigned char[BUF_SIZE];
    unsigned char* out_buf = new unsigned char[BUF_SIZE];
    //set IV and mode
    void *ptr;
    msghdr msg{};
    constexpr size_t type_cmsg_size = CMSG_SPACE(sizeof(uint32_t));
    constexpr size_t iv_cmsg_size = CMSG_SPACE(sizeof(af_alg_iv) + sizeof IV);

    msg.msg_controllen = type_cmsg_size + iv_cmsg_size;
    char *control_ptr = new char[msg.msg_controllen] {};
    msg.msg_control = control_ptr;
    msg.msg_iov = NULL;
    msg.msg_iovlen = 0;

    cmsghdr *header = CMSG_FIRSTHDR(&msg);
    header->cmsg_level = SOL_ALG;
    header->cmsg_type = ALG_SET_OP;
    header->cmsg_len = CMSG_LEN(sizeof(uint32_t));
    ptr = CMSG_DATA(header);
    *(uint32_t *)ptr = ALG_OP_ENCRYPT;

    header = CMSG_NXTHDR(&msg, header);
    header->cmsg_level = SOL_ALG;
    header->cmsg_type = ALG_SET_IV;
    header->cmsg_len = CMSG_LEN(sizeof(af_alg_iv) + sizeof IV);
    ptr = CMSG_DATA(header);
    static_cast<af_alg_iv *>(ptr)->ivlen = sizeof IV;
    memcpy(static_cast<af_alg_iv *>(ptr)->iv, IV, sizeof IV);
    int status = sendmsg(ciphersocket, &msg, MSG_MORE);
    if (status == -1)
        throw std::system_error(errno, std::system_category(),"control message not send");

    iovec iov;
    iov.iov_base = (void *)in_buf;
    iov.iov_len = BUF_SIZE;
    msg.msg_controllen = 0;
    msg.msg_control = NULL;
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_name = NULL;
    msg.msg_namelen = 0;
    msg.msg_flags = 0;
    while (source) {
        //read data portion from file
        source.read( (char*)in_buf, BUF_SIZE);
        len = source.gcount();
        if (len == 0)
            break;
        if (source.peek() != EOF)
            pad = MSG_MORE;
        else
            pad = 0;
        iov.iov_len = len;
        if (len % BLOCK_LEN !=0)
              iov.iov_len += BLOCK_LEN - len % BLOCK_LEN; 
         
        //encrypt data portion
        status = sendmsg(ciphersocket, &msg, pad );
        if (status == -1)
            throw std::system_error(errno, std::system_category(),"block not send to encrypt");
        status = read(ciphersocket, out_buf, status);
        if (status == -1)
            throw std::system_error(errno, std::system_category(),"block not receive from encrypting");
        //write data portion to file
        destination.write((char*)out_buf, status);
    }

}


void FileCipher::decrypt(const std::string& source_file, const std::string& destination_file)
{
    //open files
    std::ifstream source;
    source.exceptions(std::ifstream::failbit | std::ifstream::badbit);
    source.open(source_file);
    source.exceptions(std::ifstream::goodbit );
    std::ofstream destination;
    destination.exceptions(std::ifstream::failbit | std::ifstream::badbit);
    destination.open(destination_file);
    destination.exceptions(std::ifstream::goodbit );
    int len,pad;
    unsigned char* in_buf = new unsigned char[BUF_SIZE];
    unsigned char* out_buf = new unsigned char[BUF_SIZE];
    //set IV and mode
    void *ptr;
    msghdr msg{};
    constexpr size_t type_cmsg_size = CMSG_SPACE(sizeof(uint32_t));
    constexpr size_t iv_cmsg_size = CMSG_SPACE(sizeof(af_alg_iv) + sizeof IV);

    msg.msg_controllen = type_cmsg_size + iv_cmsg_size;
    char *control_ptr = new char[msg.msg_controllen] {};
    msg.msg_control = control_ptr;
    msg.msg_iov = NULL;
    msg.msg_iovlen = 0;

    cmsghdr *header = CMSG_FIRSTHDR(&msg);
    header->cmsg_level = SOL_ALG;
    header->cmsg_type = ALG_SET_OP;
    header->cmsg_len = CMSG_LEN(sizeof(uint32_t));
    ptr = CMSG_DATA(header);
    *(uint32_t *)ptr = ALG_OP_DECRYPT;

    header = CMSG_NXTHDR(&msg, header);
    header->cmsg_level = SOL_ALG;
    header->cmsg_type = ALG_SET_IV;
    header->cmsg_len = CMSG_LEN(sizeof(af_alg_iv) + sizeof IV);
    ptr = CMSG_DATA(header);
    static_cast<af_alg_iv *>(ptr)->ivlen = sizeof IV;
    memcpy(static_cast<af_alg_iv *>(ptr)->iv, IV, sizeof IV);
    int status = sendmsg(ciphersocket, &msg, MSG_MORE);
    if (status == -1)
        throw std::system_error(errno, std::system_category(),"control message not send");

    iovec iov;
    iov.iov_base = (void *)in_buf;
    iov.iov_len = BUF_SIZE;
    msg.msg_controllen = 0;
    msg.msg_control = NULL;
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_name = NULL;
    msg.msg_namelen = 0;
    msg.msg_flags = 0;
    while (source) {
        //read data portion from file
        source.read( (char*)in_buf, BUF_SIZE);
        len = source.gcount();
        if (len == 0)
            break;
        if (source.peek() != EOF)
            pad = MSG_MORE;
        else
            pad = 0;
        iov.iov_len = len;
 
        //encrypt data portion
        status = sendmsg(ciphersocket, &msg, pad );
        if (status == -1)
            throw std::system_error(errno, std::system_category(),"block not send to decrypt");
        status = read(ciphersocket, out_buf, len);
        if (status == -1)
            throw std::system_error(errno, std::system_category(),"block not receive from decrypting");
        //write data portion to file
        destination.write((char*)out_buf, len);
    }

}
