#include <system_error>
#include <cstring>
#include "hash.h"


//////////////////////// Hash //////////////////////////////////////////////////

Hash::Hash(HashAlg alg) : buf(new unsigned char[BUF_SIZE]), _alg(alg)
{
    cryptosocket = socket(AF_ALG, SOCK_SEQPACKET, 0);
    if (cryptosocket == -1)
        throw std::system_error(errno, std::system_category(), "Error open crypto socket");

    sockaddr_alg sa = {};
    sa.salg_family = AF_ALG;
    strcpy((char *)sa.salg_type, "hash");
    strcpy((char *)sa.salg_name, AlgList[_alg]);

    int status = bind(cryptosocket, (sockaddr *)&sa, sizeof sa);
    if (status == -1)
        throw std::system_error(errno, std::system_category(), "Error bind cryptosocket");

    hashsocket = accept(cryptosocket, nullptr, 0);
    if (hashsocket == -1)
        throw std::system_error(errno, std::system_category(), "Error accept to hashsocket");
}

Hash::Hash(std::string password, HashAlg alg):Hash(alg)
{
    int ret = setsockopt(cryptosocket, SOL_ALG, ALG_SET_KEY, password.data(), password.size());
    if (ret == -1)
        throw std::system_error(errno, std::system_category(), "Error set password");
}

Hash::~Hash()
{
    delete[] buf;
    close(hashsocket);
    close(cryptosocket);
}


void Hash::finishHash()
{
    len = recv(hashsocket, buf, BUF_SIZE, 0);
    if (len == -1)
        throw std::system_error(errno, std::system_category(), "Error get hash value");
}

std::string Hash::toString()
{
    const char HEX_DIG[16] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
    //convert hash to string
    std::string HashStr;
    for (unsigned int i = 0; i < len; i++)
    {
        HashStr.push_back(HEX_DIG[buf[i] >> 4]);  //high forth bits
        HashStr.push_back(HEX_DIG[buf[i] & 0xf]); //low forth bits
    }
    return HashStr;
}

std::string Hash::operator()(const std::string& data)
{
    calcHash(data);
    finishHash();
    return toString();
}

//////////////////////// StringHash ////////////////////////////////////////////

void StringHash::calcHash(const std::string data)
{
    //calc hash of
    len = send(hashsocket, data.c_str(), data.size(), 0);
    if (len == -1) //calc hash for data portion
        throw std::system_error(errno, std::system_category(), "Error evaluate hash data");
}

//////////////////////// FileHash ////////////////////////////////////////////

void FileHash::calcHash(const std::string data)
{
//open file
    std::ifstream f;
    f.exceptions(std::ifstream::failbit | std::ifstream::badbit);
    f.open(data, std::ios::binary);
    f.exceptions(std::ifstream::goodbit );

//calc hash of file
    while (f) {
        f.read( (char*)buf, BUF_SIZE);              //read data portion from file
        len = f.gcount();
        int last = MSG_MORE;
        if (f.peek() == EOF)
            last = 0;
        int status = send(hashsocket, buf, len, last);
        if (status == -1)    //calc hash for data portion
            throw  std::system_error(errno, std::system_category(), "Error evaluate hash data");
    }
}
