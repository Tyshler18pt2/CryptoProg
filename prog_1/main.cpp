include <iostream>
#include "hash.h"
int main(int argc, char **argv)
{
    StringHash hash(Hash::SHA1);
    std::string demo("My name is Gustavo, but u call me Stas");
    std::cout << "Hash "<<hash.name() <<" from string \'"<<demo<<"\' is\n";
    std::cout << hash(demo) << std::endl;

    std::string psw("dorogoy");
    StringHash hmac(psw, Hash::HMAC_SHA256);
    std::string salt("qaMr4Gm3");
    std::cout << "Hash "<<hmac.name() <<" from string \'"<<salt<<"\' on password \'"<<psw<<"\' is\n";
    std::cout << hmac(salt) << std::endl;

    FileHash fhash(Hash::SHA224);
    std::string fname(argv[0]);
    std::cout << "Hash "<<fhash.name() <<" from file \'"<<fname<<"\' is\n";
    std::cout << fhash(fname) << std::endl;
}
