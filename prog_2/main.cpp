#include <iostream>
#include <iomanip>
#include "cipher.h"
int main(int argc, char **argv)
{

    const std::string orig_file("file.original");
    const std::string encr_file("file.encrypted");
    const std::string decr_file("file.decrypted");

    std::ofstream original (orig_file);
    for(int i=0; i<1; i++)
        original<<"My name is Gustavo, but u call me Stas"<<std::endl;
    original.close();

    std::string psw = "dorogoy";

    FileCipher cipher(psw, Cipher::CBC_AES);
    cipher.encrypt(orig_file, encr_file);
    cipher.decrypt(encr_file, decr_file);

    std::string input_value;
    std::cout<<"Used algoruthm: "<<cipher.name()<<std::endl;
    
    std::cout<<"\nOriginal message "<<orig_file<<":\n";
    std::ifstream f(orig_file);
    getline(f,input_value);
    f.close();
    std::cout << input_value <<std::endl;
    
    std::cout<<"\nEncrypted message "<<encr_file<<":";
    f.open(encr_file, std::ios::binary | std::ios::in);
    std::cout<<std::hex<<std::setfill('0');
    int i = 0;
    while (true) {
        unsigned c = f.get();
        if (f.eof())
            break;
        if (i % 16 == 0)
            std::cout<<std::endl;
        else if (i % 8  == 0)
            std::cout<<' ';
        std::cout<<std::setw(2)<<c<<' ';
        i++;
    }
    f.close();
    
    std::cout<<"\n\nDecrypted message "<<decr_file<<":\n";
    f.open(decr_file);
    getline(f,input_value);
    f.close();
    std::cout << input_value <<std::endl;

}
