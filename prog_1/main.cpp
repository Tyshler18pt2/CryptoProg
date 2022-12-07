#include <iostream>
#include <cstdlib>
#include <cstring>//line СИ
#include <unistd.h> // for close()
//#include
#include <netinet/in.h>// sock_addr_in and allthing function  for network
#include <arpa/inet.h>
#include <sstream>
#include <string>
using namespace std;
void errors(const char* why, const int exitCode = 1)
{
    cerr << why << endl;
    exit(exitCode);
}
int main(int argc, char** argv)
{

    // подготовка структуры с адресом нашей программы (клиента)
    sockaddr_in* selfAddr = new (sockaddr_in);
    selfAddr->sin_family = AF_INET; //интернет протокол IPv4
    selfAddr->sin_port = 0;         // при взаимодейстивии система сама выберет порт
    selfAddr->sin_addr.s_addr = 0;  // все адреса компьютера
    // для своего адреса ставим 0,чтобы система сама выбирала удобный ей адрес
    // подготовка структуры с адресом сервера
    sockaddr_in* remoteAddr = new (sockaddr_in);
    remoteAddr->sin_family = AF_INET;
    remoteAddr->sin_port = htons(7);
    remoteAddr->sin_addr.s_addr = inet_addr("95.83.72.118");//127.0.0.1

    // подготовка буфера для передачи и приема данных
    char* buf = new char[256];
    strcpy(buf, "How are you?");
    int msgLen = strlen(buf); // вычисление длины строки

    // создание сокета
    int mySocket = socket(AF_INET, SOCK_STREAM, 0); //TCP
    if (mySocket == -1) {
        errors("Error open socket", 11);
    }
    // привязка сокета к своему адресу
    int rc = bind(mySocket, (const sockaddr*)selfAddr, sizeof(sockaddr_in));
    if (rc == -1) {
        close(mySocket);
        errors("Error bind socket with local address", 12);
    }
    // установка соединение с сервером
    rc = connect(mySocket, (const sockaddr*)remoteAddr/*адрес*/, sizeof(sockaddr_in));
    if (rc == -1) {
        close(mySocket);
        errors("Error bind socket with remote address", 13);
    }
    // передача данных
    rc = send(mySocket, buf, msgLen, 0); // возвращает количестово переданных байтов
    if (rc == -1) {
        close(mySocket);
        errors("Error send message", 14);
    }
    cout << "We send: " << buf << endl;
    rc = recv(mySocket, buf, 256, 0);
    if (rc == -1) {
        close(mySocket);
        errors("Error recevie answer", 15);
    }
    buf[rc] = '\0';
    cout << "answer: " << buf << endl;
    // закрытие сокета
    close(mySocket);
    // освобождение памяти
    delete selfAddr;
    delete remoteAddr;
    delete[] buf;
    return 0;
}