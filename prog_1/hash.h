/** @file hash.h
 *  @author Лупанов М.Ю.
 *  @version 1.0
 *  @date 15.05.2020
 *  @copyright ИБСТ ПГУ
 *  @warning Это учебный пример
 *  @brief Классы для использования хэш-функций CryptoAPI ядра Linux
 */
#pragma once
#include <iostream>
#include <fstream>
#include <string>
#include <map>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <linux/if_alg.h>

#define ALG_MD5 "md5"               
#define ALG_MD4 "md4"
#define ALG_SHA1 "sha1"
#define ALG_SHA224 "sha224"
#define ALG_SHA256 "sha256"
#define ALG_SHA384 "sha384"
#define ALG_SHA512 "sha512"
#define ALG_HMAC_SHA1 "hmac(sha1)"
#define ALG_HMAC_SHA256 "hmac(sha256)"

/**
 @brief Абстрактый базовый класс для работы с хэш-функциями
 @warning Может быть использован только как базовый класс.
*/ 
class Hash
{
public:
/** 
 @brief Набор идентификаторов поддерживаемых алгоритмов хэширования.
 @details Алгоритмы MD4, MD5, SHA1, SHA224, SHA256, SHA384 и SHA512 являются
 простыми алгоритмами хэширования, требуют на вход только хэшируемые данные.
 Алгоритмы HMAC_SHA1 и HMAC_SHA256 - алгоритмы хэширования с ключем, 
 требуют на вход ключ и хэшируемые данные.
*/  
    enum HashAlg {MD4,MD5,SHA1,SHA224,SHA256,SHA384,SHA512,HMAC_SHA1,HMAC_SHA256};
protected:
/** 
 @brief Ассоциативный массив, связывающий идентификаторы алгоритмов с их строковым представлением, 
 требуемым при вызове API-функций.
*/ 
    std::map<int, const char *> AlgList{
        std::pair<int, const char *>(MD5, ALG_MD5),
        std::pair<int, const char *>(MD4, ALG_MD4),
        std::pair<int, const char *>(SHA1, ALG_SHA1),
        std::pair<int, const char *>(SHA224, ALG_SHA224),
        std::pair<int, const char *>(SHA256, ALG_SHA256),
        std::pair<int, const char *>(SHA384, ALG_SHA384),
        std::pair<int, const char *>(SHA512, ALG_SHA512),
        std::pair<int, const char *>(HMAC_SHA1, ALG_HMAC_SHA1),
        std::pair<int, const char *>(HMAC_SHA256, ALG_HMAC_SHA256)};
    static constexpr int BUF_SIZE = 1024 * 4;   ///< размер рабочего буфера 4К, константа
    unsigned char *buf;                         ///< указатель на рабочий буфер
    int cryptosocket;                           ///< сокет для связи с CryptoAPI
    int hashsocket;                             ///< сокет для связи с функцией хэширования
    ssize_t len;                                ///< переменная для хранения размера данных
    HashAlg _alg;                               ///< идентификатор используемого алгоритма       
    
/** 
 @brief Вычисление хэш-функции. Абстрактный метод.  
 @param [in] data Входные данные, задают источник данных для хэширования
 @warning Должен быть перегружен в производном классе
*/
    virtual void calcHash(const std::string data) = 0;

/** 
 @brief Завершение хэш-функции.
 @details Получает из ядра Linux накопленное значение хэш-функции и 
 сохраняет его во внутреннем буфере Hash::buf
 @throw std::system_error в случае ошибки при получении хэша из ядра. 
 Параметры исключения:
 @code 
 code = errno, what = 'Error get hash value'
 @endcode
*/
    void finishHash();
    
/** 
 @brief Перевод в строку.
 @details Преобразовывает значение вычисленной хэш-функции, находящейся в Hash::buf, 
 в шестнадцатеричное представление в виде строки. 
 @return Строка std::string со значением хэш-функции в hex-формате
*/    
    std::string toString();

public:

/** 
 @brief Конструктор для хэш-функции без ключа.
 @param [in] alg Идентификатор алгоритма хэширования
 @throw std::system_error Ошибка при инициализации работы с функцией хэширования. 
 Параметры исключения:
 @code 
 code = errno, what = 'Error open crypto socket' 
                      'Error bind cryptosocket' 
                      'Error accept to hashsocket'
 @endcode 
*/
    Hash(HashAlg alg = MD5);

/** 
 @brief Конструктор для хэш-функции c ключом.
 @param [in] password Пароль (ключ) для хэширования
 @param [in] alg Идентификатор алгоритма хэширования
 @throw std::system_error Ошибка при инициализации работы с функцией хэширования. 
 Параметры исключения:
 @code 
 code = errno, what = 'Error open crypto socket' 
                      'Error bind cryptosocket' 
                      'Error accept to hashsocket'
                      'Error set password'
 @endcode 
*/
    Hash(std::string password, HashAlg alg = HMAC_SHA1);
    
/// @brief Деструктор.    
    virtual ~Hash();
    
/** 
 @brief Оператор вызова функции. Вычисляет хэш.
 @details Перегруженный оператор вызова функции вычисляет хэш-функцию от переданных данных и 
 возвращает его значение в виде строки с шестнадцатеричным представлением.
 Реализован в виде последовательного вызова методов Hash::calcHash, Hash::finishHash и Hash::toString
 @code
std::string Hash::operator()(const std::string& data)
{
    calcHash(data);
    finishHash();
    return toString();
}
 @endcode 
 @param [in] data Данные для хэширования, std::string.
 @return Строка std::string со значением хэш-функции в hex-формате
 @throw std::system_error в случае ошибки при вычислении хэша. 
 @code 
 code = errno, what = 'Error evaluate hash data'
                      'Error get hash value'
 @endcode
*/
    std::string operator()(const std::string& data);

/** @brief Имя алгоритма.
 @details Возвращает имя используемого алгоритма хэширования
 @return Срока std::string с именем алгоритма
*/
    std::string name() {
        return AlgList[_alg];
    }
};

/**
 @brief Класс для вычисления хэш-функции от строки
 @details Пример использования класса для вычисления хэша без ключа
 @code
StringHash hash(Hash::SHA1);
std::string demo("hello, world");
std::cout << "Hash "<<hash.name() <<" from string \'"<<demo<<"\' is\n";
std::cout << hash(demo) << std::endl;
 @endcode
 И пример использования класса для вычисления хэша с ключом (паролем)
 @code
std::string psw("SuperPa$$w0rd");
StringHash hmac(psw, Hash::HMAC_SHA256);
std::string salt("qaMr4Gm3");
std::cout << "Hash "<<hmac.name() <<" from string \'"<<salt<<"\' on password \'"<<psw<<"\' is\n";
std::cout << hmac(salt) << std::endl; 
 @endcode
*/ 
class StringHash : public Hash
{
private:
/** 
 @brief Вычисление хэш-функции.  
 @param [in] data Строка std::string, для которой вычисляется хэш
 @throw std::system_error в случае ошибки при вычислении хэша.
 Параметры исключения:
 @code 
 code = errno, what = 'Error evaluate hash data'
 @endcode
*/
    virtual void calcHash(const std::string data);

public:
/** 
 @brief Конструктор для хэш-функции без ключа.
 @param [in] alg Идентификатор алгоритма хэширования
 @throw std::system_error Ошибка при инициализации работы с функцией хэширования. 
 Параметры исключения:
 @code 
 code = errno, what = 'Error open crypto socket' 
                      'Error bind cryptosocket' 
                      'Error accept to hashsocket'
                      'Error set password'
 @endcode 
*/
    StringHash(HashAlg alg = MD5) : Hash(alg) {}
/** 
 @brief Конструктор для хэш-функции c ключом.
 @param [in] password Пароль (ключ) для хэширования
 @param [in] alg Идентификатор алгоритма хэширования
 @throw std::system_error Ошибка при инициализации работы с функцией хэширования. 
 Параметры исключения:
 @code 
 code = errno, what = 'Error open crypto socket' 
                      'Error bind cryptosocket' 
                      'Error accept to hashsocket'
 @endcode 
*/
    StringHash(std::string password, HashAlg alg = HMAC_SHA1) : Hash(password, alg) {}

};

/**
 @brief Класс для вычисления хэш-функции от файла
 @details Пример использования класса
 @code
FileHash fhash(Hash::SHA224);
std::string fname(argv[0]);
std::cout << "Hash "<<fhash.name() <<" from file \'"<<fname<<"\' is\n";
std::cout << fhash(fname) << std::endl;
@endcode
*/ 
class FileHash : public Hash
{
private:
/** 
 @brief Вычисление хэш-функции.  
 @param [in] data Строка std::string c именем файла, для которого вычисляется хэш
 @throw std::system_error в случае ошибки при вычислении хэша. 
 Параметры исключения:
 @code 
 code = errno, what = 'Error evaluate hash data'
 @endcode
*/
    virtual void calcHash(const std::string data);

public:
/** 
 @brief Конструктор для хэш-функции без ключа.
 @param [in] alg Идентификатор алгоритма хэширования
 @throw std::system_error Ошибка при инициализации работы с функцией хэширования. 
 Параметры исключения:
 @code
 code = errno, what = 'Error open crypto socket' 
                      'Error bind cryptosocket'
                      'Error accept to hashsocket'
 @endcode 
*/
    FileHash(HashAlg alg = MD5) : Hash(alg) {}

};
