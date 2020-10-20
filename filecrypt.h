/**
 * The MIT License
 *
 * Copyright (c) 2020 Ilwoong Jeong (https://github.com/ilwoong)
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#ifndef __FILECRYPT_FILECRYPT_H__

#include <array>
#include <cstdint>
#include <fstream>
#include <string>

#include <openssl/evp.h>

#include "datatypes.h"

namespace filecrypt {
    
    class FileCrypt {
    private:
        size_t msglen; 

        std::string passphrase;
        std::string srcpath;
        std::string dstpath;

        std::ifstream ifs;
        std::ofstream ofs;

        buffer_t ibuf;
        buffer_t obuf;

        array256_t salt;
        array256_t key;
        array128_t iv;
        array128_t tag;
        
        int verified;
        const EVP_CIPHER* cipher;
        EVP_CIPHER_CTX* ctx;

    public:
        FileCrypt(const std::string& passphrase, const std::string& srcpath, const std::string& dstPath);        
        FileCrypt(const FileCrypt& other);
        ~FileCrypt() = default;

        void encrypt();
        void decrypt();

    private:
        void open();
        void close();

        void init_encrypt();
        void create_enc_ctx();
        void process_encrypt();

        void init_decrypt();
        void create_dec_ctx();
        void process_decrypt();

        template<size_t N>
        inline size_t read(std::array<uint8_t, N>& data, size_t count)
        {
            return ifs.read(reinterpret_cast<char*>(data.data()), count).gcount();
        }

        template<size_t N>
        inline size_t read(std::array<uint8_t, N>& data) 
        {
            return read(data, N);
        }

        template<size_t N>
        inline void write(std::array<uint8_t, N>& data, size_t count)
        {
            ofs.write(reinterpret_cast<char*>(data.data()), count);
        }

        template<size_t N>
        inline void write(std::array<uint8_t, N>& data)
        {
            write(data, N);
        }
    };
}

#endif