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

#include "filecrypt.h"
#include "pbkdf2.h"

#include <algorithm>
#include <functional>
#include <random>

using namespace filecrypt;

static size_t get_file_size(std::istream& is)
{
    is.seekg(0, std::ios::end);
    size_t msglen = is.tellg();
    is.seekg(0, std::ios::beg);

    return msglen;
}

static std::vector<uint8_t> get_random_bytes(size_t count)
{
    std::random_device rd;
    auto engine = std::mt19937(rd());
    auto dist = std::uniform_int_distribution<uint8_t>(0, 255);
    auto next_random_byte = std::bind(dist, engine);
    
    std::vector<uint8_t> result;
    for (auto i = 0; i < count; ++i) {
        result.push_back(next_random_byte());
    }

    return result;
}

FileCrypt::FileCrypt(const std::string& passphrase, const std::string& srcpath, const std::string& dstpath)
    : passphrase(passphrase), srcpath(srcpath), dstpath(dstpath), verified(1)
{
    cipher = EVP_aes_256_gcm();
    ctx = EVP_CIPHER_CTX_new();
}

FileCrypt::FileCrypt(const FileCrypt& other) : FileCrypt(other.passphrase, other.srcpath, other.dstpath)
{
}

void FileCrypt::open()
{
    ifs.open(srcpath, std::ios::binary);
    ofs.open(dstpath, std::ios::binary);

    if (ifs.good() == false) {
        throw std::string("file open failed: " + srcpath);
    }

    if (ofs.good() == false) {
        throw std::string("file creation failed: " + dstpath);
    }

    msglen = get_file_size(ifs);
}

void FileCrypt::close()
{
    ofs.close();
    ifs.close();

    if (verified == 0) {
        ofs.open(dstpath, std::ofstream::out | std::ofstream::trunc);
        ofs.close();
        throw std::string("tag mismatch");
    }
}

void FileCrypt::encrypt()
{
    open();
    init_encrypt();
    create_enc_ctx();
    process_encrypt();
    close();
}

void FileCrypt::init_encrypt()
{
    auto s = get_random_bytes(32);
    std::copy(s.begin(), s.end(), salt.begin());

    auto pbkdf2 = Pbkdf2();
    auto pair = pbkdf2.derive(passphrase, salt);
    this->key = pair.first;
    this->iv = pair.second;

    write(salt);
    write(iv);
}

void FileCrypt::create_enc_ctx()
{
    EVP_EncryptInit_ex(ctx, cipher, nullptr, nullptr, nullptr);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv.size(), nullptr);
    EVP_EncryptInit_ex(ctx, nullptr, nullptr, key.data(), iv.data());
}

void FileCrypt::process_encrypt()
{
    int len = 0;
    EVP_EncryptUpdate(ctx, nullptr, &len, salt.data(), salt.size());
    EVP_EncryptUpdate(ctx, nullptr, &len, iv.data(), iv.size());

    auto bytes_read = 0;
    while ((bytes_read = read(ibuf)) > 0) {
        EVP_EncryptUpdate(ctx, obuf.data(), &len, ibuf.data(), bytes_read);
        write(obuf, len);
    }

    EVP_EncryptFinal_ex(ctx, obuf.data(), &len);
    write(obuf, len);

    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, tag.size(), tag.data());
    write(tag);
}

void FileCrypt::decrypt()
{
    open();
    init_decrypt();
    create_dec_ctx();
    process_decrypt();
    close();
}

void FileCrypt::init_decrypt()
{
    msglen -= salt.size() + iv.size() + tag.size();

    read(salt);
    read(iv);

    auto pbkdf2 = Pbkdf2();
    auto pair = pbkdf2.derive(passphrase, salt);
    this->key = pair.first;

    if (std::equal(iv.begin(), iv.end(), pair.second.begin()) == false) {
        throw std::string("passphrase mismatch");
    }
}

void FileCrypt::create_dec_ctx()
{
    EVP_DecryptInit_ex(ctx, cipher, nullptr, nullptr, nullptr);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv.size(), nullptr);
    EVP_DecryptInit_ex(ctx, nullptr, nullptr, key.data(), iv.data());
}

void FileCrypt::process_decrypt()
{
    int len = 0;
    EVP_DecryptUpdate(ctx, nullptr, &len, salt.data(), salt.size());
    EVP_DecryptUpdate(ctx, nullptr, &len, iv.data(), iv.size());

    auto bytes_read = 0;
    while (msglen > 0) {
        auto chunksize = std::min(msglen, ibuf.size());
        bytes_read = read(ibuf, chunksize);
        EVP_DecryptUpdate(ctx, obuf.data(), &len, ibuf.data(), bytes_read);        
        write(obuf, len);
        msglen -= bytes_read;
    }

    read(tag);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, tag.size(), tag.data());

    verified = EVP_DecryptFinal_ex(ctx, obuf.data(), &len);
    ofs.write(reinterpret_cast<char*>(obuf.data()), len);
}