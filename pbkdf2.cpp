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

#include "pbkdf2.h"

#include <vector>

#include <openssl/evp.h>

using namespace filecrypt;

Pbkdf2::Pbkdf2() : iterations(2020)
{}

Pbkdf2::Pbkdf2(const Pbkdf2& other) : iterations(other.iterations)
{}

key_iv_pair_t Pbkdf2::derive(const std::string& passphrase, const array256_t& salt)
{
    array256_t key;
    array128_t iv;

    auto md = EVP_sha256();
    auto derived = std::vector<uint8_t>(key.size() + iv.size());
    PKCS5_PBKDF2_HMAC(passphrase.data(), passphrase.size(), salt.data(), salt.size(), iterations, md, derived.size(), derived.data());

    std::copy(derived.begin(), derived.begin() + key.size(), key.data());
    std::copy(derived.begin() + key.size(), derived.end(), iv.data());

    return std::make_pair<>(key, iv);
}