#pragma once
#include <iostream>
#include <vector>
#include <string>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/core_names.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/pem.h>
#include <openssl/provider.h>
#include <openssl/rsa.h>
#include <openssl/err.h>
#include <openssl/kdf.h>
#include <openssl/sha.h>
#include <cppcodec/base64_rfc4648.hpp>

#include <sstream>

#define SIZE_OF_KEYS 64
#define NUM_OF_ITERATIONS 1000
#define RSA_KEY_SIZE 2048
#define RSA_PUBLIC_EXPONENT 65537
#define AMOUNT_OF_BYTES_IN_INT 4
#define OAEP_PADDING_OVERHEAD 42
#define NUM_BITS_IN_BYTE 8
#define START_UPPER_CASE_LETTER 'A'
#define END_UPPER_CASE_LETTER 'Z'
#define START_LOWER_CASE_LETTER 'a'
#define END_LOWER_CASE_LETTER 'z'
#define START_NUM_CHARACTERS '0'
#define END_NUM_CHARACTERS '9'
#define PLUS_CHARACTER '+'
#define FORWARDSLASH_CHARACTER '/'



typedef std::vector<unsigned char> buffer;

class Encryption
{
public:
	static void generate_keypair(std::string& public_key, std::string& private_key);
	static void rsa_encryption(std::string& encryption_key, std::vector<unsigned char>& data, std::vector<unsigned char>& output);
	static void rsa_decryption(std::string& decryption_key, std::vector<unsigned char>& data, std::vector<unsigned char>& output);
	static void derive_keys_from_srp_data(const std::string& srp_group, const std::string& username, const std::string& salt, const std::string& verifier, std::string& encryption_key, std::string& decryption_key);
	static std::vector<unsigned char> base64_decode(const std::string& input);

	static std::string format_key_string(const std::string& key_str);

private:
	static bool is_base64_character(char c);
};