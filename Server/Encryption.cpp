#include "Encryption.h"

/*
 * The function generates a RSA key pair (public and private keys).
 * input:
 * none
 * output:
 * std::string& public_key - the generated public key
 * std::string& private_key - the generated private key
 */
void Encryption::generate_keypair(std::string& public_key, std::string& private_key)
{

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (!ctx) {
        std::cerr << "Error creating EVP_PKEY_CTX" << std::endl;
        return;
    }

    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        std::cerr << "Error initializing keygen" << std::endl;
        return;
    }

    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, RSA_KEY_SIZE) <= 0) {
        std::cerr << "Error setting keygen bits" << std::endl;
        return;
    }

    EVP_PKEY* pkey = NULL;
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        std::cerr << "Error generating key pair" << std::endl;
        return;
    }

    BIO* public_bio = BIO_new(BIO_s_mem());
    BIO* private_bio = BIO_new(BIO_s_mem());

    PEM_write_bio_PUBKEY(public_bio, pkey);
    PEM_write_bio_PrivateKey(private_bio, pkey, NULL, NULL, 0, NULL, NULL);

    char* pub_key_data = NULL;
    long pub_key_len = BIO_get_mem_data(public_bio, &pub_key_data);
    public_key.assign(pub_key_data, pub_key_len);

    char* priv_key_data = NULL;
    long priv_key_len = BIO_get_mem_data(private_bio, &priv_key_data);
    private_key.assign(priv_key_data, priv_key_len);

    EVP_PKEY_free(pkey);
    BIO_free_all(public_bio);
    BIO_free_all(private_bio);
    EVP_PKEY_CTX_free(ctx);
}

/*
 * The function encrypts the input data using the provided public key.
 * input:
 * std::string& encryption_key - the public key for encryption
 * std::vector<unsigned int>& data - the input data to be encrypted
 * output:
 * std::vector<unsigned int>& output - the encrypted output data
 */
void Encryption::rsa_encryption(std::string& encryption_key, std::vector<unsigned char>& data, std::vector<unsigned char>& output)
{
    constexpr int OAEP_PADDING_SIZE = OAEP_PADDING_OVERHEAD;
    std::vector<unsigned char> key_buffer(encryption_key.begin(), encryption_key.end());
    BIO* public_bio = BIO_new_mem_buf(key_buffer.data(), static_cast<int>(key_buffer.size()));

    EVP_PKEY* public_key = PEM_read_bio_PUBKEY(public_bio, NULL, NULL, NULL);
    if (public_key == NULL) {
        std::cerr << "Error loading public key" << std::endl;
        BIO_free(public_bio);
        return;
    }
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_PKEY_CTX* pkey_ctx = EVP_PKEY_CTX_new(public_key, NULL);

    EVP_PKEY_encrypt_init(pkey_ctx);
    EVP_PKEY_CTX_set_rsa_padding(pkey_ctx, RSA_PKCS1_OAEP_PADDING);

    const size_t max_chunk_size = (EVP_PKEY_size(public_key) * NUM_BITS_IN_BYTE) / NUM_BITS_IN_BYTE - OAEP_PADDING_SIZE;
    size_t data_size = data.size();
    size_t position = 0;

    while (position < data_size) {
        size_t chunk_size = std::min(max_chunk_size, data_size - position);
        size_t outlen = EVP_PKEY_size(public_key);
        std::vector<unsigned char> encrypted_chunk(outlen); // Allocate memory using the key size in bytes

        EVP_PKEY_encrypt(pkey_ctx, encrypted_chunk.data(), &outlen, data.data() + position, chunk_size);
        encrypted_chunk.resize(outlen); // Resize the vector based on the actual output size

        output.insert(output.end(), encrypted_chunk.begin(), encrypted_chunk.end());
        position += chunk_size;
    }

    EVP_PKEY_free(public_key);
    BIO_free(public_bio);
    EVP_PKEY_CTX_free(pkey_ctx);
    EVP_CIPHER_CTX_free(ctx);
}

/*
 * The function decrypts the input data using the provided private key.
 * input:
 * std::string& decryption_key - the private key for decryption
 * std::vector<unsigned int>& data - the input data to be decrypted
 * output:
 * std::vector<unsigned int>& output - the decrypted output data
 */
void Encryption::rsa_decryption(std::string& decryption_key, std::vector<unsigned char>& data, std::vector<unsigned char>& output)
{
    std::vector<unsigned char> key_buffer(decryption_key.begin(), decryption_key.end());
    BIO* private_bio = BIO_new_mem_buf(key_buffer.data(), static_cast<int>(key_buffer.size()));

    EVP_PKEY* private_key = PEM_read_bio_PrivateKey(private_bio, NULL, NULL, NULL);
    if (private_key == NULL) {
        std::cerr << "Error loading private key" << std::endl;
        BIO_free(private_bio);
        return;
    }

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_PKEY_CTX* pkey_ctx = EVP_PKEY_CTX_new(private_key, NULL);

    EVP_PKEY_decrypt_init(pkey_ctx);
    EVP_PKEY_CTX_set_rsa_padding(pkey_ctx, RSA_PKCS1_OAEP_PADDING);

    const size_t max_chunk_size = EVP_PKEY_size(private_key);
    size_t data_size = data.size();
    size_t position = 0;

    while (position < data_size) {
        size_t outlen = max_chunk_size;
        std::vector<unsigned char> decrypted_chunk(outlen);

        EVP_PKEY_decrypt(pkey_ctx, decrypted_chunk.data(), &outlen, data.data() + position, max_chunk_size);
        decrypted_chunk.resize(outlen); // Resize the vector based on the actual output size

        output.insert(output.end(), decrypted_chunk.begin(), decrypted_chunk.end());
        position += max_chunk_size;
    }

    EVP_PKEY_free(private_key);
    BIO_free(private_bio);
    EVP_PKEY_CTX_free(pkey_ctx);
    EVP_CIPHER_CTX_free(ctx);
}


void Encryption::derive_keys_from_srp_data(const std::string& srp_group, const std::string& username, const std::string& salt, const std::string& verifier, std::string& encryption_key, std::string& decryption_key)
{
    static EVP_PKEY* evp_pkey = nullptr;
    static bool initialized = false;

    if (!initialized) {
        initialized = true;

        BIGNUM* bn_e = BN_new();
        BN_set_word(bn_e, RSA_F4);

        EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
        if (ctx == nullptr) {
            BN_free(bn_e);
            return;
        }

        unsigned long e = BN_get_word(bn_e);
        OSSL_PARAM params[] = {
            OSSL_PARAM_construct_ulong(OSSL_PKEY_PARAM_RSA_E, &e),
            OSSL_PARAM_END
        };

        if (EVP_PKEY_keygen_init(ctx) <= 0 ||
            EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) <= 0 ||
            EVP_PKEY_CTX_set_params(ctx, params) <= 0 ||
            EVP_PKEY_keygen(ctx, &evp_pkey) <= 0) {
            EVP_PKEY_CTX_free(ctx);
            BN_free(bn_e);
            return;
        }

        BN_free(bn_e);
        EVP_PKEY_CTX_free(ctx);
    }

    std::string combined = srp_group + username + salt + verifier;

    // Calculate SHA256 hash
    unsigned char hash[SHA256_DIGEST_LENGTH];
    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(mdctx, EVP_sha256(), nullptr);
    EVP_DigestUpdate(mdctx, combined.c_str(), combined.size());
    EVP_DigestFinal_ex(mdctx, hash, nullptr);
    EVP_MD_CTX_free(mdctx);

    BIO* bio_public = BIO_new(BIO_s_mem());
    BIO* bio_private = BIO_new(BIO_s_mem());

    if (!PEM_write_bio_PUBKEY(bio_public, evp_pkey) ||
        !PEM_write_bio_PrivateKey(bio_private, evp_pkey, nullptr, nullptr, 0, nullptr, nullptr)) {
        BIO_free(bio_public);
        BIO_free(bio_private);
        return;
    }

    BUF_MEM* bio_public_buf;
    BUF_MEM* bio_private_buf;

    BIO_get_mem_ptr(bio_public, &bio_public_buf);
    BIO_get_mem_ptr(bio_private, &bio_private_buf);

    encryption_key.assign(bio_public_buf->data, bio_public_buf->length);
    decryption_key.assign(bio_private_buf->data, bio_private_buf->length);

    BIO_free(bio_public);
    BIO_free(bio_private);
}

std::vector<unsigned char> Encryption::base64_decode(const std::string& input)
{
    std::string cleaned_base64_string;
    cleaned_base64_string.reserve(input.size());

    for (char c : input)
    {
        if (is_base64_character(c)) {
            cleaned_base64_string.push_back(c);
        }
    }

    // Add padding back to the base64 string
    size_t padding_needed = 4 - (cleaned_base64_string.size() % 4);
    if (padding_needed < 4) {
        cleaned_base64_string.append(padding_needed, '=');
    }

    return cppcodec::base64_rfc4648::decode(cleaned_base64_string);
}


bool Encryption::is_base64_character(char c)
{
    return (c >= START_UPPER_CASE_LETTER && c <= END_UPPER_CASE_LETTER) || (c >= START_LOWER_CASE_LETTER && c <= END_LOWER_CASE_LETTER) ||
        (c >= START_NUM_CHARACTERS && c <= END_NUM_CHARACTERS) || c == PLUS_CHARACTER || c == FORWARDSLASH_CHARACTER;
}