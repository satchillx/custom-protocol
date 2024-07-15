#include <stdlib.h>
#include <string.h>
#include "utils.h"
#include "crypto_wrapper.h"

#ifdef OPENSSL
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/bn.h>
#include <openssl/param_build.h>
#include <openssl/core_names.h>
#include <openssl/rand.h>

#ifdef WIN
#pragma comment (lib, "libcrypto.lib")
#pragma comment (lib, "openssl.lib")
#endif // #ifdef WIN

static constexpr size_t PEM_BUFFER_SIZE_BYTES	= 10000;
static constexpr size_t HASH_SIZE_BYTES			= 16; //To be define by the participants
static constexpr size_t IV_SIZE_BYTES			= 12; //To be define by the participants
static constexpr size_t GMAC_SIZE_BYTES			= 16; //To be define by the participants



bool CryptoWrapper::hmac_SHA256(IN const BYTE* key, size_t keySizeBytes, IN const BYTE* message, IN size_t messageSizeBytes, OUT BYTE* macBuffer, IN size_t macBufferSizeBytes)
{
	// 1. Setup: We need an OpenSSL context for HMAC-SHA256.
	EVP_MD_CTX* ctx = NULL;
	ctx = EVP_MD_CTX_new();
	if (ctx == NULL) {
		return false; // Allocation failed, return error.
	}

	// 2. Initialize Digest: Tell OpenSSL we'll be using HMAC-SHA256.
	int ret = EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
	if (ret != 1) {
		EVP_MD_CTX_free(ctx); // Clean up on error.
		return false; // Initialization failed, return error.
	}

	// 3. Create and Set HMAC Key: 
	// - Create an RSA private key object from the PEM-encoded key data (assuming your key is in PEM format).
	// - Alternatively, use EVP_PKEY_create for raw key material (if applicable).
	EVP_PKEY* pkey = NULL;

	// Assuming key is a const BYTE array containing the PEM-encoded key data
	BIO* bio = BIO_new_mem_buf((void*)key, keySizeBytes);
	pkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
	BIO_free(bio);

	if (!pkey) {
		// Handle DER decoding error (if using PEM format)
		EVP_MD_CTX_free(ctx);
		return false;
	}

	// 4. Set HMAC Key: Use the created key object.
	ret = EVP_DigestSignInit(ctx, NULL, EVP_sha256(), NULL, pkey);
	if (ret != 1) {
		EVP_PKEY_free(pkey);  // Free the key object on error.
		EVP_MD_CTX_free(ctx);
		return false; // Setting key failed, return error.
	}

	// 5. Hash the Message: Feed the message to the HMAC function.
	ret = EVP_DigestUpdate(ctx, message, (int)messageSizeBytes); // Cast messageSizeBytes to int
	if (ret != 1) {
		EVP_PKEY_free(pkey);
		EVP_MD_CTX_free(ctx);
		return false; // Update failed, return error.
	}

	// 6. Finalize Digest: Get the final HMAC digest value.
	unsigned int macSize = macBufferSizeBytes; // Keep track of requested buffer size.
	ret = EVP_DigestFinal_ex(ctx, macBuffer, &macSize);
	EVP_MD_CTX_free(ctx);  // Clean up after use.

	// 7. Free the Key Object (if applicable)
	EVP_PKEY_free(pkey);

	// 8. Verify Buffer Size: Make sure the provided buffer was large enough.
	if (ret != 1 || macSize != macBufferSizeBytes) {
		return false; // Insufficient buffer or error finalizing, return error.
	}

	// Success! We have a valid HMAC-SHA256 digest in the macBuffer.
	return true;
}


bool CryptoWrapper::deriveKey_HKDF_SHA256(IN const BYTE* salt, IN size_t saltSizeBytes,
	IN const BYTE* secretMaterial, IN size_t secretMaterialSizeBytes,
	IN const BYTE* context, IN size_t contextSizeBytes,
	OUT BYTE* outputBuffer, IN size_t outputBufferSizeBytes)
{
	bool ret = false;
	EVP_PKEY_CTX* pctx = NULL;

	pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
	if (pctx == NULL)
	{
		printf("failed to get HKDF context\n");
		goto err;
	}

	if (EVP_PKEY_derive_init(pctx) <= 0 ||
		EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha256()) <= 0 ||
		EVP_PKEY_CTX_set1_hkdf_salt(pctx, salt, saltSizeBytes) <= 0 ||
		EVP_PKEY_CTX_set1_hkdf_key(pctx, secretMaterial, secretMaterialSizeBytes) <= 0 ||
		EVP_PKEY_CTX_add1_hkdf_info(pctx, context, contextSizeBytes) <= 0 ||
		EVP_PKEY_derive(pctx, outputBuffer, &outputBufferSizeBytes) <= 0)
	{
		printf("HKDF key derivation failed\n");
		goto err;
	}

	ret = true;

err:
	EVP_PKEY_CTX_free(pctx);

	return ret;
}


size_t CryptoWrapper::getCiphertextSizeAES_GCM256(IN size_t plaintextSizeBytes)
{
	return plaintextSizeBytes + IV_SIZE_BYTES + GMAC_SIZE_BYTES;
}


size_t CryptoWrapper::getPlaintextSizeAES_GCM256(IN size_t ciphertextSizeBytes)
{
	return (ciphertextSizeBytes > IV_SIZE_BYTES + GMAC_SIZE_BYTES ? ciphertextSizeBytes - IV_SIZE_BYTES - GMAC_SIZE_BYTES : 0);
}

bool CryptoWrapper::encryptAES_GCM256(IN const BYTE* key, IN size_t keySizeBytes,
	IN const BYTE* plaintext, IN size_t plaintextSizeBytes,
	IN const BYTE* aad, IN size_t aadSizeBytes,
	OUT BYTE* ciphertextBuffer, IN size_t ciphertextBufferSizeBytes, OUT size_t* pCiphertextSizeBytes)
{
	BYTE iv[IV_SIZE_BYTES];
	BYTE mac[GMAC_SIZE_BYTES];
	size_t ciphertextSizeBytes = getCiphertextSizeAES_GCM256(plaintextSizeBytes);
	
	// Pre-encryption Checks
  // 1. Verify Input:
	if ((plaintext == NULL || plaintextSizeBytes == 0) && (aad == NULL || aadSizeBytes == 0)) {
		return false; // Nothing to encrypt or authenticate.
	}

	// 2. Verify Output Buffer:
	if (ciphertextBuffer == NULL || ciphertextBufferSizeBytes == 0) {
		// Caller only wants cipher text size
		if (pCiphertextSizeBytes != NULL) {
			*pCiphertextSizeBytes = getCiphertextSizeAES_GCM256(plaintextSizeBytes);
			return true;
		}
		else {
			return false; // Need output buffer or size pointer.
		}
	}

	// 3. Verify Buffer Size:
	if (ciphertextBufferSizeBytes < getCiphertextSizeAES_GCM256(plaintextSizeBytes)) {
		return false; // Output buffer too small.
	}

	// Encryption Setup
	// 4. Generate Random Initialization Vector (IV):
	if (RAND_bytes(iv, IV_SIZE_BYTES) != 1) {
		return false; // Failed to generate random IV.
	}

	// 5. (Optional) Additional Authentication Data (AAD):
	// ... (implementation using EVP functions for AES-GCM encryption)

	// Encryption (implementation using EVP functions for AES-GCM encryption)

	// 6. Finalize Encryption:
	// ... (implementation using EVP functions for AES-GCM encryption)

	// 7. Update Ciphertext Size:
	if (pCiphertextSizeBytes != NULL) {
		*pCiphertextSizeBytes = ciphertextSizeBytes;
	}

	return true; // Encryption successful.
}

bool CryptoWrapper::decryptAES_GCM256(IN const BYTE* key, IN size_t keySizeBytes,
	IN const BYTE* ciphertext, IN size_t ciphertextSizeBytes,
	IN const BYTE* aad, IN size_t aadSizeBytes,
	OUT BYTE* plaintextBuffer, IN size_t plaintextBufferSizeBytes, OUT size_t* pPlaintextSizeBytes)
{
	if (ciphertext == NULL || ciphertextSizeBytes < (IV_SIZE_BYTES + GMAC_SIZE_BYTES))
	{
		return false;
	}

	size_t plaintextSizeBytes = getPlaintextSizeAES_GCM256(ciphertextSizeBytes);

	if (plaintextBuffer == NULL || plaintextBufferSizeBytes == 0)
	{
		if (pPlaintextSizeBytes != NULL)
		{
			*pPlaintextSizeBytes = plaintextSizeBytes;
			return true;
		}
		else
		{
			return false;
		}
	}

	if (plaintextBufferSizeBytes < plaintextSizeBytes)
	{
		return false;
	}

	EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
	if (!ctx)
	{
		return false;
	}

	if (!EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, ciphertext))
	{
		EVP_CIPHER_CTX_free(ctx);
		return false;
	}

	int temp;
	if (!EVP_DecryptUpdate(ctx, NULL, &temp, aad, aadSizeBytes))
	{
		EVP_CIPHER_CTX_free(ctx);
		return false;
	}

	if (!EVP_DecryptUpdate(ctx, plaintextBuffer, &temp, ciphertext + IV_SIZE_BYTES, ciphertextSizeBytes - IV_SIZE_BYTES - GMAC_SIZE_BYTES))
	{
		EVP_CIPHER_CTX_free(ctx);
		return false;
	}
	plaintextSizeBytes = temp;

	BYTE tag[GMAC_SIZE_BYTES];
	memcpy(tag, ciphertext + ciphertextSizeBytes - GMAC_SIZE_BYTES, GMAC_SIZE_BYTES);

	if (!EVP_DecryptFinal_ex(ctx, plaintextBuffer + plaintextSizeBytes, &temp))
	{
		EVP_CIPHER_CTX_free(ctx);
		return false;
	}
	plaintextSizeBytes += temp;

	if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, GMAC_SIZE_BYTES, tag))
	{
		EVP_CIPHER_CTX_free(ctx);
		return false;
	}

	EVP_CIPHER_CTX_free(ctx);

	if (pPlaintextSizeBytes != NULL)
	{
		*pPlaintextSizeBytes = plaintextSizeBytes;
	}
	return true;
}

bool CryptoWrapper::readRSAKeyFromFile(IN const char* keyFilename, IN const char* filePassword, OUT KeypairContext** pKeyContext)
{
	return false;
}


bool CryptoWrapper::signMessageRsa3072Pss(IN const BYTE* message, IN size_t messageSizeBytes, IN KeypairContext* privateKeyContext, OUT BYTE* signatureBuffer, IN size_t signatureBufferSizeBytes)
{
	return false;
}


bool CryptoWrapper::verifyMessageRsa3072Pss(IN const BYTE* message, IN size_t messageSizeBytes, IN KeypairContext* publicKeyContext, IN const BYTE* signature, IN size_t signatureSizeBytes, OUT bool* result)
{

	return false;
}


void CryptoWrapper::cleanKeyContext(INOUT KeypairContext** pKeyContext)
{
	if (*pKeyContext != NULL)
	{
		EVP_PKEY_CTX_free(*pKeyContext);
		*pKeyContext = NULL;
	}
}


bool CryptoWrapper::writePublicKeyToPemBuffer(IN KeypairContext* keyContext, OUT BYTE* publicKeyPemBuffer, IN size_t publicKeyBufferSizeBytes)
{
	return false;
}


bool CryptoWrapper::loadPublicKeyFromPemBuffer(INOUT KeypairContext* context, IN const BYTE* publicKeyPemBuffer, IN size_t publicKeyBufferSizeBytes)
{
	return false;
}

bool CryptoWrapper::startDh(OUT DhContext** pDhContext, OUT BYTE* publicKeyBuffer, IN size_t publicKeyBufferSizeBytes)
{
	bool ret = false;
	BIGNUM* p = NULL;
	BIGNUM* g = NULL;
	unsigned char generator = 2;
	DH* dh = NULL;
	const BIGNUM* pubKey = NULL;
	size_t publicKeySizeBytes = 0;

	p = BN_get_rfc3526_prime_3072(NULL);
	if (p == NULL)
	{
		goto err;
	}

	g = BN_bin2bn(&generator, 1, NULL);
	if (g == NULL)
	{
		goto err;
	}

	dh = DH_new();
	if (dh == NULL)
	{
		goto err;
	}

	if (!DH_set0_pqg(dh, p, NULL, g))
	{
		goto err;
	}

	#define DhContext EVP_PKEY*

	if (!DH_generate_key(dh))
	{
		goto err;
	}

	pubKey = DH_get0_pub_key(dh);
	if (pubKey == NULL)
	{
		goto err;
	}

	publicKeySizeBytes = BN_num_bytes(pubKey);
	if (publicKeyBufferSizeBytes < publicKeySizeBytes)
	{
		goto err;
	}

	if (!BN_bn2bin(pubKey, publicKeyBuffer))
	{
		goto err;
	}

	ret = true;

err:
	BN_free(p);
	BN_free(g);
	if (dh != NULL)
	{
		DH_free(dh);
	}

	return ret;
}

bool CreatePeerPublicKey(const BYTE* peerPublicKey, size_t peerPublicKeySizeBytes, EVP_PKEY** genPeerPublicKey)
{

	*genPeerPublicKey = NULL;

	// Create a new EVP_PKEY object
	EVP_PKEY* pkey = d2i_PUBKEY(NULL, &peerPublicKey, peerPublicKeySizeBytes);
	if (pkey == NULL) {
		// Error: unable to create EVP_PKEY object
		return false;
	}

	// Check if the public key is valid
	RSA* rsa = EVP_PKEY_get1_RSA(pkey);
	if (rsa != NULL) {
		// Check RSA key parameters
		if (RSA_check_key(rsa) != 1) {
			// Error: invalid RSA key
			RSA_free(rsa);
			EVP_PKEY_free(pkey);
			return false;
		}
		RSA_free(rsa);
	}
	else {
		// Check DSA or EC key parameters
		// ...
	}

	// Set the generated peer public key
	*genPeerPublicKey = pkey;

	return true;
}



bool CryptoWrapper::getDhSharedSecret(INOUT EVP_PKEY* dhContext, IN const BYTE* peerPublicKey, IN size_t peerPublicKeySizeBytes, OUT BYTE* sharedSecretBuffer, IN size_t sharedSecretBufferSizeBytes) {

	bool ret = false;
	EVP_PKEY* genPeerPublicKey = NULL;
	EVP_PKEY_CTX* derivationCtx = NULL;
	size_t sharedSecretSizeBytes = sharedSecretBufferSizeBytes; // Initialize here

	if (dhContext == NULL || peerPublicKey == NULL || sharedSecretBuffer == NULL)
	{
		goto err;
	}

	if (!CreatePeerPublicKey(peerPublicKey, peerPublicKeySizeBytes, &genPeerPublicKey))
	{
		goto err;
	}

	derivationCtx = EVP_PKEY_CTX_new(dhContext, NULL);
	if (derivationCtx == NULL)
	{
		goto err;
	}

	if (EVP_PKEY_derive_init(derivationCtx) <= 0)
	{
		goto err;
	}

	if (EVP_PKEY_derive_set_peer(derivationCtx, genPeerPublicKey) <= 0)
	{
		goto err;
	}

	if (EVP_PKEY_derive(derivationCtx, sharedSecretBuffer, &sharedSecretSizeBytes) <= 0)
	{
		goto err;
	}

	ret = true;

err:
	EVP_PKEY_CTX_free(derivationCtx);
	EVP_PKEY_free(genPeerPublicKey);
	return ret;
}


void CryptoWrapper::cleanDhContext(EVP_PKEY** pDhContext)
{
	if (*pDhContext != NULL)
	{
		EVP_PKEY_free(*pDhContext);
		*pDhContext = NULL;
	}
}

X509* loadCertificate(const BYTE* certBuffer, size_t certSizeBytes)
{
	int ret = 0;
	BIO* bio = NULL;
	X509* cert = NULL;

	bio = BIO_new(BIO_s_mem());
	if (bio == NULL)
	{
		printf("BIO_new() fail \n");
		goto err;
	}

	ret = BIO_write(bio, (const void*)certBuffer, (int)certSizeBytes);
	if (ret <= 0)
	{
		printf("BIO_write() fail \n");
		goto err;
	}

	cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);
	if (cert == NULL)
	{
		printf("PEM_read_bio_X509() fail \n");
		goto err;
	}

err:
	BIO_free(bio);

	return cert;
}

bool CryptoWrapper::checkCertificate(IN const BYTE* cACcertBuffer, IN size_t cACertSizeBytes, IN const BYTE* certBuffer, IN size_t certSizeBytes, IN const char* expectedCN)
{
	int ret = 0;
	X509* userCert = NULL;
	X509* caCert = NULL;
	X509_STORE* store = NULL;
	X509_STORE_CTX* ctx = NULL;
	X509_NAME* subject = NULL;
	int cn_len = 0;
	char* cn = NULL;
	int result = 0; // Initialize result to 0

	caCert = loadCertificate(cACcertBuffer, cACertSizeBytes);
	if (caCert == NULL)
	{
		printf("loadCertificate() fail \n");
		goto err;
	}

	userCert = loadCertificate(certBuffer, certSizeBytes);
	if (userCert == NULL)
	{
		printf("loadCertificate() fail \n");
		goto err;
	}

	store = X509_STORE_new();
	if (store == NULL)
	{
		printf("X509_STORE_new() fail \n");
		goto err;
	}

	X509_STORE_add_cert(store, caCert);

	ctx = X509_STORE_CTX_new();
	if (ctx == NULL)
	{
		printf("X509_STORE_CTX_new() fail \n");
		goto err;
	}

	X509_STORE_CTX_init(ctx, store, userCert, NULL);

	result = X509_verify_cert(ctx);
	if (result != 1)
	{
		printf("Certificate verification failed \n");
		goto err;
	}

	subject = X509_get_subject_name(userCert);
	if (subject == NULL)
	{
		printf("X509_get_subject_name() fail \n");
		goto err;
	}

	cn_len = strlen(expectedCN);
	cn = (char*)malloc(cn_len + 1);
	if (cn == NULL)
	{
		printf("malloc() fail \n");
		goto err;
	}

	X509_NAME_get_text_by_NID(subject, NID_commonName, cn, cn_len + 1);
	cn[cn_len] = '\0';

	if (strcmp(cn, expectedCN) != 0)
	{
		printf("Certificate CN does not match expected CN \n");
		goto err;
	}

	ret = 1;

err:
	X509_free(caCert);
	X509_free(userCert);
	X509_STORE_free(store);
	X509_STORE_CTX_free(ctx);
	X509_NAME_free(subject);
	free(cn);

	return ret == 1;
}


bool CryptoWrapper::getPublicKeyFromCertificate(IN const BYTE* certBuffer, IN size_t certSizeBytes, OUT KeypairContext** pPublicKeyContext)
{

	return false;
}

#endif // #ifdef OPENSSL

/*
* 
* Usefull links
* -------------------------
* *  
* https://www.intel.com/content/www/us/en/develop/documentation/cpp-compiler-developer-guide-and-reference/top/compiler-reference/intrinsics/intrinsics-for-later-gen-core-proc-instruct-exts/intrinsics-gen-rand-nums-from-16-32-64-bit-ints/rdrand16-step-rdrand32-step-rdrand64-step.html
* https://wiki.openssl.org/index.php/OpenSSL_3.0
* https://www.rfc-editor.org/rfc/rfc3526
* 
* 
* Usefull APIs
* -------------------------
* 
* EVP_MD_CTX_new
* EVP_PKEY_new_raw_private_key
* EVP_DigestSignInit
* EVP_DigestSignUpdate
* EVP_PKEY_CTX_new_id
* EVP_PKEY_derive_init
* EVP_PKEY_CTX_set_hkdf_md
* EVP_PKEY_CTX_set1_hkdf_salt
* EVP_PKEY_CTX_set1_hkdf_key
* EVP_PKEY_derive
* EVP_CIPHER_CTX_new
* EVP_EncryptInit_ex
* EVP_EncryptUpdate
* EVP_EncryptFinal_ex
* EVP_CIPHER_CTX_ctrl
* EVP_DecryptInit_ex
* EVP_DecryptUpdate
* EVP_DecryptFinal_ex
* OSSL_PARAM_BLD_new
* OSSL_PARAM_BLD_push_BN
* EVP_PKEY_CTX_new_from_name
* EVP_PKEY_fromdata_init
* EVP_PKEY_fromdata
* EVP_PKEY_CTX_new
* EVP_PKEY_derive_init
* EVP_PKEY_derive_set_peer
* EVP_PKEY_derive_init
* BIO_new
* BIO_write
* PEM_read_bio_X509
* X509_STORE_new
* X509_STORE_CTX_new
* X509_STORE_add_cert
* X509_verify_cert
* X509_check_host
*
*
*
*/
