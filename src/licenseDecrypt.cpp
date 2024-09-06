
/*****************************************************************
 * License control Manager
 * licenseDecrypt.cpp
 *
 * @brief D-Bus service designed to manage and monitor the usage of
 * licensed resources the system, ensuring limitations and oversight
 * are maintained.
 *
 * Author: Manikandan.V manikandanv@ami.com
 *
 ******************************************************************/

#include <fstream>
#include <include/licensecontrol.hpp>
#include <iostream>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <regex>
#include <string>
#include <vector>
#define LC_PK_IDENTIFIER "$SHPKIDF$"
#define LC_PK_OFFSET 0x2000
#define LC_PK_SIZE 10
#define erase_blk_size 0x10000
#define tlvMsgBaseDelimiter "$+"
#define tlvMsgHashDelimiter "$-"
#define tlvMsgSignDelimiter "$*"
#define TLV_LENGTH_BYTES 4
#define SHA_ALGORITHM EVP_sha512()

namespace fs = std::filesystem;

std::string getLicenseEncFile() {

  std::string uploadedKeyFileName = "";
  std::string directoryPath = UPLOADED_NEWKEYPATH;

  // User uploades the new key via Web interface, only if the key is valied
  // directry is created.
  if (!fs::is_directory(directoryPath)) {
    std::cerr << "Error: Directory " << directoryPath << " does not exist."
              << std::endl;
    return "";
  }

  for (const auto &entry : fs::directory_iterator(directoryPath)) {
    if (entry.is_regular_file() &&
        entry.path().extension() == UPLOADED_KEY_FILEFORMAT) {
      uploadedKeyFileName = entry.path().filename().string();
      break;
    }
  }

  if (uploadedKeyFileName.empty()) {
    std::cerr << "Error: File format " << UPLOADED_KEY_FILEFORMAT
              << " not found in specified directory." << directoryPath
              << std::endl;
    return "";
  }

  return directoryPath + uploadedKeyFileName;
}

uint64_t getImageSizeFromFWSize(const std::string &filePath = "/etc/FWSize") {
  std::ifstream file(filePath);
  if (!file.is_open()) {
    std::cerr << "Error: Could not open file " << filePath << std::endl;
    return 0;
  }

  std::string hexValue;
  std::getline(file, hexValue);
  file.close();

  uint64_t imageSize;
  std::istringstream(hexValue) >> std::hex >> imageSize;

  return imageSize;
}

int getPublicKey() {
  int MTDDevId = 0;
  char pub_key_identifier[LC_PK_SIZE] = {0};
  char pub_key_length[4] = {0};
  int offset = 0;
  unsigned char *OneEBlock = nullptr;
  uint64_t Image_size = getImageSizeFromFWSize();

  if (Image_size == 0) {
    std::cerr << "Error in getting Image Size" << std::endl;
    return -1;
  }

  OneEBlock = (unsigned char *)malloc(erase_blk_size);
  if (OneEBlock == nullptr) {
    std::cout << "Memory allocation error\n";
    return -1;
  }

  MTDDevId = open("/dev/mtd0", O_RDONLY);

  if (MTDDevId < 0) {
    std::cout << "Cannot open mtd raw device MTDDev. Exiting...\n";
    if (OneEBlock != nullptr) {
      free(OneEBlock);
      OneEBlock = nullptr;
    }
    return -1;
  }

  if (lseek(MTDDevId, (Image_size - erase_blk_size), SEEK_SET) == -1) {

    std::cout << "lseek MTDDevId error\n";
    if (MTDDevId >= 0) {
      close(MTDDevId);
      MTDDevId = -1;
    }
    if (OneEBlock != nullptr) {
      free(OneEBlock);
      OneEBlock = nullptr;
    }
    return -1;
  }

  int ret_read = read(MTDDevId, OneEBlock, erase_blk_size);

  if (ret_read != erase_blk_size) {
    std::cout << "read MTDDevId error\n";
    if (MTDDevId >= 0) {
      close(MTDDevId);
      MTDDevId = -1;
    }
    if (OneEBlock != nullptr) {
      free(OneEBlock);
      OneEBlock = nullptr;
    }
    return -1;
  }

  offset = erase_blk_size - LC_PK_OFFSET;

  DEBUG(std::cout << "offset: " << std::hex << offset << std::endl;);

  memcpy(pub_key_identifier, OneEBlock + offset, sizeof(LC_PK_IDENTIFIER));

  DEBUG(std::cout << "pub_key_identifier: " << pub_key_identifier
                  << "\nLC_PK_IDENTIFIER: " << LC_PK_IDENTIFIER << std::endl;);
  if (strncmp(pub_key_identifier, LC_PK_IDENTIFIER, sizeof(LC_PK_IDENTIFIER)) !=
      0) {

    std::cout << "public key not found\n";
    if (MTDDevId >= 0) {
      close(MTDDevId);
      MTDDevId = -1;
    }
    if (OneEBlock != nullptr) {
      free(OneEBlock);
      OneEBlock = nullptr;
    }
    return -1;
  }

  offset += sizeof(LC_PK_IDENTIFIER);
  DEBUG(std::cout << "offset: " << std::hex << offset << std::endl;);

  memcpy(&pub_key_length, OneEBlock + offset, sizeof(int));

  offset += sizeof(int);
  DEBUG(std::cout << "offset: " << std::hex << offset << std::endl;);
  if (std::stoi(pub_key_length) > 512) {

    if (MTDDevId >= 0) {
      close(MTDDevId);
      MTDDevId = -1;
    }
    if (OneEBlock != nullptr) {
      free(OneEBlock);
      OneEBlock = nullptr;
    }
    return -1;
  }

  std::string public_key(reinterpret_cast<const char *>(OneEBlock + offset),
                         std::stoi(pub_key_length));

  std::ofstream publicFile(licensePublicKey);

  if (!publicFile.is_open()) {
    std::cerr << "Error: Unable to open file " << licensePublicKey << std::endl;
    if (MTDDevId >= 0) {
      close(MTDDevId);
      MTDDevId = -1;
    }
    if (OneEBlock != nullptr) {
      free(OneEBlock);
      OneEBlock = nullptr;
    }
    return -1;
  }

  publicFile << public_key;

  publicFile.close();
  if (MTDDevId >= 0) {
    close(MTDDevId);
    MTDDevId = -1;
  }
  if (OneEBlock != nullptr) {
    free(OneEBlock);
    OneEBlock = nullptr;
  }
  return 0;
}

std::string base64_decode(const std::string &encoded_text) {

  OpenSSL_add_all_algorithms();
  ERR_load_crypto_strings();

  BIO *bio, *b64;
  bio = BIO_new_mem_buf(encoded_text.c_str(), -1);
  b64 = BIO_new(BIO_f_base64());
  BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
  bio = BIO_push(b64, bio);

  std::vector<char> buffer(encoded_text.size());
  int decoded_length = BIO_read(bio, buffer.data(), buffer.size());

  if (decoded_length < 0) {
    std::cerr << "Error in base64 decoding" << std::endl;
    ERR_print_errors_fp(stderr);
    BIO_free_all(bio);
    return "";
  }

  BIO_free_all(bio);

  return std::string(buffer.data(), decoded_length);
}

std::string extract_tlv_data(const std::string &tlv_message,
                             const std::string &tag) {
  size_t tag_pos = tlv_message.find(tag);
  if (tag_pos == std::string::npos) {
    std::cerr << "Error Missing Delimiter Tag in the token provided"
              << std::endl;
    return "";
  }

  size_t length_pos = tag_pos + tag.length();
  std::string length_str = tlv_message.substr(length_pos, TLV_LENGTH_BYTES);
  std::string::size_type length = std::stoi(length_str);

  size_t data_pos = length_pos + TLV_LENGTH_BYTES;

  // Ensure validity of data length
  if (data_pos + length > tlv_message.length()) {
    std::cerr << "Integrity Error: Invalid data length" << std::endl;
    return "";
  }

  std::string data = tlv_message.substr(data_pos, length);

  // Check if the extracted data length matches the actual length provided.
  if (data.length() != length) {
    std::cerr << "Integrity Error: Invalid data length, unauthorized changes"
              << std::endl;
    return "";
  }

  return data;
}

std::string generatedHashValue(const std::string &input) {
  unsigned char hash[SHA512_DIGEST_LENGTH];
  unsigned int hashLen = 0;

  EVP_MD_CTX *mdCtx = EVP_MD_CTX_new();
  if (!mdCtx) {
    std::cerr << "Error: Unable to create message digest context" << std::endl;
    return "";
  }

  if (EVP_DigestInit(mdCtx, SHA_ALGORITHM) != 1) {
    EVP_MD_CTX_free(mdCtx);
    std::cerr << "Error: Unable to initialize message digest operation"
              << std::endl;
    return "";
  }

  if (EVP_DigestUpdate(mdCtx, input.c_str(), input.length()) != 1) {
    EVP_MD_CTX_free(mdCtx);
    std::cerr << "Error: Unable to provide data to message digest operation"
              << std::endl;
    return "";
  }

  if (EVP_DigestFinal(mdCtx, hash, &hashLen) != 1) {
    EVP_MD_CTX_free(mdCtx);
    std::cerr << "Error: Unable to finalize message digest operation"
              << std::endl;
    return "";
  }

  EVP_MD_CTX_free(mdCtx);

  std::stringstream hashedValue;
  for (int i = 0; i < SHA512_DIGEST_LENGTH; i++) {
    hashedValue << std::hex << std::setw(2) << std::setfill('0')
                << static_cast<int>(hash[i]);
  }

  return hashedValue.str();
}

bool verifySignature(const std::string &data, const std::string &signature,
                     EVP_PKEY *public_key) {
  int result = false;

  EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
  if (mdctx == NULL) {
    std::cerr << "Error: Unable to create message digest context" << std::endl;
    return false;
  }

  result = EVP_VerifyInit_ex(mdctx, SHA_ALGORITHM, NULL);
  if (result != 1) {
    std::cerr << "Error: Unable to initialize verification operation"
              << std::endl;
    EVP_MD_CTX_free(mdctx);
    return false;
  }

  result = EVP_VerifyUpdate(mdctx, data.c_str(), data.size());
  if (result != 1) {
    std::cerr << "Error: Unable to provide data to verification operation"
              << std::endl;
    EVP_MD_CTX_free(mdctx);
    return false;
  }

  result = EVP_VerifyFinal(
      mdctx, reinterpret_cast<const unsigned char *>(signature.c_str()),
      signature.size(), public_key);
  if (result != 1) {
    std::cerr << "Error: Signature verification process" << std::endl;
    EVP_MD_CTX_free(mdctx);
    return false;
  }

  EVP_MD_CTX_free(mdctx);

  return true;
}

std::string readBinaryFileToString(const std::string &filename) {
  std::ifstream file(filename, std::ios::binary | std::ios::ate);
  if (!file.is_open()) {
    std::cerr << "Error opening file: " << filename << std::endl;
    return "";
  }

  std::ifstream::pos_type fileSize = file.tellg();
  if (fileSize < 0) {
    std::cerr << "Error determining file size: " << filename << std::endl;
    file.close();
    return "";
  }

  file.seekg(0, std::ios::beg);

  std::string buffer(fileSize, '\0');
  file.read(&buffer[0], fileSize);

  if (!file) {
    std::cerr << "Error reading file: " << filename << std::endl;
    file.close();
    return "";
  }

  file.close();

  return buffer;
}

std::string decodeAndExtractLicense(const std::string &input_file,
                                    EVP_PKEY *public_key) {
  std::string generated_hash{}, tlv_message{}, base64_encode{}, hash_data{};
  std::string signature{}, token{}, message_data{};

  std::ifstream file(input_file, std::ios::binary | std::ios::ate);
  if (!file.is_open()) {
    std::cerr << "Error opening file: " << input_file << std::endl;
    return "";
  }

  tlv_message = readBinaryFileToString(input_file);
  if (tlv_message.empty()) {
    std::cerr << "Error reading file: " << input_file << std::endl;
    return "";
  }

  base64_encode = extract_tlv_data(tlv_message, tlvMsgBaseDelimiter);
  if (base64_encode.empty()) {
    std::cerr << "Error extracting TLV data base64_encode " << std::endl;
  }
  hash_data = extract_tlv_data(tlv_message, tlvMsgHashDelimiter);
  if (hash_data.empty()) {
    std::cerr << "Error extracting TLV data hash_data " << std::endl;
  }
  signature = extract_tlv_data(tlv_message, tlvMsgSignDelimiter);
  if (signature.empty()) {
    std::cerr << "Error extracting TLV data signature " << std::endl;
  }

  token = base64_decode(base64_encode);

  DEBUG(std::cout << "Encoded Data: " << token << std::endl;);
  DEBUG(std::cout << "Hash Data: " << hash_data << std::endl;);

  message_data = base64_encode + hash_data;

  // Authenticity check
  if (!verifySignature(message_data, signature, public_key)) {
    std::cerr << "Signature verification failed!" << std::endl;
    return "";
  }

  // Integrity check
  generated_hash = generatedHashValue(token);
  if (generated_hash.empty()) {
    std::cerr << "Error: Unable to generate hash" << std::endl;
  } else if (generated_hash == hash_data) {
    DEBUG(std::cout << "Hashes match.." << std::endl;);
  } else {
    std::cerr << "Hashes do not match..!" << std::endl;
  }

  return token;
}

int decriptLicenseFile(const std::string &encryptLicencefile) {
  FILE *pubKeyFile = fopen(licensePublicKey.c_str(), "r");
  if (!pubKeyFile) {
    std::cerr << "Error opening public key file." << std::endl;
    return -1;
  }

  EVP_PKEY *publickey = PEM_read_PUBKEY(pubKeyFile, NULL, NULL, NULL);
  fclose(pubKeyFile);

  if (!publickey) {
    std::cerr << "Error reading public key." << std::endl;
    return -1;
  }

  std::string token = decodeAndExtractLicense(encryptLicencefile, publickey);

  std::ofstream newLicenseToken(newLicenseValidityTokenPath);

  if (!newLicenseToken.is_open()) {
    std::cerr << "Error: Unable to open file " << newLicenseValidityTokenPath
              << std::endl;
    EVP_PKEY_free(publickey);
    return -1;
  }

  if (token.empty()) {
    std::cout << "unable to Extract the license" << std::endl;
    newLicenseToken.close();
    EVP_PKEY_free(publickey);
    return -1;
  }

  newLicenseToken << token;

  newLicenseToken.close();

  EVP_PKEY_free(publickey);

  return 0;
}
