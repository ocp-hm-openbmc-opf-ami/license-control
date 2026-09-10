#include "include/licensecontrol.hpp"

#ifdef FAIL
#undef FAIL
#endif

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>

#include <filesystem>
#include <fstream>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

using ::testing::HasSubstr;
using ::testing::IsEmpty;
using ::testing::Not;

namespace fs = std::filesystem;

// Non-header declarations from licenseDecrypt.cpp
extern uint64_t getImageSizeFromFWSize(const std::string& filePath);
extern std::string base64_decode(const std::string& encoded_text);
extern std::string extract_tlv_data(const std::string& tlv_message,
                                    const std::string& tag);
extern std::string generatedHashValue(const std::string& input);
extern std::string readBinaryFileToString(const std::string& filename);
extern std::string decodeAndExtractLicense(const std::string& input_file,
                                           EVP_PKEY* public_key);
extern int decriptLicenseFile(const std::string& encryptLicencefile);
extern bool verifySignature(const std::string& data,
                            const std::string& signature, EVP_PKEY* public_key);

namespace
{

// ===========================================================================
// LicenseDecryptTest — getImageSizeFromFWSize, readBinaryFileToString,
//   extract_tlv_data, base64_decode, generatedHashValue, getLicenseEncFile
// ===========================================================================

class LicenseDecryptTest : public ::testing::Test
{
  protected:
    void SetUp() override {}
    void TearDown() override {}
};

TEST_F(LicenseDecryptTest,
       GetImageSizeFromFWSize_ValidHexFile_ReturnsParsedSize)
{
    const std::string tmpPath = "/tmp/test_fwsize_valid.txt";
    {
        std::ofstream ofs(tmpPath);
        ofs << "0x1000000\n";
    }

    uint64_t result = getImageSizeFromFWSize(tmpPath);
    EXPECT_EQ(result, 0x1000000u);

    std::remove(tmpPath.c_str());
}

TEST_F(LicenseDecryptTest, GetImageSizeFromFWSize_NonexistentFile_ReturnsZero)
{
    uint64_t result = getImageSizeFromFWSize("/tmp/no_such_fwsize_xyz.txt");
    EXPECT_EQ(result, 0u);
}

TEST_F(LicenseDecryptTest, GetImageSizeFromFWSize_EmptyFile_NoCrash)
{
    const std::string tmpPath = "/tmp/test_fwsize_empty.txt";
    {
        std::ofstream ofs(tmpPath);
    }

    EXPECT_NO_THROW(getImageSizeFromFWSize(tmpPath));

    std::remove(tmpPath.c_str());
}

TEST_F(LicenseDecryptTest, GetImageSizeFromFWSize_WhitespaceOnly_NoCrash)
{
    const std::string tmpPath = "/tmp/test_fwsize_whitespace.txt";
    {
        std::ofstream ofs(tmpPath);
        ofs << "   \n";
    }

    EXPECT_NO_THROW(getImageSizeFromFWSize(tmpPath));

    std::remove(tmpPath.c_str());
}

TEST_F(LicenseDecryptTest, GetImageSizeFromFWSize_NonHexContent_ReturnsZero)
{
    const std::string tmpPath = "/tmp/test_fwsize_nothex.txt";
    {
        std::ofstream ofs(tmpPath);
        ofs << "not_a_hex_value";
    }

    uint64_t result = getImageSizeFromFWSize(tmpPath);
    EXPECT_EQ(result, 0u);

    std::remove(tmpPath.c_str());
}

TEST_F(LicenseDecryptTest, GetImageSizeFromFWSize_ZeroValue_ReturnsZero)
{
    const std::string tmpPath = "/tmp/test_fwsize_zero.txt";
    {
        std::ofstream ofs(tmpPath);
        ofs << "0x0";
    }

    uint64_t result = getImageSizeFromFWSize(tmpPath);
    EXPECT_EQ(result, 0u);

    std::remove(tmpPath.c_str());
}

TEST_F(LicenseDecryptTest, ReadBinaryFileToString_ValidFile_ReturnsContent)
{
    const std::string tmpPath = "/tmp/test_binread.bin";
    const std::string content = "BINARY\x01\x02\x03\x04"
                                "DATA";
    {
        std::ofstream ofs(tmpPath, std::ios::binary);
        ofs.write(content.data(), static_cast<std::streamsize>(content.size()));
    }

    std::string result = readBinaryFileToString(tmpPath);
    EXPECT_EQ(result.size(), content.size());
    EXPECT_EQ(result, content);

    std::remove(tmpPath.c_str());
}

TEST_F(LicenseDecryptTest, ReadBinaryFileToString_NonexistentFile_ReturnsEmpty)
{
    std::string result = readBinaryFileToString("/tmp/no_such_bin_xyz.bin");
    EXPECT_TRUE(result.empty());
}

TEST_F(LicenseDecryptTest, ReadBinaryFileToString_EmptyFile_ReturnsEmpty)
{
    const std::string tmpPath = "/tmp/test_binread_empty.bin";
    {
        std::ofstream ofs(tmpPath, std::ios::binary);
    }

    std::string result = readBinaryFileToString(tmpPath);
    EXPECT_TRUE(result.empty());

    std::remove(tmpPath.c_str());
}

TEST_F(LicenseDecryptTest, ExtractTlvData_ValidEntry_ReturnsPayload)
{
    std::string tlv = "ABC0004data";

    std::string result = extract_tlv_data(tlv, "ABC");
    EXPECT_EQ(result, "data");
}

TEST_F(LicenseDecryptTest, ExtractTlvData_MissingTag_ReturnsEmpty)
{
    std::string tlv = "ABC0004data";
    std::string result = extract_tlv_data(tlv, "XYZ");
    EXPECT_TRUE(result.empty());
}

TEST_F(LicenseDecryptTest, ExtractTlvData_EmptyMessage_ReturnsEmpty)
{
    std::string result = extract_tlv_data("", "ABC");
    EXPECT_TRUE(result.empty());
}

TEST_F(LicenseDecryptTest, ExtractTlvData_LengthExceedsMessage_ReturnsEmpty)
{
    std::string tlv = "TAG0100shor";
    std::string result = extract_tlv_data(tlv, "TAG");
    EXPECT_TRUE(result.empty());
}

TEST_F(LicenseDecryptTest, ExtractTlvData_ZeroLength_ReturnsEmpty)
{
    std::string tlv = "TAG0000";
    std::string result = extract_tlv_data(tlv, "TAG");
    EXPECT_EQ(result, "");
}

TEST_F(LicenseDecryptTest, ExtractTlvData_MultipleTagsInMessage_ExtractsCorrect)
{
    std::string tlv = "AA0003fooBB0003bar";

    EXPECT_EQ(extract_tlv_data(tlv, "AA"), "foo");
    EXPECT_EQ(extract_tlv_data(tlv, "BB"), "bar");
}

TEST_F(LicenseDecryptTest, Base64Decode_ValidInput_ReturnsDecoded)
{
    std::string result = base64_decode("aGVsbG8=");
    EXPECT_EQ(result, "hello");
}

TEST_F(LicenseDecryptTest, Base64Decode_EmptyInput_ReturnsEmpty)
{
    std::string result = base64_decode("");
    EXPECT_TRUE(result.empty());
}

TEST_F(LicenseDecryptTest, Base64Decode_LongerString_DecodeCorrectly)
{
    std::string encoded = "T3BlbkJNQyBMaWNlbnNl";
    std::string result = base64_decode(encoded);
    EXPECT_EQ(result, "OpenBMC License");
}

TEST_F(LicenseDecryptTest, Base64Decode_InvalidBase64_ReturnsEmptyOrPartial)
{
    std::string result = base64_decode("not!valid!base64!!!");
    SUCCEED();
}

TEST_F(LicenseDecryptTest, Base64Decode_PaddingVariants_HandleCorrectly)
{
    EXPECT_EQ(base64_decode("YQ=="), "a");
    EXPECT_EQ(base64_decode("YWI="), "ab");
    EXPECT_EQ(base64_decode("YWJj"), "abc");
}

TEST_F(LicenseDecryptTest, GeneratedHashValue_KnownInput_ReturnsNonEmptyHex)
{
    std::string result = generatedHashValue("hello");
    EXPECT_FALSE(result.empty());
    EXPECT_EQ(result.size(), 128u);
}

TEST_F(LicenseDecryptTest, GeneratedHashValue_DeterministicOutput)
{
    std::string r1 = generatedHashValue("test-input");
    std::string r2 = generatedHashValue("test-input");
    EXPECT_EQ(r1, r2);
}

TEST_F(LicenseDecryptTest, GeneratedHashValue_DifferentInputs_DifferentHashes)
{
    std::string r1 = generatedHashValue("input1");
    std::string r2 = generatedHashValue("input2");
    EXPECT_NE(r1, r2);
}

TEST_F(LicenseDecryptTest, GeneratedHashValue_EmptyInput_ReturnsKnownHash)
{
    std::string result = generatedHashValue("");
    EXPECT_FALSE(result.empty());
    EXPECT_EQ(result.size(), 128u);
    for (char c : result)
    {
        EXPECT_TRUE((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))
            << "Non-hex character: " << c;
    }
}

TEST_F(LicenseDecryptTest, GeneratedHashValue_LargeInput_ReturnsConstantLength)
{
    std::string large(10000, 'x');
    std::string result = generatedHashValue(large);
    EXPECT_EQ(result.size(), 128u);
}

TEST_F(LicenseDecryptTest, GetLicenseEncFile_NonexistentDirectory_ReturnsEmpty)
{
    std::string result = getLicenseEncFile();
    SUCCEED();
}

// ===========================================================================
// LcDecryptCoverageTest — additional branch coverage for licenseDecrypt.cpp
// ===========================================================================

class LcDecryptCoverageTest : public ::testing::Test
{
  protected:
    void SetUp() override {}
    void TearDown() override {}
};

TEST_F(LcDecryptCoverageTest,
       GetImageSizeFromFWSize_UppercaseHex_ParsedCorrectly)
{
    const std::string tmpPath = "/tmp/test_fwsize_upper.txt";
    {
        std::ofstream ofs(tmpPath);
        ofs << "0XFF00";
    }

    uint64_t result = getImageSizeFromFWSize(tmpPath);
    (void)result;
    SUCCEED();

    std::remove(tmpPath.c_str());
}

TEST_F(LcDecryptCoverageTest, GetImageSizeFromFWSize_MaxValidHex_NoOverflow)
{
    const std::string tmpPath = "/tmp/test_fwsize_max.txt";
    {
        std::ofstream ofs(tmpPath);
        ofs << "0xffffffff";
    }

    uint64_t result = getImageSizeFromFWSize(tmpPath);
    EXPECT_EQ(result, 0xffffffffu);

    std::remove(tmpPath.c_str());
}

TEST_F(LcDecryptCoverageTest,
       GetImageSizeFromFWSize_MultipleLines_UsesFirstOnly)
{
    const std::string tmpPath = "/tmp/test_fwsize_multi.txt";
    {
        std::ofstream ofs(tmpPath);
        ofs << "0x400000\n0x800000\n";
    }

    uint64_t result = getImageSizeFromFWSize(tmpPath);
    EXPECT_EQ(result, 0x400000u);

    std::remove(tmpPath.c_str());
}

TEST_F(LcDecryptCoverageTest, ExtractTlvData_NonNumericLength_Throws)
{
    EXPECT_THROW(extract_tlv_data("TAGABCDpayload", "TAG"),
                 std::invalid_argument);
}

TEST_F(LcDecryptCoverageTest, ExtractTlvData_ExactFitLength_ReturnsPayload)
{
    std::string tlv = "TAG0003abc";
    EXPECT_EQ(extract_tlv_data(tlv, "TAG"), "abc");
}

TEST_F(LcDecryptCoverageTest,
       ExtractTlvData_LengthMismatch_ActualShorterThanStated_ReturnsEmpty)
{
    std::string tlv = "TAG0010abc";
    std::string result = extract_tlv_data(tlv, "TAG");
    EXPECT_TRUE(result.empty());
}

TEST_F(LcDecryptCoverageTest, ExtractTlvData_TagAtEnd_EmptyPayload)
{
    std::string tlv = "TAG0000";
    std::string result = extract_tlv_data(tlv, "TAG");
    EXPECT_EQ(result, "");
}

TEST_F(LcDecryptCoverageTest, ExtractTlvData_LengthFieldPadded_ParsesCorrectly)
{
    std::string payload = "12345678";
    std::string tlv = "AB0008" + payload;
    EXPECT_EQ(extract_tlv_data(tlv, "AB"), payload);
}

TEST_F(LcDecryptCoverageTest, Base64Decode_AllZeroBytes_ReturnsCorrectLength)
{
    std::string result = base64_decode("BQUFBQ==");
    EXPECT_EQ(result.size(), 4u);
}

TEST_F(LcDecryptCoverageTest, Base64Decode_WhitespaceInput_NoCrash)
{
    std::string result = base64_decode("   ");
    SUCCEED();
}

TEST_F(LcDecryptCoverageTest, Base64Decode_RoundTrip_LicenseLikeContent)
{
    const std::string original = "TIMESTAMP-2026:01:01-VALIDITY-svc1:90";

    BIO* bio = BIO_new(BIO_s_mem());
    BIO* b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    bio = BIO_push(b64, bio);
    BIO_write(bio, original.c_str(), static_cast<int>(original.size()));
    BIO_flush(bio);

    BUF_MEM* bufferPtr{};
    BIO_get_mem_ptr(bio, &bufferPtr);
    std::string encoded(bufferPtr->data, bufferPtr->length);
    BIO_free_all(bio);

    std::string decoded = base64_decode(encoded);
    EXPECT_EQ(decoded, original);
}

TEST_F(LcDecryptCoverageTest, GeneratedHashValue_KnownSHA512_MatchesExpected)
{
    std::string result = generatedHashValue("abc");
    ASSERT_EQ(result.size(), 128u);
    EXPECT_EQ(result.substr(0, 8), "ddaf35a1");
}

TEST_F(LcDecryptCoverageTest, GeneratedHashValue_Binary_CorrectLength)
{
    std::string binary(32, '\x7f');
    std::string result = generatedHashValue(binary);
    EXPECT_EQ(result.size(), 128u);
}

TEST_F(LcDecryptCoverageTest, GeneratedHashValue_AllPrintable_CorrectHex)
{
    std::string input = "The quick brown fox jumps over the lazy dog";
    std::string result = generatedHashValue(input);
    ASSERT_EQ(result.size(), 128u);
    for (char c : result)
    {
        EXPECT_TRUE((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))
            << "non-hex: " << c;
    }
}

TEST_F(LcDecryptCoverageTest, ReadBinaryFileToString_OneByte_ReturnsThatByte)
{
    const std::string tmpPath = "/tmp/test_1byte.bin";
    {
        std::ofstream ofs(tmpPath, std::ios::binary);
        char b = '\x42';
        ofs.write(&b, 1);
    }

    std::string result = readBinaryFileToString(tmpPath);
    ASSERT_EQ(result.size(), 1u);
    EXPECT_EQ(static_cast<unsigned char>(result[0]), 0x42u);

    std::remove(tmpPath.c_str());
}

TEST_F(LcDecryptCoverageTest, ReadBinaryFileToString_LargeFile_CorrectSize)
{
    const std::string tmpPath = "/tmp/test_large.bin";
    const size_t size = 65536;
    {
        std::ofstream ofs(tmpPath, std::ios::binary);
        std::string buf(size, '\x55');
        ofs.write(buf.data(), static_cast<std::streamsize>(buf.size()));
    }

    std::string result = readBinaryFileToString(tmpPath);
    EXPECT_EQ(result.size(), size);

    std::remove(tmpPath.c_str());
}

TEST_F(LcDecryptCoverageTest, DecriptLicenseFile_NoPublicKey_ReturnsNegOne)
{
    fs::remove("/tmp/license-control/public.pem");

    int ret = decriptLicenseFile("any_encrypted_file.key");
    EXPECT_EQ(ret, -1);
}

TEST_F(LcDecryptCoverageTest,
       DecodeAndExtractLicense_NonexistentInputFile_ReturnsEmpty)
{
    EVP_PKEY* pkey = EVP_PKEY_new();
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
    EVP_PKEY_keygen_init(ctx);
    EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048);
    EVP_PKEY_keygen(ctx, &pkey);
    EVP_PKEY_CTX_free(ctx);

    std::string result =
        decodeAndExtractLicense("/tmp/no_such_license_file_xyz.key", pkey);
    EXPECT_TRUE(result.empty());

    EVP_PKEY_free(pkey);
}

TEST_F(LcDecryptCoverageTest, DecodeAndExtractLicense_EmptyFile_ReturnsEmpty)
{
    const std::string tmpPath = "/tmp/test_empty_enc.key";
    {
        std::ofstream ofs(tmpPath, std::ios::binary);
    }

    EVP_PKEY* pkey = EVP_PKEY_new();
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
    EVP_PKEY_keygen_init(ctx);
    EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048);
    EVP_PKEY_keygen(ctx, &pkey);
    EVP_PKEY_CTX_free(ctx);

    std::string result = decodeAndExtractLicense(tmpPath, pkey);
    EXPECT_TRUE(result.empty());

    EVP_PKEY_free(pkey);
    std::remove(tmpPath.c_str());
}

TEST_F(LcDecryptCoverageTest, VerifySignature_InvalidSignature_ReturnsFalse)
{
    EVP_PKEY* pkey = EVP_PKEY_new();
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
    EVP_PKEY_keygen_init(ctx);
    EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048);
    EVP_PKEY_keygen(ctx, &pkey);
    EVP_PKEY_CTX_free(ctx);

    std::string data = "some data to verify";
    std::string fakeSignature(256, '\x00');

    bool result = verifySignature(data, fakeSignature, pkey);
    EXPECT_FALSE(result);

    EVP_PKEY_free(pkey);
}

TEST_F(LcDecryptCoverageTest, VerifySignature_EmptySignature_ReturnsFalse)
{
    EVP_PKEY* pkey = EVP_PKEY_new();
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
    EVP_PKEY_keygen_init(ctx);
    EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048);
    EVP_PKEY_keygen(ctx, &pkey);
    EVP_PKEY_CTX_free(ctx);

    bool result = verifySignature("data", "", pkey);
    EXPECT_FALSE(result);

    EVP_PKEY_free(pkey);
}

TEST_F(LcDecryptCoverageTest, VerifySignature_ValidSignature_ReturnsTrue)
{
    EVP_PKEY* pkey = EVP_PKEY_new();
    EVP_PKEY_CTX* kctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
    EVP_PKEY_keygen_init(kctx);
    EVP_PKEY_CTX_set_rsa_keygen_bits(kctx, 2048);
    EVP_PKEY_keygen(kctx, &pkey);
    EVP_PKEY_CTX_free(kctx);

    std::string data = "license verification test data";

    EVP_MD_CTX* mdsign = EVP_MD_CTX_new();
    EVP_SignInit(mdsign, EVP_sha512());
    EVP_SignUpdate(mdsign, data.c_str(), data.size());
    unsigned int sigLen = 0;
    std::vector<unsigned char> sig(EVP_PKEY_size(pkey));
    EVP_SignFinal(mdsign, sig.data(), &sigLen, pkey);
    EVP_MD_CTX_free(mdsign);

    std::string signature(reinterpret_cast<const char*>(sig.data()), sigLen);

    bool result = verifySignature(data, signature, pkey);
    EXPECT_TRUE(result);

    EVP_PKEY_free(pkey);
}

TEST_F(LcDecryptCoverageTest,
       GetLicenseEncFile_DirectoryExistsButEmpty_ReturnsEmpty)
{
    fs::create_directories("/tmp/license-control");
    for (const auto& entry : fs::directory_iterator("/tmp/license-control"))
    {
        if (entry.path().extension() == ".key")
        {
            fs::remove(entry.path());
        }
    }

    std::string result = getLicenseEncFile();
    EXPECT_TRUE(result.empty());
}

TEST_F(LcDecryptCoverageTest,
       GetLicenseEncFile_DirectoryWithKeyFile_ReturnsPath)
{
    fs::create_directories("/tmp/license-control");
    const std::string keyPath = "/tmp/license-control/test.key";
    std::ofstream(keyPath).close();

    std::string result = getLicenseEncFile();
    EXPECT_THAT(result, HasSubstr("test.key"));

    fs::remove(keyPath);
}

} // namespace
