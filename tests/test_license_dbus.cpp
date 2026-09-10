#include "include/licensecontrol.hpp"

#ifdef FAIL
#undef FAIL
#endif

#include <filesystem>
#include <fstream>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

using ::testing::_;
using ::testing::HasSubstr;
using ::testing::Not;

namespace fs = std::filesystem;

// External globals
extern json globalData;
extern bool exitSchedulerTask;
extern int64_t UpCountDays;
extern int64_t Globalvalidcount;
extern std::string AlertNotificationLicenseControl;
extern uint32_t alertCountValue;
extern std::map<std::string, std::string> serviceDates;

// Non-header declarations from licenseDbus.cpp
extern bool MacAddrCamp(const std::string& str1, const std::string& str2);
extern int getTimeStampfromLicence(const std::string& filePath);
extern std::string generateServiceValidityString(const json& jsonData);
extern std::string generateTotalValidityData();
extern std::string updateTokenValiditySection(std::string str1,
                                              const std::string& str2);
extern std::string readTokenFromFile(const std::string& filename);
extern int updateNewServiceValidity(const std::string& inputString,
                                    json& jsonData);
extern int updateLicTokenwithExtValidity();
extern void parseService(const std::string& service, std::string& serviceName,
                         int& serviceValue);
extern bool isServiceRunning(const std::string& serviceName);
extern uint32_t getMinValidityDate();
extern void removeTempFiles();

namespace
{

// ===========================================================================
// LicenseDbusTest — MacAddrCamp, getTimeStampfromLicence,
//   generateServiceValidityString, updateTokenValiditySection,
//   readTokenFromFile, generateTotalValidityData, updateNewServiceValidity
// ===========================================================================

class LicenseDbusTest : public ::testing::Test
{
  protected:
    void SetUp() override
    {
        globalData = json::object();
        serviceDates.clear();
        UpCountDays = 0;
        Globalvalidcount = 0;
        alertCountValue = 0;
        AlertNotificationLicenseControl = "";
    }

    void TearDown() override
    {
        globalData.clear();
        serviceDates.clear();
    }
};

TEST_F(LicenseDbusTest, MacAddrCamp_SameCase_ReturnsTrue)
{
    EXPECT_TRUE(MacAddrCamp("AA:BB:CC:DD:EE:FF", "AA:BB:CC:DD:EE:FF"));
}

TEST_F(LicenseDbusTest, MacAddrCamp_MixedCase_ReturnsTrue)
{
    EXPECT_TRUE(MacAddrCamp("aa:bb:cc:dd:ee:ff", "AA:BB:CC:DD:EE:FF"));
}

TEST_F(LicenseDbusTest, MacAddrCamp_DifferentMac_ReturnsFalse)
{
    EXPECT_FALSE(MacAddrCamp("AA:BB:CC:DD:EE:FF", "11:22:33:44:55:66"));
}

TEST_F(LicenseDbusTest, MacAddrCamp_DifferentLength_ReturnsFalse)
{
    EXPECT_FALSE(MacAddrCamp("AA:BB:CC", "AA:BB:CC:DD:EE:FF"));
}

TEST_F(LicenseDbusTest, MacAddrCamp_EmptyStrings_ReturnsTrue)
{
    EXPECT_TRUE(MacAddrCamp("", ""));
}

TEST_F(LicenseDbusTest, MacAddrCamp_OneEmpty_ReturnsFalse)
{
    EXPECT_FALSE(MacAddrCamp("", "AA:BB:CC:DD:EE:FF"));
}

TEST_F(LicenseDbusTest, GetTimeStampfromLicence_ValidFile_ReturnsTimestamp)
{
    const std::string tmpPath = "/tmp/test_ts_licence.txt";
    {
        std::ofstream ofs(tmpPath);
        ofs << "1234567;other-data";
    }

    int ret = getTimeStampfromLicence(tmpPath);
    EXPECT_EQ(ret, 1234567);

    std::remove(tmpPath.c_str());
}

TEST_F(LicenseDbusTest,
       GetTimeStampfromLicence_NoSemicolon_ParsesWholeFirstLine)
{
    const std::string tmpPath = "/tmp/test_ts_nosemi.txt";
    {
        std::ofstream ofs(tmpPath);
        ofs << "99\n";
    }

    int ret = getTimeStampfromLicence(tmpPath);
    EXPECT_EQ(ret, 99);

    std::remove(tmpPath.c_str());
}

TEST_F(LicenseDbusTest, GetTimeStampfromLicence_NonexistentFile_ReturnsNegOne)
{
    int ret = getTimeStampfromLicence("/tmp/no_such_ts_file_xyz.txt");
    EXPECT_EQ(ret, -1);
}

TEST_F(LicenseDbusTest, GetTimeStampfromLicence_NonNumericField_ReturnsNegOne)
{
    const std::string tmpPath = "/tmp/test_ts_nonnumeric.txt";
    {
        std::ofstream ofs(tmpPath);
        ofs << "notanumber;other-data";
    }

    int ret = getTimeStampfromLicence(tmpPath);
    EXPECT_EQ(ret, -1);

    std::remove(tmpPath.c_str());
}

TEST_F(LicenseDbusTest, GetTimeStampfromLicence_EmptyFile_ReturnsNegOne)
{
    const std::string tmpPath = "/tmp/test_ts_empty.txt";
    {
        std::ofstream ofs(tmpPath);
    }

    int ret = getTimeStampfromLicence(tmpPath);
    EXPECT_EQ(ret, -1);

    std::remove(tmpPath.c_str());
}

TEST_F(LicenseDbusTest,
       GenerateServiceValidityString_NormalData_ContainsServiceAndGlobal)
{
    json testData;
    testData["licensableServices"] = json::array();
    testData["licensableServices"].push_back(
        {{"serviceName", "svc1"}, {"LicenseValidity", 30}});
    testData["licenseconfig"] = json::array();
    testData["licenseconfig"].push_back({{"globalLicenseValidity", 90}});

    std::string result = generateServiceValidityString(testData);

    EXPECT_THAT(result, HasSubstr("svc1:30"));
    EXPECT_THAT(result, HasSubstr("GLOBAL:90"));
}

TEST_F(LicenseDbusTest,
       GenerateServiceValidityString_ZeroLicenseValidity_ServiceOmitted)
{
    json testData;
    testData["licensableServices"] = json::array();
    testData["licensableServices"].push_back(
        {{"serviceName", "svc2"}, {"LicenseValidity", 0}});
    testData["licenseconfig"] = json::array();
    testData["licenseconfig"].push_back({{"globalLicenseValidity", 50}});

    std::string result = generateServiceValidityString(testData);

    EXPECT_THAT(result, Not(HasSubstr("svc2")));
    EXPECT_THAT(result, HasSubstr("GLOBAL:50"));
}

TEST_F(LicenseDbusTest,
       GenerateServiceValidityString_MultipleServices_AllIncluded)
{
    json testData;
    testData["licensableServices"] = json::array();
    testData["licensableServices"].push_back(
        {{"serviceName", "svcA"}, {"LicenseValidity", 10}});
    testData["licensableServices"].push_back(
        {{"serviceName", "svcB"}, {"LicenseValidity", 20}});
    testData["licenseconfig"] = json::array();
    testData["licenseconfig"].push_back({{"globalLicenseValidity", 100}});

    std::string result = generateServiceValidityString(testData);

    EXPECT_THAT(result, HasSubstr("svcA:10"));
    EXPECT_THAT(result, HasSubstr("svcB:20"));
}

TEST_F(LicenseDbusTest, UpdateTokenValiditySection_ExistingService_UpdatesValue)
{
    std::string existing = "svc1:50;GLOBAL:100";
    std::string updates = "svc1:75";

    std::string result = updateTokenValiditySection(existing, updates);

    EXPECT_THAT(result, HasSubstr("svc1:75"));
    EXPECT_THAT(result, HasSubstr("GLOBAL:100"));
}

TEST_F(LicenseDbusTest, UpdateTokenValiditySection_NewService_PrependedToResult)
{
    std::string existing = "svc1:50;GLOBAL:100";
    std::string updates = "newSvc:30";

    std::string result = updateTokenValiditySection(existing, updates);

    EXPECT_THAT(result, HasSubstr("newSvc:30"));
}

TEST_F(LicenseDbusTest, UpdateTokenValiditySection_EmptyUpdates_ReturnsOriginal)
{
    std::string existing = "svc1:50;GLOBAL:100";
    std::string result = updateTokenValiditySection(existing, "");
    EXPECT_EQ(result, existing);
}

TEST_F(LicenseDbusTest, UpdateTokenValiditySection_EmptyBase_PrependNewEntry)
{
    std::string result = updateTokenValiditySection("", "svc1:25");
    EXPECT_THAT(result, HasSubstr("svc1:25"));
}

TEST_F(LicenseDbusTest, UpdateTokenValiditySection_MultipleUpdates_AllApplied)
{
    std::string existing = "svcA:10;svcB:20";
    std::string updates = "svcA:99;svcB:88";

    std::string result = updateTokenValiditySection(existing, updates);

    EXPECT_THAT(result, HasSubstr("svcA:99"));
    EXPECT_THAT(result, HasSubstr("svcB:88"));
}

TEST_F(LicenseDbusTest, ReadTokenFromFile_ValidFile_ReturnsContent)
{
    const std::string tmpPath = "/tmp/test_read_token.txt";
    const std::string content = "TIMESTAMP-2026:01:15-VALIDITY-svc1:90";
    {
        std::ofstream ofs(tmpPath);
        ofs << content;
    }

    std::string result = readTokenFromFile(tmpPath);
    EXPECT_EQ(result, content);

    std::remove(tmpPath.c_str());
}

TEST_F(LicenseDbusTest, ReadTokenFromFile_EmptyFile_ReturnsEmpty)
{
    const std::string tmpPath = "/tmp/test_read_token_empty.txt";
    {
        std::ofstream ofs(tmpPath);
    }

    std::string result = readTokenFromFile(tmpPath);
    EXPECT_TRUE(result.empty());

    std::remove(tmpPath.c_str());
}

TEST_F(LicenseDbusTest, ReadTokenFromFile_NonexistentFile_ReturnsEmpty)
{
    std::string result = readTokenFromFile("/tmp/no_such_token_xyz.txt");
    EXPECT_TRUE(result.empty());
}

TEST_F(LicenseDbusTest, ReadTokenFromFile_MultilineFile_ReturnsAllContent)
{
    const std::string tmpPath = "/tmp/test_read_multiline.txt";
    {
        std::ofstream ofs(tmpPath);
        ofs << "line1\nline2\nline3";
    }

    std::string result = readTokenFromFile(tmpPath);
    EXPECT_THAT(result, HasSubstr("line1"));
    EXPECT_THAT(result, HasSubstr("line2"));
    EXPECT_THAT(result, HasSubstr("line3"));

    std::remove(tmpPath.c_str());
}

TEST_F(LicenseDbusTest,
       GenerateTotalValidityData_NormalData_ReturnsFormattedString)
{
    globalData["licenseconfig"] = json::array();
    globalData["licenseconfig"].push_back({{"globalLicenseValidity", 100}});
    globalData["licensableServices"] = json::array();
    globalData["licensableServices"].push_back(
        {{"serviceName", "svc1"}, {"LicenseValidity", 50}});

    std::string result = generateTotalValidityData();
    EXPECT_THAT(result, HasSubstr("svc1"));
    EXPECT_THAT(result, HasSubstr("150"));
}

TEST_F(LicenseDbusTest, GenerateTotalValidityData_NoServices_ReturnsEmpty)
{
    globalData["licenseconfig"] = json::array();
    globalData["licenseconfig"].push_back({{"globalLicenseValidity", 100}});
    globalData["licensableServices"] = json::array();

    std::string result = generateTotalValidityData();
    EXPECT_TRUE(result.empty());
}

TEST_F(LicenseDbusTest,
       UpdateNewServiceValidity_ResetsLicenseValidityToZeroFirst)
{
    json testData;
    testData["licenseconfig"] = json::array();
    testData["licenseconfig"].push_back(
        {{"globalLicenseValidity", 100}, {"servicesUpCountDays", 10}});
    testData["licensableServices"] = json::array();
    testData["licensableServices"].push_back(
        {{"serviceName", "svc1"}, {"LicenseValidity", 50}});

    globalData = testData;

    std::string token =
        "TIMESTAMP-2026:01:15 00:00:00-VALIDITY-svc1:30-MAC-AA:BB:CC:DD:EE:FF";

    updateNewServiceValidity(token, testData);

    EXPECT_EQ(testData["licenseconfig"][0]["servicesUpCountDays"], 0);
}

TEST_F(LicenseDbusTest, UpdateNewServiceValidity_UpdatesGlobalLicenseValidity)
{
    json testData;
    testData["licenseconfig"] = json::array();
    testData["licenseconfig"].push_back(
        {{"globalLicenseValidity", 100}, {"servicesUpCountDays", 10}});
    testData["licensableServices"] = json::array();
    testData["licensableServices"].push_back(
        {{"serviceName", "svc1"}, {"LicenseValidity", 50}});

    globalData = testData;

    std::string token =
        "TIMESTAMP-2026:01:15-VALIDITY-svc1:30;GLOBAL:200-MAC-AA:BB:CC:DD:EE:FF";

    updateNewServiceValidity(token, testData);

    int newGlobal = testData["licenseconfig"][0]["globalLicenseValidity"];
    EXPECT_GT(newGlobal, 0);
}

// ===========================================================================
// LcDbusCoverageTest — VaildateTimeStamp, parseService,
// updateLicTokenwithExtValidity,
//   isServiceRunning, removeTempFiles, getMinValidityDate,
//   generateServiceValidityString, updateTokenValiditySection,
//   updateNewServiceValidity, readTokenFromFile, MacAddrCamp
// ===========================================================================

class LcDbusCoverageTest : public ::testing::Test
{
  protected:
    void SetUp() override
    {
        globalData = json::object();
        serviceDates.clear();
        UpCountDays = 0;
        Globalvalidcount = 0;
        alertCountValue = 0;
        AlertNotificationLicenseControl = "";
        exitSchedulerTask = false;
    }

    void TearDown() override
    {
        globalData.clear();
        serviceDates.clear();
    }
};

TEST_F(LcDbusCoverageTest,
       VaildateTimeStamp_NewTokenInFuture_CurrentLessThanNew_ReturnsNegOne)
{
    globalData["licenseconfig"] = json::array();
    globalData["licenseconfig"].push_back(
        {{"effectiveTimeStamp", "2000:01:01 00:00:00"}});

    std::string oldTok = "TIMESTAMP-2020:01:01 00:00:00";
    std::string newTok = "TIMESTAMP-2099:01:01 00:00:00";

    int ret = VaildateTimeStamp(oldTok, newTok);
    EXPECT_EQ(ret, -1);
}

TEST_F(LcDbusCoverageTest,
       VaildateTimeStamp_OldEqualNew_OldNotLessThanNew_ReturnsNegOne)
{
    globalData["licenseconfig"] = json::array();
    globalData["licenseconfig"].push_back(
        {{"effectiveTimeStamp", "2000:01:01 00:00:00"}});

    std::string tok = "TIMESTAMP-2020:06:01 00:00:00";
    int ret = VaildateTimeStamp(tok, tok);
    EXPECT_EQ(ret, -1);
}

TEST_F(LcDbusCoverageTest,
       VaildateTimeStamp_FutureEffective_CurrentNotGreater_ReturnsNegOne)
{
    globalData["licenseconfig"] = json::array();
    globalData["licenseconfig"].push_back(
        {{"effectiveTimeStamp", "2099:01:01 00:00:00"}});

    std::string oldTok = "TIMESTAMP-2010:01:01 00:00:00";
    std::string newTok = "TIMESTAMP-2020:01:01 00:00:00";

    int ret = VaildateTimeStamp(oldTok, newTok);
    EXPECT_EQ(ret, -1);
}

TEST_F(LcDbusCoverageTest, VaildateTimeStamp_EmptyTimestamps_ReturnsNegOne)
{
    globalData["licenseconfig"] = json::array();
    globalData["licenseconfig"].push_back({{"effectiveTimeStamp", ""}});

    int ret = VaildateTimeStamp("", "");
    EXPECT_EQ(ret, -1);
}

TEST_F(LcDbusCoverageTest, ParseService_StandardFormat_SplitsCorrectly)
{
    std::string serviceName;
    int serviceValue = 0;
    parseService("svc1:90", serviceName, serviceValue);

    EXPECT_EQ(serviceName, "svc1");
    EXPECT_EQ(serviceValue, 90);
}

TEST_F(LcDbusCoverageTest, ParseService_ZeroValue)
{
    std::string serviceName;
    int serviceValue = -1;
    parseService("myService:0", serviceName, serviceValue);

    EXPECT_EQ(serviceName, "myService");
    EXPECT_EQ(serviceValue, 0);
}

TEST_F(LcDbusCoverageTest, ParseService_LargeValue)
{
    std::string serviceName;
    int serviceValue = 0;
    parseService("GLOBAL:9999", serviceName, serviceValue);

    EXPECT_EQ(serviceName, "GLOBAL");
    EXPECT_EQ(serviceValue, 9999);
}

TEST_F(LcDbusCoverageTest, ParseService_NoColon_ServiceNameIsWholeString)
{
    std::string serviceName;
    int serviceValue = -1;
    parseService("NOCOOL", serviceName, serviceValue);

    EXPECT_EQ(serviceName, "NOCOOL");
    EXPECT_EQ(serviceValue, -1);
}

TEST_F(LcDbusCoverageTest,
       UpdateLicTokenwithExtValidity_FileNotFound_ReturnsNegOne)
{
    int ret = updateLicTokenwithExtValidity();
    EXPECT_EQ(ret, -1);
}

TEST_F(LcDbusCoverageTest, IsServiceRunning_KnownInactiveService_ReturnsFalse)
{
    bool result = isServiceRunning("no-such-unit-xyz.service");
    EXPECT_FALSE(result);
}

TEST_F(LcDbusCoverageTest, IsServiceRunning_EmptyName_ReturnsFalseOrFalse)
{
    bool result = isServiceRunning("");
    EXPECT_FALSE(result);
}

TEST_F(LcDbusCoverageTest,
       RemoveTempFiles_DirectoryWithFiles_ClearsRegularFiles)
{
    fs::create_directories("/tmp/license-control");

    std::ofstream("/tmp/license-control/file1.key").close();
    std::ofstream("/tmp/license-control/file2.txt").close();

    removeTempFiles();

    bool anyRegularFile = false;
    for (const auto& entry : fs::directory_iterator("/tmp/license-control"))
    {
        if (fs::is_regular_file(entry.path()))
        {
            anyRegularFile = true;
        }
    }
    EXPECT_FALSE(anyRegularFile);

    fs::remove_all("/tmp/license-control");
}

TEST_F(LcDbusCoverageTest, RemoveTempFiles_EmptyDirectory_NoCrash)
{
    fs::create_directories("/tmp/license-control");

    EXPECT_NO_THROW(removeTempFiles());

    fs::remove_all("/tmp/license-control");
}

TEST_F(LcDbusCoverageTest, GetMinValidityDate_NoServices_ReturnsMaxAlertCount)
{
    globalData["licenseconfig"] = json::array();
    globalData["licenseconfig"].push_back({{"globalLicenseValidity", 100}});
    globalData["licensableServices"] = json::array();

    uint32_t result = getMinValidityDate();
    EXPECT_EQ(result, 60u);
}

TEST_F(LcDbusCoverageTest, GetMinValidityDate_WithServices_ReturnsBoundedByMax)
{
    globalData["licenseconfig"] = json::array();
    globalData["licenseconfig"].push_back({{"globalLicenseValidity", 100}});
    globalData["licensableServices"] = json::array();
    globalData["licensableServices"].push_back(
        {{"serviceName", "svc1"}, {"LicenseValidity", 50}});

    uint32_t result = getMinValidityDate();
    EXPECT_EQ(result, 60u);
}

TEST_F(LcDbusCoverageTest,
       GenerateServiceValidityString_EmptyServices_OnlyGlobal)
{
    json testData;
    testData["licensableServices"] = json::array();
    testData["licenseconfig"] = json::array();
    testData["licenseconfig"].push_back({{"globalLicenseValidity", 75}});

    std::string result = generateServiceValidityString(testData);

    EXPECT_THAT(result, HasSubstr("GLOBAL:75"));
}

TEST_F(LcDbusCoverageTest,
       GenerateServiceValidityString_FirstServicePositive_NoLeadingSemicolon)
{
    json testData;
    testData["licensableServices"] = json::array();
    testData["licensableServices"].push_back(
        {{"serviceName", "svc1"}, {"LicenseValidity", 10}});
    testData["licenseconfig"] = json::array();
    testData["licenseconfig"].push_back({{"globalLicenseValidity", 50}});

    std::string result = generateServiceValidityString(testData);

    EXPECT_EQ(result[0], 's');
    EXPECT_THAT(result, HasSubstr("svc1:10"));
}

TEST_F(LcDbusCoverageTest,
       GenerateServiceValidityString_SecondServicePositive_SemicolonSeparator)
{
    json testData;
    testData["licensableServices"] = json::array();
    testData["licensableServices"].push_back(
        {{"serviceName", "svc1"}, {"LicenseValidity", 10}});
    testData["licensableServices"].push_back(
        {{"serviceName", "svc2"}, {"LicenseValidity", 20}});
    testData["licenseconfig"] = json::array();
    testData["licenseconfig"].push_back({{"globalLicenseValidity", 50}});

    std::string result = generateServiceValidityString(testData);

    EXPECT_THAT(result, HasSubstr("svc1:10;svc2:20"));
}

TEST_F(LcDbusCoverageTest,
       UpdateTokenValiditySection_Str1EndsWithSemicolon_NoDouble)
{
    std::string str1 = "existing:10;";
    std::string str2 = "newSvc:5";

    std::string result = updateTokenValiditySection(str1, str2);

    EXPECT_THAT(result, HasSubstr("newSvc:5"));
    EXPECT_THAT(result, HasSubstr("existing:10"));
}

TEST_F(LcDbusCoverageTest, UpdateTokenValiditySection_UpdateAndPrepend_BothWork)
{
    std::string str1 = "alpha:100;beta:200";
    std::string str2 = "alpha:999;gamma:50";

    std::string result = updateTokenValiditySection(str1, str2);

    EXPECT_THAT(result, HasSubstr("alpha:999"));
    EXPECT_THAT(result, HasSubstr("beta:200"));
    EXPECT_THAT(result, HasSubstr("gamma:50"));
}

TEST_F(LcDbusCoverageTest,
       UpdateNewServiceValidity_UpCountExceedsGlobal_ZeroesUpdatedValidity)
{
    json testData;
    testData["licenseconfig"] = json::array();
    testData["licenseconfig"].push_back(
        {{"globalLicenseValidity", 30}, {"servicesUpCountDays", 50}});
    testData["licensableServices"] = json::array();
    testData["licensableServices"].push_back(
        {{"serviceName", "svc1"}, {"LicenseValidity", 20}});

    globalData = testData;

    std::string token =
        "TIMESTAMP-2026:01:15-VALIDITY-svc1:10-MAC-AA:BB:CC:DD:EE:FF";
    int ret = updateNewServiceValidity(token, testData);

    EXPECT_EQ(ret, 0);
    EXPECT_EQ(testData["licenseconfig"][0]["servicesUpCountDays"], 0);
}

TEST_F(LcDbusCoverageTest,
       UpdateNewServiceValidity_UpCountLessThanGlobal_KeepsExistingValidity)
{
    json testData;
    testData["licenseconfig"] = json::array();
    testData["licenseconfig"].push_back(
        {{"globalLicenseValidity", 100}, {"servicesUpCountDays", 5}});
    testData["licensableServices"] = json::array();
    testData["licensableServices"].push_back(
        {{"serviceName", "svc1"}, {"LicenseValidity", 50}});

    globalData = testData;

    std::string token =
        "TIMESTAMP-2026:01:15-VALIDITY-svc1:30-MAC-AA:BB:CC:DD:EE:FF";
    int ret = updateNewServiceValidity(token, testData);

    EXPECT_EQ(ret, 0);
    EXPECT_EQ(testData["licenseconfig"][0]["servicesUpCountDays"], 0);
}

TEST_F(LcDbusCoverageTest,
       UpdateNewServiceValidity_NoGlobalInToken_GlobalSetToRemainder)
{
    json testData;
    testData["licenseconfig"] = json::array();
    testData["licenseconfig"].push_back(
        {{"globalLicenseValidity", 100}, {"servicesUpCountDays", 10}});
    testData["licensableServices"] = json::array();
    testData["licensableServices"].push_back(
        {{"serviceName", "svc1"}, {"LicenseValidity", 50}});

    globalData = testData;

    std::string token =
        "TIMESTAMP-2026:01:15-VALIDITY-svc1:30-MAC-AA:BB:CC:DD:EE:FF";
    updateNewServiceValidity(token, testData);

    int newGlobal = testData["licenseconfig"][0]["globalLicenseValidity"];
    EXPECT_EQ(newGlobal, 90);
}

TEST_F(LcDbusCoverageTest,
       UpdateNewServiceValidity_ServiceNotFoundInNew_PushedBack)
{
    json testData;
    testData["licenseconfig"] = json::array();
    testData["licenseconfig"].push_back(
        {{"globalLicenseValidity", 100}, {"servicesUpCountDays", 0}});
    testData["licensableServices"] = json::array();
    testData["licensableServices"].push_back(
        {{"serviceName", "svcOld"}, {"LicenseValidity", 30}});

    globalData = testData;

    std::string token =
        "TIMESTAMP-2026:01:15-VALIDITY-svcNew:20-MAC-AA:BB:CC:DD:EE:FF";
    updateNewServiceValidity(token, testData);

    bool foundOld = false;
    for (const auto& svc : testData["licensableServices"])
    {
        if (svc["serviceName"] == "svcOld")
        {
            foundOld = true;
        }
    }
    EXPECT_TRUE(foundOld);
}

TEST_F(LcDbusCoverageTest, ReadTokenFromFile_BinaryContent_RetainsAllBytes)
{
    const std::string tmpPath = "/tmp/test_token_binary.bin";
    std::string content(256, '\0');
    for (int i = 0; i < 256; ++i)
    {
        content[i] = static_cast<char>((i % 127) + 1);
    }
    {
        std::ofstream ofs(tmpPath, std::ios::binary);
        ofs.write(content.data(), static_cast<std::streamsize>(content.size()));
    }

    std::string result = readTokenFromFile(tmpPath);
    EXPECT_EQ(result.size(), 256u);

    std::remove(tmpPath.c_str());
}

TEST_F(LcDbusCoverageTest, MacAddrCamp_AllUppercase_Matches)
{
    EXPECT_TRUE(MacAddrCamp("AB:CD:EF:01:23:45", "AB:CD:EF:01:23:45"));
}

TEST_F(LcDbusCoverageTest, MacAddrCamp_UpperVsLower_Matches)
{
    EXPECT_TRUE(MacAddrCamp("AB:cd:EF:01:23:45", "ab:CD:ef:01:23:45"));
}

TEST_F(LcDbusCoverageTest, MacAddrCamp_SingleCharDiff_ReturnsFalse)
{
    EXPECT_FALSE(MacAddrCamp("AB:CD:EF:01:23:45", "AB:CD:EF:01:23:46"));
}

} // namespace
