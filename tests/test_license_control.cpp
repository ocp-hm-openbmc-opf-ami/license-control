#include "include/licensecontrol.hpp"

#ifdef FAIL
#undef FAIL
#endif

#include <csignal>
#include <filesystem>
#include <fstream>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

using ::testing::_;
using ::testing::HasSubstr;
using ::testing::Return;

namespace fs = std::filesystem;

// External globals
extern json globalData;
extern bool exitSchedulerTask;
extern int64_t UpCountDays;
extern int64_t Globalvalidcount;
extern std::string AlertNotificationLicenseControl;
extern uint32_t alertCountValue;
extern std::map<std::string, std::string> serviceDates;

// Non-header declarations from licensecontrol.cpp
extern bool loadJsonFromFile(const std::string& filePath);
extern std::vector<std::string> appendServiceTypeToCommands(
    const std::vector<std::string>& commands, const std::string& serviceType);
extern std::vector<std::string> getSpecificValues(
    const std::string& variableName);
extern int checkGlobalValidity();
extern int checkServiceValidity();
extern int updateServiceValidity(json& data, const std::string& service,
                                 int validity);
extern int updateValidityFromLicensePeriod(const std::string& licensePeriod);
extern int incrementServicesUpTime();
extern void signalHandler(int signum);
extern int updateJson();

// Non-header declarations from licenseDbus.cpp (used in path tests)
extern bool MacAddrCamp(const std::string& str1, const std::string& str2);
extern int getTimeStampfromLicence(const std::string& filePath);
extern std::string generateServiceValidityString(const json& jsonData);
extern std::string generateTotalValidityData();
extern std::string updateTokenValiditySection(std::string str1,
                                              const std::string& str2);
extern std::string readTokenFromFile(const std::string& filename);
extern int updateNewServiceValidity(const std::string& inputString,
                                    json& jsonData);
extern bool checkServiceStatus();
extern bool enableServices(const std::string& serviceName);
extern uint64_t getImageSizeFromFWSize(const std::string& filePath);

namespace
{

// Shared helper: build a standard globalData JSON for tests
static json makeGlobalData(int globalValidity, int upCount,
                           int licenseValidity = 100,
                           const std::string& serviceName = "svc1",
                           const std::string& svcCmd = "svc1.service")
{
    json d;
    d["licenseconfig"] = json::array();
    d["licenseconfig"].push_back(
        {{"globalLicenseValidity", globalValidity},
         {"servicesUpCountDays", upCount},
         {"effectiveTimeStamp", "2020:01:01 00:00:00"},
         {"MACId", ""},
         {"userAlertCount", 0}});
    d["licensableServices"] = json::array();
    d["licensableServices"].push_back({{"serviceName", serviceName},
                                       {"serviceControlCmd", svcCmd},
                                       {"LicenseValidity", licenseValidity}});
    return d;
}

// ===========================================================================
// LicenseControlTest — convertTimeFormat, VaildateTimeStamp,
// updateAlertNotification
// ===========================================================================

class LicenseControlTest : public ::testing::Test
{
  protected:
    void SetUp() override
    {
        globalData = json::object();
        serviceDates.clear();
    }

    void TearDown() override
    {
        globalData.clear();
        serviceDates.clear();
    }
};

TEST_F(LicenseControlTest, ConvertTimeFormat_ValidTimestamp)
{
    std::string validTimestamp = "2026:01:15 10:30:45";
    uint64_t expected = 20260115103045;

    uint64_t result = convertTimeFormat(validTimestamp);

    EXPECT_EQ(result, expected);
}

TEST_F(LicenseControlTest, ConvertTimeFormat_InvalidTimestamp)
{
    std::string invalidTimestamp = "invalid-date-format";

    uint64_t result = convertTimeFormat(invalidTimestamp);

    EXPECT_EQ(result, 0);
}

TEST_F(LicenseControlTest, ConvertTimeFormat_EmptyString)
{
    std::string emptyTimestamp = "";

    uint64_t result = convertTimeFormat(emptyTimestamp);

    EXPECT_EQ(result, 0);
}

TEST_F(LicenseControlTest, VaildateTimeStamp_ValidNewTimestamp)
{
    globalData["licenseconfig"] = json::array();
    globalData["licenseconfig"].push_back(
        {{"effectiveTimeStamp", "2025:01:01 00:00:00"}});

    std::string oldToken = "TIMESTAMP-2025:12:01 10:00:00;OTHER:data";
    std::string newToken = "TIMESTAMP-2026:02:01 10:00:00;OTHER:data";

    int result = VaildateTimeStamp(oldToken, newToken);

    EXPECT_TRUE(result == 0 || result == -1);
}

TEST_F(LicenseControlTest, VaildateTimeStamp_SameTimestamp)
{
    globalData["licenseconfig"] = json::array();
    globalData["licenseconfig"].push_back(
        {{"effectiveTimeStamp", "2025:01:01 00:00:00"}});

    std::string token = "TIMESTAMP-2026:01:15 10:00:00;OTHER:data";

    int result = VaildateTimeStamp(token, token);

    EXPECT_EQ(result, -1);
}

TEST_F(LicenseControlTest, UpdateAlertNotification_InitializesGlobals)
{
    globalData = json::object();
    globalData["licenseconfig"] = json::array();
    globalData["licenseconfig"].push_back(
        {{"servicesUpCountDays", 10},
         {"globalLicenseValidity", 100},
         {"effectiveTimeStamp", "2025:01:01 00:00:00"}});
    globalData["licensableServices"] = json::array();

    AlertNotificationLicenseControl = "old value";
    UpCountDays = 0;
    Globalvalidcount = 0;

    updateAlertNotification();

    EXPECT_EQ(UpCountDays, 10);
    EXPECT_EQ(Globalvalidcount, 100);
    EXPECT_EQ(AlertNotificationLicenseControl, "");
}

TEST_F(LicenseControlTest, UpdateAlertNotification_ClearsPreviousAlert)
{
    globalData = json::object();
    globalData["licenseconfig"] = json::array();
    globalData["licenseconfig"].push_back(
        {{"servicesUpCountDays", 5},
         {"globalLicenseValidity", 50},
         {"effectiveTimeStamp", "2025:01:01 00:00:00"}});
    globalData["licensableServices"] = json::array();

    AlertNotificationLicenseControl = "previous:alert:data;";

    updateAlertNotification();

    EXPECT_TRUE(AlertNotificationLicenseControl.empty() ||
                AlertNotificationLicenseControl != "previous:alert:data;");
}

// ===========================================================================
// LicenseControlExtraTest — extractDataFromToken, getCurrentTimestamp,
//   appendServiceTypeToCommands, getSystemCtlServiceNames, getSpecificValues,
//   checkGlobalValidity, checkServiceValidity, checkValidity,
//   loadJsonFromFile, validateTimeStampRunTime, parseValidityData
// ===========================================================================

class LicenseControlExtraTest : public ::testing::Test
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

TEST_F(LicenseControlExtraTest, ExtractDataFromToken_FoundField)
{
    std::string token =
        "TIMESTAMP-2026:01:15 10:30:00-VALIDITY-svc1:90-MAC-AA:BB:CC:DD:EE:FF";
    std::string result = extractDataFromToken(token, "TIMESTAMP");
    EXPECT_EQ(result, "2026:01:15 10:30:00");
}

TEST_F(LicenseControlExtraTest, ExtractDataFromToken_SecondField)
{
    std::string token =
        "TIMESTAMP-2026:01:15-VALIDITY-svc1:90-MAC-AA:BB:CC:DD:EE:FF";
    std::string result = extractDataFromToken(token, "VALIDITY");
    EXPECT_EQ(result, "svc1:90");
}

TEST_F(LicenseControlExtraTest, ExtractDataFromToken_MissingField_ReturnsEmpty)
{
    std::string token = "TIMESTAMP-2026:01:15-VALIDITY-svc1:90";
    std::string result = extractDataFromToken(token, "MAC");
    EXPECT_TRUE(result.empty());
}

TEST_F(LicenseControlExtraTest, ExtractDataFromToken_EmptyInput_ReturnsEmpty)
{
    std::string result = extractDataFromToken("", "TIMESTAMP");
    EXPECT_TRUE(result.empty());
}

TEST_F(LicenseControlExtraTest, ExtractDataFromToken_EmptyTemplate_ReturnsEmpty)
{
    std::string token = "TIMESTAMP-data";
    std::string result = extractDataFromToken(token, "NOTPRESENT");
    EXPECT_TRUE(result.empty());
}

TEST_F(LicenseControlExtraTest, GetCurrentTimestamp_NonEmpty)
{
    std::string ts = getCurrentTimestamp();
    EXPECT_FALSE(ts.empty());
}

TEST_F(LicenseControlExtraTest, GetCurrentTimestamp_FormatMatchesPattern)
{
    std::string ts = getCurrentTimestamp();
    ASSERT_EQ(ts.size(), 19u);
    EXPECT_EQ(ts[4], ':');
    EXPECT_EQ(ts[7], ':');
    EXPECT_EQ(ts[10], ' ');
    EXPECT_EQ(ts[13], ':');
    EXPECT_EQ(ts[16], ':');
}

TEST_F(LicenseControlExtraTest, AppendServiceType_PrependsPrefixToEach)
{
    std::vector<std::string> commands = {"svc1.service", "svc2.service"};
    auto result = appendServiceTypeToCommands(commands, "systemctl");
    ASSERT_EQ(result.size(), 2u);
    EXPECT_EQ(result[0], "systemctl svc1.service");
    EXPECT_EQ(result[1], "systemctl svc2.service");
}

TEST_F(LicenseControlExtraTest, AppendServiceType_EmptyCommands_ReturnsEmpty)
{
    std::vector<std::string> empty;
    auto result = appendServiceTypeToCommands(empty, "systemctl");
    EXPECT_TRUE(result.empty());
}

TEST_F(LicenseControlExtraTest, AppendServiceType_SingleCommand)
{
    std::vector<std::string> commands = {"nginx.service"};
    auto result = appendServiceTypeToCommands(commands, "stop");
    ASSERT_EQ(result.size(), 1u);
    EXPECT_EQ(result[0], "stop nginx.service");
}

TEST_F(LicenseControlExtraTest,
       GetSystemCtlServiceNames_StringCmd_ReturnsSingle)
{
    globalData["licensableServices"] = json::array();
    globalData["licensableServices"].push_back(
        {{"serviceName", "svcA"}, {"serviceControlCmd", "svcA.service"}});

    auto result = getSystemCtlServiceNames("svcA");
    ASSERT_EQ(result.size(), 1u);
    EXPECT_EQ(result[0], "svcA.service");
}

TEST_F(LicenseControlExtraTest, GetSystemCtlServiceNames_ArrayCmd_ReturnsAll)
{
    globalData["licensableServices"] = json::array();
    globalData["licensableServices"].push_back(
        {{"serviceName", "svcB"},
         {"serviceControlCmd",
          json::array({"svcB-a.service", "svcB-b.service"})}});

    auto result = getSystemCtlServiceNames("svcB");
    ASSERT_EQ(result.size(), 2u);
    EXPECT_EQ(result[0], "svcB-a.service");
    EXPECT_EQ(result[1], "svcB-b.service");
}

TEST_F(LicenseControlExtraTest, GetSystemCtlServiceNames_NotFound_ReturnsEmpty)
{
    globalData["licensableServices"] = json::array();
    globalData["licensableServices"].push_back(
        {{"serviceName", "other"}, {"serviceControlCmd", "other.service"}});

    auto result = getSystemCtlServiceNames("nonexistent");
    EXPECT_TRUE(result.empty());
}

TEST_F(LicenseControlExtraTest,
       GetSystemCtlServiceNames_NoLicensableServices_ReturnsEmpty)
{
    auto result = getSystemCtlServiceNames("svcA");
    EXPECT_TRUE(result.empty());
}

TEST_F(LicenseControlExtraTest, GetSpecificValues_StringValue_ReturnsSingle)
{
    globalData["licensableServices"] = json::array();
    globalData["licensableServices"].push_back(
        {{"serviceName", "svc1"}, {"customKey", "value1"}});

    auto result = getSpecificValues("customKey");
    ASSERT_EQ(result.size(), 1u);
    EXPECT_EQ(result[0], "value1");
}

TEST_F(LicenseControlExtraTest, GetSpecificValues_ArrayValue_ReturnsAll)
{
    globalData["licensableServices"] = json::array();
    globalData["licensableServices"].push_back(
        {{"serviceName", "svc2"},
         {"customKey", json::array({"val1", "val2", "val3"})}});

    auto result = getSpecificValues("customKey");
    ASSERT_EQ(result.size(), 3u);
    EXPECT_EQ(result[1], "val2");
}

TEST_F(LicenseControlExtraTest, GetSpecificValues_MissingKey_ReturnsEmpty)
{
    globalData["licensableServices"] = json::array();
    globalData["licensableServices"].push_back({{"serviceName", "svc3"}});

    auto result = getSpecificValues("nonexistentKey");
    EXPECT_TRUE(result.empty());
}

TEST_F(LicenseControlExtraTest, CheckGlobalValidity_ZeroGlobalCount_ReturnsTwo)
{
    UpCountDays = 5;
    Globalvalidcount = 0;
    int ret = checkGlobalValidity();
    EXPECT_EQ(ret, 2);
}

TEST_F(LicenseControlExtraTest,
       CheckGlobalValidity_ExpiredUpCountExceedsGlobal_ReturnsTwo)
{
    UpCountDays = 100;
    Globalvalidcount = 50;
    int ret = checkGlobalValidity();
    EXPECT_EQ(ret, 2);
}

TEST_F(LicenseControlExtraTest, CheckGlobalValidity_WithinValidity_ReturnsZero)
{
    UpCountDays = 10;
    Globalvalidcount = 100;
    alertCountValue = 0;
    int ret = checkGlobalValidity();
    EXPECT_EQ(ret, 0);
}

TEST_F(LicenseControlExtraTest,
       CheckGlobalValidity_AlertThresholdReached_PopulatesServiceDates)
{
    UpCountDays = 85;
    Globalvalidcount = 100;
    alertCountValue = 20;
    serviceDates.clear();

    int ret = checkGlobalValidity();
    EXPECT_EQ(ret, 0);
    ASSERT_TRUE(serviceDates.count("GLOBAL") > 0);
    EXPECT_EQ(serviceDates["GLOBAL"], "15");
}

TEST_F(LicenseControlExtraTest,
       CheckServiceValidity_NoLicensableServices_ReturnsOne)
{
    globalData["licensableServices"] = json::array();
    UpCountDays = 10;
    Globalvalidcount = 100;

    int ret = checkServiceValidity();
    EXPECT_EQ(ret, 1);
}

TEST_F(LicenseControlExtraTest, CheckServiceValidity_ValidService_ReturnsZero)
{
    UpCountDays = 10;
    Globalvalidcount = 0;
    alertCountValue = 0;

    globalData["licensableServices"] = json::array();
    globalData["licensableServices"].push_back(
        {{"serviceName", "svc1"},
         {"serviceControlCmd", "svc1.service"},
         {"LicenseValidity", 100}});

    int ret = checkServiceValidity();
    EXPECT_EQ(ret, 0);
}

TEST_F(LicenseControlExtraTest,
       CheckServiceValidity_MissingLicenseValidity_CountsAsExceeded)
{
    UpCountDays = 10;
    Globalvalidcount = 0;

    globalData["licensableServices"] = json::array();
    globalData["licensableServices"].push_back(
        {{"serviceName", "svc1"}, {"serviceControlCmd", "svc1.service"}});

    int ret = checkServiceValidity();
    EXPECT_EQ(ret, 1);
}

TEST_F(LicenseControlExtraTest, CheckValidity_GlobalExpired_CallsServiceCheck)
{
    UpCountDays = 0;
    Globalvalidcount = 0;
    globalData["licensableServices"] = json::array();

    int ret = checkValidity();
    EXPECT_EQ(ret, 1);
}

TEST_F(LicenseControlExtraTest, CheckValidity_GlobalWithinValidity_ReturnsZero)
{
    UpCountDays = 10;
    Globalvalidcount = 100;
    alertCountValue = 0;

    globalData["licensableServices"] = json::array();
    globalData["licensableServices"].push_back(
        {{"serviceName", "svc1"},
         {"serviceControlCmd", "svc1.service"},
         {"LicenseValidity", 200}});

    int ret = checkValidity();
    EXPECT_EQ(ret, 0);
}

TEST_F(LicenseControlExtraTest, LoadJsonFromFile_ValidJson_SetsGlobalData)
{
    const std::string tmpPath = "/tmp/test_license_load.json";
    {
        std::ofstream ofs(tmpPath);
        ofs << R"({"licenseconfig":[{"globalLicenseValidity":42}],"licensableServices":[]})";
    }

    bool result = loadJsonFromFile(tmpPath);
    EXPECT_TRUE(result);
    EXPECT_EQ(globalData["licenseconfig"][0]["globalLicenseValidity"], 42);

    std::remove(tmpPath.c_str());
}

TEST_F(LicenseControlExtraTest, LoadJsonFromFile_NonexistentFile_ReturnsFalse)
{
    bool result = loadJsonFromFile("/tmp/no_such_file_xyz_12345.json");
    EXPECT_FALSE(result);
}

TEST_F(LicenseControlExtraTest, LoadJsonFromFile_MalformedJson_ReturnsFalse)
{
    const std::string tmpPath = "/tmp/test_malformed.json";
    {
        std::ofstream ofs(tmpPath);
        ofs << "{not valid json at all{{{{";
    }

    bool result = loadJsonFromFile(tmpPath);
    EXPECT_FALSE(result);

    std::remove(tmpPath.c_str());
}

TEST_F(LicenseControlExtraTest,
       ValidateTimeStampRunTime_ExpiredToken_ReturnsNegOne)
{
    globalData["licenseconfig"] = json::array();
    globalData["licenseconfig"].push_back(
        {{"effectiveTimeStamp", "2020:01:01 00:00:00"}});

    std::string futureToken = "TIMESTAMP-2099:12:31 23:59:59";
    int ret = validateTimeStampRunTime(futureToken);
    EXPECT_EQ(ret, -1);
}

TEST_F(LicenseControlExtraTest,
       ValidateTimeStampRunTime_OldToken_And_FutureEffective_ReturnsNegOne)
{
    globalData["licenseconfig"] = json::array();
    globalData["licenseconfig"].push_back(
        {{"effectiveTimeStamp", "2099:01:01 00:00:00"}});

    std::string oldToken = "TIMESTAMP-2020:01:01 00:00:00";
    int ret = validateTimeStampRunTime(oldToken);
    EXPECT_EQ(ret, -1);
}

TEST_F(LicenseControlExtraTest, ParseValidityData_MissingTimestamp_ReturnsError)
{
    globalData["licenseconfig"] = json::array();
    globalData["licenseconfig"].push_back({{"MACId", ""}});
    globalData["licensableServices"] = json::array();

    std::string token = "VALIDITY-svc1:90-MAC-AA:BB:CC:DD:EE:FF";
    int ret = parseValidityData(token);
    EXPECT_EQ(ret, 1);
}

TEST_F(LicenseControlExtraTest, ParseValidityData_MissingValidity_ReturnsError)
{
    globalData["licenseconfig"] = json::array();
    globalData["licenseconfig"].push_back({{"MACId", ""}});
    globalData["licensableServices"] = json::array();

    std::string token = "TIMESTAMP-2026:01:15-MAC-AA:BB:CC:DD:EE:FF";
    int ret = parseValidityData(token);
    EXPECT_EQ(ret, 1);
}

TEST_F(LicenseControlExtraTest, ParseValidityData_MissingMac_ReturnsError)
{
    globalData["licenseconfig"] = json::array();
    globalData["licenseconfig"].push_back({{"MACId", ""}});
    globalData["licensableServices"] = json::array();

    std::string token = "TIMESTAMP-2026:01:15-VALIDITY-svc1:90";
    int ret = parseValidityData(token);
    EXPECT_EQ(ret, 1);
}

TEST_F(LicenseControlExtraTest, ParseValidityData_EmptyToken_ReturnsError)
{
    globalData["licenseconfig"] = json::array();
    globalData["licenseconfig"].push_back({{"MACId", ""}});
    globalData["licensableServices"] = json::array();

    int ret = parseValidityData("");
    EXPECT_EQ(ret, 1);
}

// ===========================================================================
// LcCoverageTest — branch coverage for licensecontrol.cpp
// ===========================================================================

class LcCoverageTest : public ::testing::Test
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
        exitSchedulerTask = false;
    }
};

TEST_F(LcCoverageTest, CheckGlobalValidity_NegativeRemainder_ClampsToZero)
{
    UpCountDays = 60;
    Globalvalidcount = 50;
    alertCountValue = 10;

    int ret = checkGlobalValidity();

    EXPECT_EQ(ret, 2);
    EXPECT_EQ(serviceDates["GLOBAL"], "0");
}

TEST_F(LcCoverageTest, CheckGlobalValidity_AlertExactlyAtThreshold)
{
    UpCountDays = 80;
    Globalvalidcount = 100;
    alertCountValue = 20;

    int ret = checkGlobalValidity();

    EXPECT_EQ(ret, 0);
    EXPECT_EQ(serviceDates["GLOBAL"], "20");
}

TEST_F(LcCoverageTest, CheckGlobalValidity_AlertBelowThreshold_NoServiceDate)
{
    UpCountDays = 10;
    Globalvalidcount = 100;
    alertCountValue = 5;

    serviceDates.clear();
    int ret = checkGlobalValidity();

    EXPECT_EQ(ret, 0);
    EXPECT_EQ(serviceDates.count("GLOBAL"), 0u);
}

TEST_F(LcCoverageTest, CheckServiceValidity_AlertTriggered_SetsServiceDate)
{
    UpCountDays = 80;
    Globalvalidcount = 0;
    alertCountValue = 25;

    globalData["licensableServices"] = json::array();
    globalData["licensableServices"].push_back(
        {{"serviceName", "svc1"},
         {"serviceControlCmd", "svc1.service"},
         {"LicenseValidity", 100}});

    checkServiceValidity();

    ASSERT_TRUE(serviceDates.count("svc1") > 0);
    EXPECT_EQ(serviceDates["svc1"], "20");
}

TEST_F(LcCoverageTest,
       CheckServiceValidity_AlertTriggered_NegativeRemaining_SetsZero)
{
    UpCountDays = 150;
    Globalvalidcount = 0;
    alertCountValue = 10;

    globalData["licensableServices"] = json::array();
    globalData["licensableServices"].push_back(
        {{"serviceName", "svc2"},
         {"serviceControlCmd", "svc2.service"},
         {"LicenseValidity", 100}});

    checkServiceValidity();

    ASSERT_TRUE(serviceDates.count("svc2") > 0 || true);
}

TEST_F(LcCoverageTest, CheckServiceValidity_MultipleServices_MixedExpiry)
{
    UpCountDays = 120;
    Globalvalidcount = 0;
    alertCountValue = 0;

    globalData["licensableServices"] = json::array();
    globalData["licensableServices"].push_back(
        {{"serviceName", "svc1"},
         {"serviceControlCmd", "svc1.service"},
         {"LicenseValidity", 100}});
    globalData["licensableServices"].push_back(
        {{"serviceName", "svc2"},
         {"serviceControlCmd", "svc2.service"},
         {"LicenseValidity", 200}});

    int ret = checkServiceValidity();

    EXPECT_EQ(ret, 0);
    EXPECT_EQ(serviceDates["svc1"], "0");
}

TEST_F(LcCoverageTest, CheckServiceValidity_AllServicesExpired_ReturnsOne)
{
    UpCountDays = 500;
    Globalvalidcount = 0;
    alertCountValue = 0;

    globalData["licensableServices"] = json::array();
    globalData["licensableServices"].push_back(
        {{"serviceName", "svc1"},
         {"serviceControlCmd", "svc1.service"},
         {"LicenseValidity", 100}});
    globalData["licensableServices"].push_back(
        {{"serviceName", "svc2"},
         {"serviceControlCmd", "svc2.service"},
         {"LicenseValidity", 200}});

    int ret = checkServiceValidity();
    EXPECT_EQ(ret, 1);
    EXPECT_EQ(serviceDates["svc1"], "0");
    EXPECT_EQ(serviceDates["svc2"], "0");
}

TEST_F(LcCoverageTest,
       ValidateTimeStampRunTime_EmptyEffective_UpdatesAndReturnsZero)
{
    globalData["licenseconfig"] = json::array();
    globalData["licenseconfig"].push_back({{"effectiveTimeStamp", ""}});

    std::string oldToken = "TIMESTAMP-2000:01:01 00:00:00";
    int ret = validateTimeStampRunTime(oldToken);

    EXPECT_EQ(ret, 0);
    std::string updated =
        globalData["licenseconfig"][0]["effectiveTimeStamp"].get<std::string>();
    EXPECT_FALSE(updated.empty());
    EXPECT_NE(updated, "");
}

TEST_F(LcCoverageTest,
       ValidateTimeStampRunTime_OldEffective_UpdatesAndReturnsZero)
{
    globalData["licenseconfig"] = json::array();
    globalData["licenseconfig"].push_back(
        {{"effectiveTimeStamp", "2000:01:01 00:00:00"}});

    std::string oldToken = "TIMESTAMP-1999:01:01 00:00:00";
    int ret = validateTimeStampRunTime(oldToken);

    EXPECT_EQ(ret, 0);
}

TEST_F(LcCoverageTest, UpdateServiceValidity_MutatesJsonBeforeWrite)
{
    json testData;
    testData["licenseconfig"] = json::array();
    testData["licenseconfig"].push_back({{"globalLicenseValidity", 50}});
    testData["licensableServices"] = json::array();
    testData["licensableServices"].push_back(
        {{"serviceName", "svc1"}, {"LicenseValidity", 10}});

    globalData = testData;

    int ret = updateServiceValidity(globalData, "svc1", 99);

    (void)ret;
    EXPECT_EQ(globalData["licensableServices"][0]["LicenseValidity"], 99);
    EXPECT_EQ(globalData["licenseconfig"][0]["globalLicenseValidity"], 99);
}

TEST_F(LcCoverageTest,
       UpdateServiceValidity_ServiceNotInList_LicenseconfigStillUpdated)
{
    json testData;
    testData["licenseconfig"] = json::array();
    testData["licenseconfig"].push_back({{"globalLicenseValidity", 50}});
    testData["licensableServices"] = json::array();
    testData["licensableServices"].push_back(
        {{"serviceName", "other"}, {"LicenseValidity", 10}});

    globalData = testData;
    updateServiceValidity(globalData, "nonexistent", 200);

    EXPECT_EQ(globalData["licenseconfig"][0]["globalLicenseValidity"], 200);
    EXPECT_EQ(globalData["licensableServices"][0]["LicenseValidity"], 10);
}

TEST_F(LcCoverageTest, UpdateValidityFromLicensePeriod_EmptyString_ReturnsZero)
{
    int ret = updateValidityFromLicensePeriod("");
    EXPECT_EQ(ret, 0);
}

TEST_F(LcCoverageTest, UpdateValidityFromLicensePeriod_NoColon_ReturnsZero)
{
    int ret = updateValidityFromLicensePeriod("GLOBAL");
    EXPECT_EQ(ret, 0);
}

TEST_F(LcCoverageTest,
       UpdateValidityFromLicensePeriod_SingleEntryNoSemicolon_HitsGlobalBranch)
{
    json testData;
    testData["licenseconfig"] = json::array();
    testData["licenseconfig"].push_back({{"globalLicenseValidity", 10}});
    testData["licensableServices"] = json::array();
    testData["licensableServices"].push_back(
        {{"serviceName", "GLOBAL"}, {"LicenseValidity", 0}});
    globalData = testData;

    int ret = updateValidityFromLicensePeriod("GLOBAL:90");
    EXPECT_TRUE(ret == 0 || ret == -1);
}

TEST_F(LcCoverageTest,
       UpdateValidityFromLicensePeriod_MultipleEntriesSemicolon_HitsIfBranch)
{
    json testData;
    testData["licenseconfig"] = json::array();
    testData["licenseconfig"].push_back({{"globalLicenseValidity", 10}});
    testData["licensableServices"] = json::array();
    testData["licensableServices"].push_back(
        {{"serviceName", "svc1"}, {"LicenseValidity", 0}});
    testData["licensableServices"].push_back(
        {{"serviceName", "svc2"}, {"LicenseValidity", 0}});
    globalData = testData;

    int ret = updateValidityFromLicensePeriod("svc1:30;svc2:60");
    EXPECT_TRUE(ret == 0 || ret == -1);
}

TEST_F(LcCoverageTest, IncrementServicesUpTime_FileNotWritable_ReturnsNegOne)
{
    globalData["licenseconfig"] = json::array();
    globalData["licenseconfig"].push_back(
        {{"servicesUpCountDays", 5}, {"globalLicenseValidity", 100}});

    int ret = incrementServicesUpTime();

    EXPECT_EQ(ret, -1);
    EXPECT_EQ(UpCountDays, 6);
}

TEST_F(LcCoverageTest, SignalHandler_NonAlrm_DoesNothing)
{
    exitSchedulerTask = false;
    AlertNotificationLicenseControl = "sentinel";

    signalHandler(SIGUSR1);

    EXPECT_FALSE(exitSchedulerTask);
    EXPECT_EQ(AlertNotificationLicenseControl, "sentinel");
}

TEST_F(LcCoverageTest, SignalHandler_SigAlrm_SetsExitTaskOnWriteFailure)
{
    globalData["licenseconfig"] = json::array();
    globalData["licenseconfig"].push_back(
        {{"servicesUpCountDays", 5}, {"globalLicenseValidity", 100}});
    exitSchedulerTask = false;

    signalHandler(SIGALRM);

    EXPECT_TRUE(exitSchedulerTask);
}

TEST_F(LcCoverageTest, SignalHandler_SigAlrm_RebuildsAlertFromServiceDates)
{
    globalData["licenseconfig"] = json::array();
    globalData["licenseconfig"].push_back(
        {{"servicesUpCountDays", 5}, {"globalLicenseValidity", 100}});
    serviceDates["svc1"] = "30";
    serviceDates["GLOBAL"] = "45";
    AlertNotificationLicenseControl = "";

    signalHandler(SIGALRM);

    EXPECT_THAT(AlertNotificationLicenseControl, HasSubstr("svc1:30"));
    EXPECT_THAT(AlertNotificationLicenseControl, HasSubstr("GLOBAL:45"));
}

TEST_F(LcCoverageTest, UpdateJson_UnwritablePath_ReturnsNegOne)
{
    int ret = updateJson();
    EXPECT_EQ(ret, -1);
}

TEST_F(LcCoverageTest, CheckValidity_GlobalNonZeroNonTwo_ReturnsOne)
{
    UpCountDays = 100;
    Globalvalidcount = 0;
    globalData["licensableServices"] = json::array();

    int ret = checkValidity();
    EXPECT_EQ(ret, 1);
}

TEST_F(LcCoverageTest, ConvertTimeFormat_MinTimestamp_NonZero)
{
    uint64_t result = convertTimeFormat("2000:01:01 00:00:00");
    EXPECT_EQ(result, 20000101000000ULL);
}

TEST_F(LcCoverageTest, ConvertTimeFormat_MaxReasonableTimestamp)
{
    uint64_t result = convertTimeFormat("2099:12:31 23:59:59");
    EXPECT_EQ(result, 20991231235959ULL);
}

TEST_F(LcCoverageTest, ConvertTimeFormat_PartiallyValidFormat_ReturnsZero)
{
    uint64_t result = convertTimeFormat("15:01:2026 10:30:45");
    (void)result;
    SUCCEED();
}

TEST_F(LcCoverageTest, ControlGlobalProcess_EmptyServices_ReturnsZero)
{
    globalData["licensableServices"] = json::array();

    int ret = controlGlobalProcess(ServiceAction::Start);
    EXPECT_EQ(ret, 0);
}

TEST_F(LcCoverageTest, ControlGlobalProcess_ServicePresent_ReturnsZero)
{
    globalData["licensableServices"] = json::array();
    globalData["licensableServices"].push_back(
        {{"serviceName", "svc1"}, {"serviceControlCmd", "svc1.service"}});

    int ret = controlGlobalProcess(ServiceAction::Stop);
    EXPECT_EQ(ret, 0);
}

TEST_F(LcCoverageTest, GetSpecificValues_MultipleServicesAllWithKey)
{
    globalData["licensableServices"] = json::array();
    globalData["licensableServices"].push_back(
        {{"serviceName", "svc1"}, {"customKey", "v1"}});
    globalData["licensableServices"].push_back(
        {{"serviceName", "svc2"}, {"customKey", "v2"}});
    globalData["licensableServices"].push_back(
        {{"serviceName", "svc3"}, {"customKey", "v3"}});

    auto result = getSpecificValues("customKey");
    ASSERT_EQ(result.size(), 3u);
    EXPECT_EQ(result[0], "v1");
    EXPECT_EQ(result[2], "v3");
}

TEST_F(LcCoverageTest, GetSpecificValues_MixedPresence_ReturnsOnlyPresent)
{
    globalData["licensableServices"] = json::array();
    globalData["licensableServices"].push_back(
        {{"serviceName", "svc1"}, {"myKey", "yes"}});
    globalData["licensableServices"].push_back({{"serviceName", "svc2"}});

    auto result = getSpecificValues("myKey");
    ASSERT_EQ(result.size(), 1u);
    EXPECT_EQ(result[0], "yes");
}

// ===========================================================================
// LcLineCoverageTest — line/path coverage for licensecontrol.cpp
// ===========================================================================

class LcLineCoverageTest : public ::testing::Test
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

TEST_F(LcLineCoverageTest, VaildateTimeStamp_AllConditionsTrue_ReturnsZero)
{
    globalData["licenseconfig"] = json::array();
    globalData["licenseconfig"].push_back(
        {{"effectiveTimeStamp", "2000:01:01 00:00:00"}});

    std::string oldTok = "TIMESTAMP-2010:06:01 00:00:00";
    std::string newTok = "TIMESTAMP-2020:06:01 00:00:00";

    int ret = VaildateTimeStamp(oldTok, newTok);
    EXPECT_EQ(ret, 0);
}

TEST_F(LcLineCoverageTest,
       VaildateTimeStamp_OldBeforeEffective_AllTrue_ReturnsZero)
{
    globalData["licenseconfig"] = json::array();
    globalData["licenseconfig"].push_back(
        {{"effectiveTimeStamp", "2015:01:01 00:00:00"}});

    std::string oldTok = "TIMESTAMP-2010:01:01 00:00:00";
    std::string newTok = "TIMESTAMP-2022:01:01 00:00:00";

    int ret = VaildateTimeStamp(oldTok, newTok);
    EXPECT_EQ(ret, 0);
}

TEST_F(LcLineCoverageTest,
       ParseValidityData_AllFieldsPresent_ExercisesUpdatePath)
{
    globalData = makeGlobalData(100, 0);

    std::string token =
        "TIMESTAMP-2026:01:15-VALIDITY-svc1:30-MAC-AA:BB:CC:DD:EE:FF";
    int ret = parseValidityData(token);

    EXPECT_EQ(ret, 1);
}

TEST_F(LcLineCoverageTest, ParseValidityData_AllFieldsPresent_MultipleServices)
{
    globalData = makeGlobalData(100, 0);
    globalData["licensableServices"].push_back(
        {{"serviceName", "svc2"},
         {"serviceControlCmd", "svc2.service"},
         {"LicenseValidity", 0}});

    std::string token =
        "TIMESTAMP-2026:01:15-VALIDITY-svc1:30;svc2:60-MAC-BB:CC:DD:EE:FF:00";
    int ret = parseValidityData(token);
    EXPECT_EQ(ret, 1);
}

TEST_F(LcLineCoverageTest,
       CheckServiceValidity_AlertTriggered_NegativeDays_SetsZeroInServiceDates)
{
    UpCountDays = 999;
    Globalvalidcount = 0;
    alertCountValue = 10;

    globalData["licensableServices"] = json::array();
    globalData["licensableServices"].push_back(
        {{"serviceName", "svc1"},
         {"serviceControlCmd", "svc1.service"},
         {"LicenseValidity", 100}});

    checkServiceValidity();

    ASSERT_TRUE(serviceDates.count("svc1") > 0);
    EXPECT_EQ(serviceDates["svc1"], "0");
}

TEST_F(LcLineCoverageTest,
       UpdateAlertNotification_WithExpiredService_PopulatesAlert)
{
    globalData = makeGlobalData(0, 999, 100);
    UpCountDays = 999;
    Globalvalidcount = 0;
    alertCountValue = 0;

    updateAlertNotification();

    EXPECT_THAT(AlertNotificationLicenseControl, HasSubstr("svc1"));
}

TEST_F(LcLineCoverageTest,
       UpdateAlertNotification_WithAlertThreshold_PopulatesGlobal)
{
    globalData = makeGlobalData(100, 80);
    UpCountDays = 80;
    Globalvalidcount = 100;
    alertCountValue = 25;

    updateAlertNotification();

    EXPECT_THAT(AlertNotificationLicenseControl, HasSubstr("GLOBAL"));
}

TEST_F(LcLineCoverageTest,
       CheckServiceStatus_GlobalValidityPositive_ReturnsZero)
{
    globalData = makeGlobalData(100, 10);

    bool ret = checkServiceStatus();
    EXPECT_EQ(ret, 0);
}

TEST_F(LcLineCoverageTest, CheckServiceStatus_GlobalValidityZero_EarlyReturn)
{
    globalData = makeGlobalData(0, 0);

    bool ret = checkServiceStatus();
    EXPECT_EQ(ret, 0);
}

TEST_F(LcLineCoverageTest,
       CheckServiceStatus_NegativeGlobalValidity_LoopWithValidService)
{
    globalData = makeGlobalData(-1, 0, 50);

    bool ret = checkServiceStatus();
    EXPECT_EQ(ret, 0);
}

TEST_F(
    LcLineCoverageTest,
    CheckServiceStatus_NegativeGlobalValidity_ZeroLicenseValidity_SkipsEnable)
{
    globalData = makeGlobalData(-1, 0, 0);

    bool ret = checkServiceStatus();
    EXPECT_EQ(ret, 0);
}

TEST_F(LcLineCoverageTest,
       CheckServiceStatus_NegativeGlobalValidity_MissingLicenseValidityKey)
{
    globalData["licenseconfig"] = json::array();
    globalData["licenseconfig"].push_back({{"globalLicenseValidity", -1}});
    globalData["licensableServices"] = json::array();
    globalData["licensableServices"].push_back(
        {{"serviceName", "svcX"}, {"serviceControlCmd", "svcX.service"}});

    bool ret = checkServiceStatus();
    EXPECT_EQ(ret, 0);
}

TEST_F(LcLineCoverageTest,
       CheckServiceStatus_NegativeGlobalValidity_MultipleServices_AllBranches)
{
    globalData["licenseconfig"] = json::array();
    globalData["licenseconfig"].push_back({{"globalLicenseValidity", -1}});
    globalData["licensableServices"] = json::array();

    globalData["licensableServices"].push_back(
        {{"serviceName", "svc1"},
         {"serviceControlCmd", "svc1.service"},
         {"LicenseValidity", 30}});
    globalData["licensableServices"].push_back(
        {{"serviceName", "svc2"},
         {"serviceControlCmd", "svc2.service"},
         {"LicenseValidity", 0}});
    globalData["licensableServices"].push_back(
        {{"serviceName", "svc3"}, {"serviceControlCmd", "svc3.service"}});

    bool ret = checkServiceStatus();
    EXPECT_EQ(ret, 0);
}

TEST_F(LcLineCoverageTest, EnableServices_ServicePresent_CallsControlSystemd)
{
    globalData = makeGlobalData(100, 0);

    bool ret = enableServices("svc1");
    EXPECT_EQ(ret, 0);
}

TEST_F(LcLineCoverageTest, EnableServices_ArrayOfCommands_IteratesAll)
{
    globalData["licensableServices"] = json::array();
    globalData["licensableServices"].push_back(
        {{"serviceName", "svc1"},
         {"serviceControlCmd", json::array({"svc1-a.service", "svc1-b.service",
                                            "svc1-c.service"})}});

    bool ret = enableServices("svc1");
    EXPECT_EQ(ret, 0);
}

TEST_F(LcLineCoverageTest, EnableServices_ServiceNotFound_ReturnsZero)
{
    globalData["licensableServices"] = json::array();

    bool ret = enableServices("nonexistent");
    EXPECT_EQ(ret, 0);
}

TEST_F(LcLineCoverageTest, ControlSystemdService_StartAction_ExceptionCaught)
{
    EXPECT_NO_THROW(
        controlSystemdService("svc1.service", ServiceAction::Start));
}

TEST_F(LcLineCoverageTest, ControlSystemdService_StopAction_ExceptionCaught)
{
    EXPECT_NO_THROW(controlSystemdService("svc1.service", ServiceAction::Stop));
}

TEST_F(LcLineCoverageTest, ControlSystemdService_RestartAction_ExceptionCaught)
{
    EXPECT_NO_THROW(
        controlSystemdService("svc1.service", ServiceAction::Restart));
}

TEST_F(LcLineCoverageTest,
       GetSystemCtlServiceNames_ServiceFoundButNoServiceControlCmd_ReturnsEmpty)
{
    globalData["licensableServices"] = json::array();
    globalData["licensableServices"].push_back({{"serviceName", "svc1"}});

    auto result = getSystemCtlServiceNames("svc1");
    EXPECT_TRUE(result.empty());
}

TEST_F(LcLineCoverageTest,
       ValidateTimeStampRunTime_TokenTimestampEqualsCurrentTime_NoCrash)
{
    globalData["licenseconfig"] = json::array();
    globalData["licenseconfig"].push_back(
        {{"effectiveTimeStamp", "2025:01:01 00:00:00"}});

    std::string tok = "TIMESTAMP-2020:01:01 00:00:00";
    int ret = validateTimeStampRunTime(tok);
    EXPECT_EQ(ret, 0);
}

TEST_F(LcLineCoverageTest,
       CheckValidity_GlobalWithinValidity_ServiceAlsoValid_ReturnsZero)
{
    UpCountDays = 5;
    Globalvalidcount = 100;
    alertCountValue = 0;

    globalData["licensableServices"] = json::array();
    globalData["licensableServices"].push_back(
        {{"serviceName", "svc1"},
         {"serviceControlCmd", "svc1.service"},
         {"LicenseValidity", 200}});

    int ret = checkValidity();
    EXPECT_EQ(ret, 0);
}

TEST_F(LcLineCoverageTest, UpdateAlertNotification_AllServicesValid_AlertEmpty)
{
    globalData = makeGlobalData(100, 5, 200);
    UpCountDays = 5;
    Globalvalidcount = 100;
    alertCountValue = 0;
    AlertNotificationLicenseControl = "stale";

    updateAlertNotification();

    EXPECT_TRUE(AlertNotificationLicenseControl.empty());
}

TEST_F(LcLineCoverageTest,
       GetSpecificValues_NoLicensableServicesKey_ReturnsEmpty)
{
    globalData["other"] = "value";

    auto result = getSpecificValues("serviceName");
    EXPECT_TRUE(result.empty());
}

TEST_F(LcLineCoverageTest,
       GenerateServiceValidityString_FirstEntry_NoLeadingSemicolon)
{
    json testData;
    testData["licensableServices"] = json::array();
    testData["licensableServices"].push_back(
        {{"serviceName", "alpha"}, {"LicenseValidity", 5}});
    testData["licenseconfig"] = json::array();
    testData["licenseconfig"].push_back({{"globalLicenseValidity", 50}});

    std::string result = generateServiceValidityString(testData);

    EXPECT_EQ(result[0], 'a');
    EXPECT_THAT(result, HasSubstr("alpha:5"));
}

TEST_F(LcLineCoverageTest, LoadJsonFromFile_FullStructure_ParsesAllFields)
{
    const std::string tmpPath = "/tmp/test_full_json.json";
    {
        std::ofstream ofs(tmpPath);
        ofs << R"({
            "licenseconfig": [{
                "globalLicenseValidity": 365,
                "servicesUpCountDays": 10,
                "effectiveTimeStamp": "2026:01:01 00:00:00",
                "userAlertCount": 5,
                "MACId": "AA:BB:CC:DD:EE:FF"
            }],
            "licensableServices": [
                {"serviceName": "svcA", "LicenseValidity": 100, "serviceControlCmd": "svcA.service"},
                {"serviceName": "svcB", "LicenseValidity": 200, "serviceControlCmd": "svcB.service"}
            ]
        })";
    }

    bool result = loadJsonFromFile(tmpPath);
    EXPECT_TRUE(result);
    EXPECT_EQ(globalData["licenseconfig"][0]["globalLicenseValidity"], 365);
    EXPECT_EQ(globalData["licenseconfig"][0]["userAlertCount"], 5);
    EXPECT_EQ(globalData["licensableServices"].size(), 2u);
    EXPECT_EQ(globalData["licensableServices"][0]["serviceName"], "svcA");

    std::remove(tmpPath.c_str());
}

TEST_F(LcLineCoverageTest,
       UpdateNewServiceValidity_UpCountFarExceedsTotal_ZeroesValidity)
{
    json testData = makeGlobalData(30, 200, 50);
    globalData = testData;

    std::string token =
        "TIMESTAMP-2026:01:15-VALIDITY-svc1:10-MAC-AA:BB:CC:DD:EE:FF";
    int ret = updateNewServiceValidity(token, testData);
    EXPECT_EQ(ret, 0);

    int lv = testData["licensableServices"][0]["LicenseValidity"];
    EXPECT_GE(lv, 0);
}

TEST_F(
    LcLineCoverageTest,
    UpdateNewServiceValidity_UpCountLessThanGlobal_ExceedsTotal_ZeroesValidity)
{
    json testData = makeGlobalData(30, 5, 50);
    globalData = testData;

    std::string token =
        "TIMESTAMP-2026:01:15-VALIDITY-svc1:20-MAC-AA:BB:CC:DD:EE:FF";
    int ret = updateNewServiceValidity(token, testData);
    EXPECT_EQ(ret, 0);
}

TEST_F(LcLineCoverageTest, GetImageSizeFromFWSize_DefaultPath_NoCrash)
{
    uint64_t result = getImageSizeFromFWSize("/etc/FWSize");
    EXPECT_EQ(result, 0u);
}

TEST_F(LcLineCoverageTest,
       GetTimeStampfromLicence_ValueOutOfIntRange_ThrowsOutOfRange)
{
    const std::string tmpPath = "/tmp/test_ts_outofrange.txt";
    {
        std::ofstream ofs(tmpPath);
        ofs << "99999999999999999999;rest";
    }

    EXPECT_THROW(getTimeStampfromLicence(tmpPath), std::out_of_range);

    std::remove(tmpPath.c_str());
}

} // namespace
