
/*****************************************************************
 * License control Manager
 * licensecontrol.hpp
 *
 * @brief D-Bus service designed to manage and monitor the usage of
 * licensed resources the system, ensuring limitations and oversight
 * are maintained.
 *
 * Author: Manikandan.V manikandanv@ami.com
 *
 ******************************************************************/

#pragma once

#include <boost/process/child.hpp>
#include <boost/process/io.hpp>
#include <iostream>
#include <nlohmann/json.hpp>
#include <phosphor-logging/elog-errors.hpp>
#include <phosphor-logging/elog.hpp>
#include <phosphor-logging/lg2.hpp>
#include <phosphor-logging/log.hpp>
#include <sdbusplus/bus.hpp>
#include <sdbusplus/sdbus.hpp>
#include <sdbusplus/server/manager.hpp>
#include <sdbusplus/server/object.hpp>
#include <xyz/openbmc_project/Common/error.hpp>
#include <xyz/openbmc_project/License/LicenseControl/server.hpp>

using namespace phosphor::logging;
using json = nlohmann::json;
using InternalFailure =
    sdbusplus::xyz::openbmc_project::Common::Error::InternalFailure;
using InvalidArgument =
    sdbusplus::xyz::openbmc_project::Common::Error::InvalidArgument;
using IfcBase =
    sdbusplus::xyz::openbmc_project::License::server::LicenseControl;
using Argument = xyz::openbmc_project::Common::InvalidArgument;

// Define a macro to control debug prints
#define DEBUG_ENABLED false

#if DEBUG_ENABLED
#define DEBUG(expression)                                                      \
  do {                                                                         \
    expression;                                                                \
  } while (0)
#else
#define DEBUG(expression) ((void)0)
#endif

const std::string licenseJsonFilePath = "/etc/license-control/license.json";
const std::string licenseValidityTokenPath = "/etc/license-control/token";
const std::string newLicenseValidityTokenPath = "/tmp/license-control/token";
const std::string licensePublicKey = "/tmp/license-control/public.pem";
const std::string UPLOADED_NEWKEYPATH = "/tmp/license-control/";
const std::string UPLOADED_KEY_FILEFORMAT = ".key";
const char COLON = ':';
const char SEMICOLON = ';';
const uint32_t maxUserAlertCountValue = 60;
const uint32_t secToTriggerValidation = 86400;

extern std::map<std::string, std::string> serviceDates;
extern int decriptLicenseFile(const std::string &encryptLicencefile);
extern std::string getLicenseEncFile();
extern int getPublicKey();
extern json globalData;
extern bool exitSchedulerTask;
extern int64_t UpCountDays;
extern int64_t Globalvalidcount;
extern uint32_t alertCountValue;
extern std::string AlertNotificationLicenseControl;

std::vector<std::string> getServiceCtlCommands(const std::string &serviceName,
                                               const std::string &status);
int controlGlobalProcess(const std::string &actionType);
int parseValidityData(const std::string &input);
uint64_t convertTimeFormat(const std::string &timestampString);
std::string getCurrentTimestamp();
std::string extractDataFromToken(const std::string &inputString,
                                 const std::string &targetTimestamp);
int VaildateTimeStamp(const std::string &tokenString,
                      const std::string &NewtokenString);
int validateTimeStampRunTime(std::string &tokenString);
int checkValidity();
void updateAlertNotification();
int updateJson();
uint32_t getMinValidityDate();

class LicenseControlImp : public IfcBase {
private:
  std::string licenseKeyAtBmc;

  bool writeLicenseKeyToFile();

public:
  LicenseControlImp(sdbusplus::bus_t &bus, const char *path);

  int64_t servicesUpCountDays() override;

  int64_t globalLicenseValidity() override;

  bool addLicenseKey() override;

  std::string getLicenseKey() override;

  std::string alertMessage() const override;

  uint32_t userAlertCount(uint32_t value) override {
    uint32_t val;

    if (value == IfcBase::userAlertCount()) {
      return value;
    }

    val = getMinValidityDate();
    if ((value > maxUserAlertCountValue) || (value >= val)) {
      lg2::error("Fail to set userAlertCount");
      elog<InvalidArgument>(Argument::ARGUMENT_NAME("userAlertCount"),
                            Argument::ARGUMENT_VALUE("error"));
    }

    globalData["licenseconfig"][0]["userAlertCount"] = alertCountValue = value;

    val = updateJson();
    if (val != 0) {
      std::cerr << "Failed to open the license.json file for writing."
                << std::endl;
    }

    updateAlertNotification();
    val = IfcBase::userAlertCount(value);
    return val;
  }
};
