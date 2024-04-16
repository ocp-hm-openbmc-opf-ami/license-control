
/*****************************************************************
 * License control Manager
 * licenseDbus.cpp
 *
 * @brief D-Bus service designed to manage and monitor the usage of
 * licensed resources the system, ensuring limitations and oversight
 * are maintained.
 *
 * Author: Manikandan.V manikandanv@ami.com
 *
 ******************************************************************/

#include "include/licensecontrol.hpp"
#include <filesystem>
#include <fstream>
#include <iostream>
#include <sdbusplus/bus.hpp>
#include <sdbusplus/server/object.hpp>

namespace fs = std::filesystem;

const size_t GLOBAL_PREFIX_LENGTH = 7;
const size_t TMP_BUFFER_LENGTH = 128;

using DbusUserPropVariant =
    std::variant<std::vector<std::string>, std::string, bool>;

const std::string networkService = "xyz.openbmc_project.Network";
const std::string networkPath = "/xyz/openbmc_project/network";

void updateAlertNotification() {
  AlertNotificationLicenseControl = "";
  UpCountDays = globalData["licenseconfig"][0]["servicesUpCountDays"];
  Globalvalidcount = globalData["licenseconfig"][0]["globalLicenseValidity"];

  serviceDates.clear();
  checkValidity();

  for (const auto &entry : serviceDates) {
    AlertNotificationLicenseControl += (entry.first + ":" + entry.second + ";");
  }
  DEBUG(std::cout << "AlertNotificationLicenseControl: "
                  << AlertNotificationLicenseControl << std::endl;);
}

void removeTempFiles() {
  for (const auto &entry : fs::directory_iterator(UPLOADED_NEWKEYPATH)) {
    if (fs::is_regular_file(entry.path())) {
      try {
        fs::remove(entry.path());
      } catch (const std::exception &e) {
        std::cerr << "Error removing file " << entry.path() << ": " << e.what()
                  << std::endl;
      }
    }
  }
}

int VaildateTimeStamp(const std::string &tokenString,
                      const std::string &NewtokenString) {
  std::string currentTimeStamp = getCurrentTimestamp();
  std::string oldTimeStamp = extractDataFromToken(tokenString, "TIMESTAMP");
  std::string newTimeStamp = extractDataFromToken(NewtokenString, "TIMESTAMP");
  std::string oldEffectiveTimestamp =
      globalData["licenseconfig"][0]["effectiveTimeStamp"];

  DEBUG(std::cout << "PreviousTIMESTAMP: " << oldTimeStamp
                  << "\noldEffectiveTimestamp: " << oldEffectiveTimestamp
                  << "\ncurrentTimeStamp" << currentTimeStamp
                  << "\nnewTimeStamp: " << newTimeStamp << std::endl;);

  DEBUG(std::cout << "currentTimeStamp > newTimeStamp : "
                  << (convertTimeFormat(currentTimeStamp) >
                      convertTimeFormat(newTimeStamp))
                  << std::endl;);
  DEBUG(std::cout << "currentTimeStamp > oldEffectiveTimestamp : "
                  << (convertTimeFormat(currentTimeStamp) >
                      convertTimeFormat(oldEffectiveTimestamp))
                  << std::endl;);
  DEBUG(std::cout << "oldTimeStamp < newTimeStamp : "
                  << (convertTimeFormat(oldTimeStamp) <
                      convertTimeFormat(newTimeStamp))
                  << std::endl;);

  if ((convertTimeFormat(currentTimeStamp) > convertTimeFormat(newTimeStamp)) &&
      ((convertTimeFormat(currentTimeStamp) >
        convertTimeFormat(oldEffectiveTimestamp)) &&
       (convertTimeFormat(oldTimeStamp) < convertTimeFormat(newTimeStamp)))) {
    return 0;
  }

  return -1;
}

bool MacAddrCamp(const std::string &str1, const std::string &str2) {

  if (str1.length() != str2.length()) {
    return false;
  }

  return std::equal(
      str1.begin(), str1.end(), str2.begin(),
      [](char c1, char c2) { return std::tolower(c1) == std::tolower(c2); });
}

int getDbusProperty(const std::string &service, const std::string &objPath,
                    const std::string &interface, const std::string &property,
                    DbusUserPropVariant &value) {
  auto bus = sdbusplus::bus::new_default();
  try {
    auto method = bus.new_method_call(service.c_str(), objPath.c_str(),
                                      "org.freedesktop.DBus.Properties", "Get");

    method.append(interface, property);

    auto reply = bus.call(method);
    reply.read(value);
  } catch (const sdbusplus::exception_t &e) {
    std::cerr << "Fail to getDbusProperty" << std::endl;
    return -1;
  }
  return 0;
}

int ValidateMacAddr(const std::string &LicMacAddr) {
  std::string BMCMacAddr;

  auto bus = sdbusplus::bus::new_default_system();

  sdbusplus::message::message msg = bus.new_method_call(
      "xyz.openbmc_project.ObjectMapper", "/xyz/openbmc_project/object_mapper",
      "xyz.openbmc_project.ObjectMapper", "GetSubTreePaths");

  std::vector<std::string> stringArray = {
      "xyz.openbmc_project.Network.EthernetInterface"};
  msg.append(networkPath, 0, stringArray);

  auto reply = bus.call(msg);
  if (reply.is_method_error()) {
    std::cerr << "D-Bus method call error: " << reply.get_error() << std::endl;
    return -1;
  }

  std::vector<std::string> objectPaths;
  reply.read(objectPaths);

  for (const auto &networkObjpath : objectPaths) {
    DbusUserPropVariant variant;
    if (getDbusProperty(networkService, networkObjpath,
                        "xyz.openbmc_project.Network.EthernetInterface",
                        "InterfaceName", variant) != 0) {
      return -1;
    }

    std::string Interface = std::get<std::string>(variant);
    size_t found = Interface.find("eth");

    if (found != std::string::npos) {
      if (getDbusProperty(networkService, networkObjpath,
                          "xyz.openbmc_project.Network.MACAddress",
                          "MACAddress", variant) != 0) {
        return -1;
      }

      BMCMacAddr = std::get<std::string>(variant);
      DEBUG(std::cout << "LicMacAddr: " << LicMacAddr
                      << "\nBMCMacAddr :" << BMCMacAddr << std::endl;);

      if (MacAddrCamp(LicMacAddr, BMCMacAddr)) {
        return 0;
      }
    }
  }

  return -1;
}

int getTimeStampfromLicence(const std::string &filePath) {
  std::ifstream file(filePath);

  if (!file.is_open()) {
    std::cerr << "Error opening file: " << filePath << std::endl;
    return -1;
  }

  std::string line;
  if (std::getline(file, line)) {
    std::istringstream iss(line);
    std::string strTimeStamp;
    std::getline(iss, strTimeStamp, ';');

    int timeStamp;
    try {
      timeStamp = std::stoi(strTimeStamp);
      file.close();
      return timeStamp;
    } catch (const std::invalid_argument &e) {
      std::cerr << "Error converting string to integer: " << e.what()
                << std::endl;
      file.close();
      return -1;
    }
  } else {
    std::cerr << "Error reading from file: " << filePath << std::endl;
    file.close();
    return -1;
  }
}

int updateNewServiceValidity(const std::string &inputString, json &jsonData) {
  int extGlobalLicenseValidity =
      jsonData["licenseconfig"][0]["globalLicenseValidity"];
  int extupCountDays = jsonData["licenseconfig"][0]["servicesUpCountDays"];
  bool serviceFound = false;

  json existingServiceJsonData = jsonData["licensableServices"];

  DEBUG(std::cout << "Existing Service Validity Information:" << std::endl;);
  DEBUG(std::cout << existingServiceJsonData.dump(2) << std::endl;);

  for (auto &service : jsonData["licensableServices"]) {
    service["LicenseValidity"] = 0;
  }

  parseValidityData(inputString);

  DEBUG(std::cout << "New Service Validity Information:" << std::endl;);
  DEBUG(std::cout << jsonData.dump(2) << std::endl;);

  // Add days for services that already have validity in jsonData
  for (auto &existingServiceInfo : existingServiceJsonData) {
    int existingServiceLicenseValidity = existingServiceInfo["LicenseValidity"];

    std::string serviceName = existingServiceInfo["serviceName"];

    DEBUG(std::cout << "OldexistingLicenseValidity "
                    << existingServiceLicenseValidity + extGlobalLicenseValidity
                    << " BMC have run existing upCountDays " << extupCountDays
                    << " remining license validity "
                    << (existingServiceLicenseValidity +
                        extGlobalLicenseValidity) -
                           extupCountDays
                    << " for service name " << serviceName << std::endl;);

    for (auto &serviceInfo : jsonData["licensableServices"]) {
      if (serviceInfo["serviceName"] == existingServiceInfo["serviceName"]) {

        int currentLicenseValidity = serviceInfo["LicenseValidity"];
        int updatedLicenseValidity = 0;

        if (extupCountDays >= extGlobalLicenseValidity) {
          updatedLicenseValidity =
              (extupCountDays >=
               extGlobalLicenseValidity + existingServiceLicenseValidity)
                  ? 0
                  : (extGlobalLicenseValidity +
                     existingServiceLicenseValidity) -
                        extupCountDays;
        } else {
          updatedLicenseValidity =
              (extupCountDays >=
               extGlobalLicenseValidity + existingServiceLicenseValidity)
                  ? 0
                  : existingServiceLicenseValidity;
        }
        DEBUG(std::cout << "currentLicenseValidity - " << currentLicenseValidity
                        << "extendedLicenseValidity - "
                        << currentLicenseValidity + updatedLicenseValidity
                        << std::endl;);
        serviceInfo["LicenseValidity"] =
            currentLicenseValidity + updatedLicenseValidity;
        serviceFound = true;
        break;
      }
    }

    if (!serviceFound) {
      jsonData["licensableServices"].push_back(existingServiceInfo);
    }
  }

  DEBUG(std::cout << "Updated Service Validity Information:" << std::endl;);
  DEBUG(std::cout << jsonData["licensableServices"].dump(2) << std::endl;);

  size_t globalColonPos = inputString.find("GLOBAL:");
  if (globalColonPos != std::string::npos) {
    int extendedGlobalLicenseValidity =
        extGlobalLicenseValidity - extupCountDays +
        std::stoi(inputString.substr(globalColonPos + GLOBAL_PREFIX_LENGTH));
    jsonData["licenseconfig"][0]["globalLicenseValidity"] =
        (extupCountDays >= extGlobalLicenseValidity)
            ? std::stoi(
                  inputString.substr(globalColonPos + GLOBAL_PREFIX_LENGTH))
            : extendedGlobalLicenseValidity;
  } else {
    jsonData["licenseconfig"][0]["globalLicenseValidity"] =
        (extupCountDays >= extGlobalLicenseValidity)
            ? 0
            : (extGlobalLicenseValidity - extupCountDays);
  }

  // Reset servicesUpCountDays to 0 since new key is added
  jsonData["licenseconfig"][0]["servicesUpCountDays"] = 0;

  return 0;
}

bool isServiceRunning(const std::string &serviceName) {
  std::string command = "systemctl is-active " + serviceName;
  std::shared_ptr<FILE> pipe(popen(command.c_str(), "r"), pclose);

  if (!pipe) {
    std::cerr << "Error executing command." << std::endl;
    return false;
  }

  char buffer[TMP_BUFFER_LENGTH];
  std::string result = "";
  while (!feof(pipe.get())) {
    if (fgets(buffer, TMP_BUFFER_LENGTH, pipe.get()) != nullptr)
      result += buffer;
  }

  result.erase(std::remove(result.begin(), result.end(), '\n'), result.end());

  return result == "active";
}

bool enableServices(const std::string &serviceName) {

  int result = 0;

  std::vector<std::string> startServiceCommands =
      getServiceCtlCommands(serviceName, "start");

  for (const auto &command : startServiceCommands) {
    std::cout << command << " ";

    result = std::system(command.c_str());
    if (result != 0) {
      std::cerr << "Error executing command: " << command << std::endl;
      return result;
    }
  }

  return 0;
}

bool checkServiceStatus() {

  int enableResult = 0, ret = 0;
  int globalLicenseValidity =
      globalData["licenseconfig"][0]["globalLicenseValidity"];

  if (globalLicenseValidity >= 0) {
    ret = controlGlobalProcess("start");
    if (ret != 0) {
      std::cerr << "Error enabling Global services " << std::endl;
      return ret;
    }
    return 0;
  }

  // Iterate over the services in the JSON file
  if (globalData.contains("licensableServices") &&
      globalData["licensableServices"].is_array()) {
    for (const auto &service : globalData["licensableServices"]) {
      if (service.contains("serviceName") &&
          service["serviceName"].is_string()) {
        std::string serviceName = service["serviceName"];

        std::cout << "service name " << serviceName << std::endl;

        // Check LicenseValidity
        if (service.contains("LicenseValidity") &&
            service["LicenseValidity"].is_number()) {
          uint64_t serviceLicenseValidity =
              service["LicenseValidity"].get<uint64_t>();

          if (serviceLicenseValidity != 0) {
            if (!isServiceRunning(serviceName)) {
              std::cout << "Service '" << serviceName
                        << "' is not running. Starting the service."
                        << std::endl;
              enableResult = enableServices(serviceName);
            } else {
              std::cout << "Service '" << serviceName << "' is already running."
                        << std::endl;
            }

            if (enableResult == 0) {
              std::cout << "Service '" << serviceName
                        << "' enabled successfully." << std::endl;
            } else {
              std::cerr << "Error enabling service '" << serviceName << "'."
                        << std::endl;
              return 1;
            }

          } else {
            std::cout << "LicenseValidity for service '" << serviceName
                      << "' is zero. Skipping enable." << std::endl;
          }
          serviceLicenseValidity = 0;
        } else {
          std::cerr << "Invalid JSON format for service '" << serviceName
                    << "'. Skipping." << std::endl;
        }
      }
    }
  }
  return 0;
}

std::string readTokenFromFile(const std::string &filename) {
  std::ifstream file(filename);
  std::string content = "";

  if (file.is_open()) {
    // Read the entire file content into a string
    content.assign((std::istreambuf_iterator<char>(file)),
                   std::istreambuf_iterator<char>());
    file.close();
  } else {
    std::cerr << "Unable to open file: " << filename << std::endl;
  }

  return content;
}

bool LicenseControlImp::writeLicenseKeyToFile() {

  int retVal = 0;
  std::string newLicenseKeyFilePath = "";
  std::string tokenString = "";
  std::string newTokenString = "";
  std::string newToken = "";
  std::string BMCMacAddr = "";

  newLicenseKeyFilePath = getLicenseEncFile();
  if (newLicenseKeyFilePath.empty()) {
    removeTempFiles();
    return false;
  }

  retVal = getPublicKey();
  if (retVal < 0) {
    std::cerr << "Failed to get public key for firmware" << std::endl;
    removeTempFiles();
    return false;
  }

  if (decriptLicenseFile(newLicenseKeyFilePath) != 0) {
    std::cerr << "Failed to decrypt user uploaded file" << std::endl;
    removeTempFiles();
    return false;
  }

  tokenString = readTokenFromFile(licenseValidityTokenPath);
  newTokenString = readTokenFromFile(newLicenseValidityTokenPath);

  if (VaildateTimeStamp(tokenString, newTokenString) != 0) {
    std::cout << "TimeStamp error : Invalid Key" << std::endl;
    removeTempFiles();
    return false;
  }

  std::ifstream newTokenPath(newLicenseValidityTokenPath);
  if (!newTokenPath) {
    std::cerr << "Error opening New token: " << newLicenseValidityTokenPath
              << std::endl;
    removeTempFiles();
    return false;
  }

  std::stringstream tokenbuffer;
  tokenbuffer << newTokenPath.rdbuf();
  newToken = tokenbuffer.str();
  newTokenPath.close();

  size_t MacAddrPos = newToken.find("-MAC-");
  if (MacAddrPos != std::string::npos) {
    BMCMacAddr = newToken.substr(MacAddrPos + 5, 17);
    if (ValidateMacAddr(BMCMacAddr) != 0) {
      std::cerr << "Error MAC address not matched" << std::endl;
      removeTempFiles();
      return false;
    }
  } else {
    removeTempFiles();
    return false;
  }

  retVal = updateNewServiceValidity(newToken, globalData);
  if (retVal != 0) {
    std::cerr << "Error in Updating global json data" << std::endl;
  }

  retVal = updateJson();
  if (retVal != 0) {
    std::cerr << "Failed to open the license.json file for writing."
              << std::endl;
    removeTempFiles();
    return false;
  }

  // Update the old token to latest
  std::ifstream sourceFile(newLicenseValidityTokenPath, std::ios::binary);
  std::ofstream destinationFile(licenseValidityTokenPath, std::ios::binary);

  if (!sourceFile || !destinationFile) {
    std::cerr << "Error opening files." << std::endl;
    removeTempFiles();
    return false;
  }

  destinationFile << sourceFile.rdbuf();
  if (destinationFile.fail()) {
    std::cerr << "Error Failed to copy file content." << std::endl;
    sourceFile.close();
    destinationFile.close();
    removeTempFiles();
    return false;
  }
  exitSchedulerTask = false;

  sourceFile.close();
  destinationFile.close();

  updateAlertNotification();

  // restart the services based on new key file uploaded
  retVal = checkServiceStatus();
  if (retVal != 0) {
    std::cerr << "Error Initializing licensable services" << std::endl;
    removeTempFiles();
    return false;
  }

  removeTempFiles();
  return true;
}

LicenseControlImp::LicenseControlImp(sdbusplus::bus_t &bus, const char *path)
    : IfcBase(bus, path) {}

std::string generateTotalValidityData() {
  std::string validityData;

  int globalLicenseValidity =
      globalData["licenseconfig"][0]["globalLicenseValidity"];

  std::map<std::string, int> services;
  for (const auto &service : globalData["licensableServices"]) {
    std::string serviceName = service["serviceName"];
    int licenseValidity = service["LicenseValidity"];
    services[serviceName] = globalLicenseValidity + licenseValidity;
  }

  for (const auto &service : services) {
    validityData += service.first + ":" + std::to_string(service.second) + ";";
  }
  DEBUG(std::cout << validityData << std::endl;);

  return validityData;
}

uint32_t getMinValidityDate() {
  char delimiter = {};
  std::string serviceName = {};
  int validity = 0;
  int minValidity = maxUserAlertCountValue;
  std::string validityData = generateTotalValidityData();
  std::istringstream iss(validityData);

  while (iss >> serviceName >> delimiter >> validity) {
    if (validity < minValidity) {
      minValidity = validity;
    }
  }

  return minValidity;
}

std::string LicenseControlImp::getLicenseKey() {
  return generateTotalValidityData();
}

int64_t LicenseControlImp::servicesUpCountDays() { return UpCountDays; }

int64_t LicenseControlImp::globalLicenseValidity() {
  return globalData["licenseconfig"][0]["globalLicenseValidity"];
}

bool LicenseControlImp::addLicenseKey() { return writeLicenseKeyToFile(); }

std::string LicenseControlImp::alertMessage() const {
  std::string useralert = AlertNotificationLicenseControl;
  return useralert;
}
