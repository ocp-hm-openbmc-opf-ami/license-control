
/*****************************************************************
 * License control Manager
 * licensecontrol.cpp
 *
 * @brief D-Bus service designed to manage and monitor the usage of
 * licensed resources the system, ensuring limitations and oversight
 * are maintained.
 *
 * Author: Manikandan.V manikandanv@ami.com
 *
 ******************************************************************/

#include "include/licensecontrol.hpp"
#include <chrono>
#include <csignal>
#include <fstream>
#include <future>
#include <iostream>
#include <set>
#include <thread>
#include <vector>

constexpr auto objPath = "/xyz/openbmc_project/License";

json globalData;
bool exitSchedulerTask = false;
int64_t UpCountDays = 0;
int64_t Globalvalidcount = 0;
std::string AlertNotificationLicenseControl = "";
uint32_t alertCountValue = 0;
std::map<std::string, std::string> serviceDates;

uint64_t convertTimeFormat(const std::string &timestampString) {
  std::tm timeinfo = {};
  std::istringstream ss(timestampString);

  ss >> std::get_time(&timeinfo, "%Y:%m:%d %H:%M:%S");

  if (ss.fail()) {
    return 0;
  }

  std::ostringstream outputSS;
  outputSS << std::put_time(&timeinfo, "%Y%m%d%H%M%S");

  return std::stoull(outputSS.str());
}

std::string getCurrentTimestamp() {
  std::time_t now = std::time(nullptr);
  std::tm timeinfo = *std::localtime(&now);

  std::ostringstream oss;
  oss << std::put_time(&timeinfo, "%Y:%m:%d %H:%M:%S");

  return oss.str();
}

std::string extractDataFromToken(const std::string &inputString,
                                 const std::string &dataTemplate) {
  std::istringstream ss(inputString);

  std::string token = {};
  std::string extractData = {};

  while (std::getline(ss, token, '-')) {
    if (token == dataTemplate) {
      std::getline(ss, extractData, '-');
      return extractData;
    }
  }

  return "";
}

int validateTimeStampRunTime(std::string &tokenString) {

  std::string existingTimeStamp =
      extractDataFromToken(tokenString, "TIMESTAMP");
  std::string EffectiveTimeStamp =
      globalData["licenseconfig"][0]["effectiveTimeStamp"];
  std::string bmcCurrentTimeStamp = getCurrentTimestamp();

  DEBUG(std::cout << "existingTimeStamp: " << existingTimeStamp
                  << "\nbmcCurrentTimeStamp: " << bmcCurrentTimeStamp
                  << std::endl;);

  if (!(convertTimeFormat(bmcCurrentTimeStamp) >
        convertTimeFormat(existingTimeStamp))) {
    return -1;
  }

  if ((convertTimeFormat(bmcCurrentTimeStamp) >
       convertTimeFormat(EffectiveTimeStamp)) ||
      EffectiveTimeStamp.empty()) {
    globalData["licenseconfig"][0]["effectiveTimeStamp"] = bmcCurrentTimeStamp;
  } else {
    return -1;
  }

  DEBUG(std::cout << "existingTimeStamp: " << existingTimeStamp
                  << "\nEffectiveTimeStamp: " << EffectiveTimeStamp
                  << "\nbmcCurrentTimeStamp: " << bmcCurrentTimeStamp
                  << std::endl;);

  return 0;
}

// Function to load JSON data from a file
bool loadJsonFromFile(const std::string &filePath) {
  std::ifstream ifs(filePath);
  if (!ifs.is_open()) {
    std::cerr << "Error opening JSON file: " << filePath << std::endl;
    return false;
  }

  try {
    ifs >> globalData;
  } catch (const json::exception &e) {
    std::cerr << "Error parsing JSON: " << e.what() << std::endl;
    return false;
  }

  return true;
}

std::vector<std::string>
appendServiceTypeToCommands(const std::vector<std::string> &commands,
                            const std::string &serviceType) {
  std::vector<std::string> resultCommands;
  for (size_t i = 0; i < commands.size(); ++i) {
    resultCommands.push_back(serviceType + " " + commands[i]);
    if (i < commands.size() - 1) {
      // resultCommands.back() += " &&";
    }
  }
  return resultCommands;
}

std::vector<std::string> getServiceCtlCommands(const std::string &serviceName,
                                               const std::string &status) {
  std::string serviceType =
      (status == "start") ? "systemctl start" : "systemctl stop";

  std::vector<std::string> commands = {};

  if (globalData.contains("licensableServices")) {
    for (const auto &service : globalData["licensableServices"]) {
      if (service.contains("serviceName") &&
          service["serviceName"] == serviceName) {
        if (service.contains("serviceControlCmd")) {
          const auto &controlCmd = service["serviceControlCmd"];
          if (controlCmd.is_string()) {
            commands.push_back(controlCmd);
          } else if (controlCmd.is_array()) {
            for (const auto &cmd : controlCmd) {
              if (cmd.is_string()) {
                commands.push_back(cmd);
              }
            }
          }
        }
        // Additional handling for other cases if needed
        break; // Stop searching once the serviceName is found
      }
    }
    return appendServiceTypeToCommands(commands, serviceType);
  }

  return commands;
}

// The function is used to get the specified variableName from the .json file.
std::vector<std::string> getSpecificValues(const std::string &variableName) {
  std::vector<std::string> values;

  if (globalData.contains("licensableServices")) {
    for (const auto &service : globalData["licensableServices"]) {
      if (service.contains(variableName)) {
        if (service[variableName].is_array()) {
          for (const auto &value : service[variableName]) {
            values.push_back(value);
          }
        } else {
          // If it's not an array, add the single value to the vector
          values.push_back(service[variableName]);
        }
      } else {

        std::cerr << "Variable " << variableName
                  << " not found in the JSON for service "
                  << service["serviceName"] << "." << std::endl;
      }
    }
  }

  return values;
}

int controlGlobalProcess(const std::string &actionType) {
  int result = 0;
  std::vector<std::string> services = getSpecificValues("serviceControlCmd");
  std::string serviceType = "systemctl " + actionType;
  std::vector<std::string> allServices =
      appendServiceTypeToCommands(services, serviceType);

  for (const auto &command : allServices) {
    result = std::system(command.c_str());

    std::cout << command << " ";

    if (result != 0) {
      std::cerr << "Error executing command: " << command << std::endl;
      return result;
    }
  }

  std::cout << std::endl;

  return 0;
}

int checkServiceValidity() {
  int isServiceValidityExceeded = 0, result = 0, numServicesInJson = 0;

  std::vector<std::string> stopServiceCommands = {};
  std::vector<std::string> command = getSpecificValues("serviceName");

  for (const auto &ServiceNames : command) {

    for (const auto &service : globalData["licensableServices"]) {
      if (service["serviceName"] == ServiceNames) {
        numServicesInJson++;
        // Retrieve the LicenseValidity for the specific service
        int licenseValidity = service.value("LicenseValidity", -1);

        if (licenseValidity == -1) {
          // std::cerr << "LicenseValidity not found for service " <<
          // ServiceNames << "." << std::endl;
          isServiceValidityExceeded++;
          continue; // Skip to the next service
        }

        // Check if servicesUpCountDays/UpCountDays is greater than
        // LicenseValidity
        if (UpCountDays >= (licenseValidity + Globalvalidcount)) {

          serviceDates[ServiceNames] = "0";

          std::cout
              << "Service " << ServiceNames
              << " has exceeded the license validity. Stopping the service."
              << std::endl;
          isServiceValidityExceeded++;
          stopServiceCommands = getServiceCtlCommands(ServiceNames, "stop");

          for (const auto &command : stopServiceCommands) {
            DEBUG(std::cout << command << " ";);

            result = std::system(command.c_str());
            if (result != 0) {
              std::cerr << "Error executing stop command " << command
                        << std::endl;
              return result;
            }
          }
          DEBUG(std::cout << std::endl;);
        } else {
          if (alertCountValue != 0 &&
              (alertCountValue >=
               ((Globalvalidcount + licenseValidity) - UpCountDays))) {
            if (((Globalvalidcount + licenseValidity) - UpCountDays) >= 0) {
              serviceDates[ServiceNames] = std::to_string(
                  (Globalvalidcount + licenseValidity) - UpCountDays);
            } else {
              serviceDates[ServiceNames] = "0";
            }
          }
          DEBUG(std::cout << "Service " << ServiceNames
                          << " is within the license validity." << std::endl;);
        }
      }
    }

    DEBUG(std::cout << "Number of services in the JSON: " << numServicesInJson
                    << std::endl;);
    DEBUG(std::cout << "Number of services Expired : "
                    << isServiceValidityExceeded << std::endl;);
  }

  if (numServicesInJson == isServiceValidityExceeded) {
    return 1;
  }

  return 0;
}

int checkGlobalValidity() {

  int globalCurrentValidity = 0;

  if ((alertCountValue != 0) &&
      (alertCountValue >= (Globalvalidcount - UpCountDays))) {
    globalCurrentValidity = Globalvalidcount - UpCountDays;
    if (globalCurrentValidity < 0) {
      globalCurrentValidity = 0;
    }
    serviceDates["GLOBAL"] = std::to_string(globalCurrentValidity);
  }

  if (Globalvalidcount == 0 || (UpCountDays >= Globalvalidcount)) {
    return 2;
  }

  return 0;
}

int checkValidity() {
  int ret = checkGlobalValidity();

  if (ret == 2) {
    ret = checkServiceValidity();
    if (ret != 0) {
      std::cout << "All Licensable Services has been stoped" << std::endl;
      return 1;
    }
  } else if (ret != 0) {
    std::cout << "AMI Global Licence period expired.. Exiting!" << std::endl;
    return 1;
  }
  return 0;
}

int updateJson() {
  if (std::ofstream ofs(licenseJsonFilePath); ofs.is_open()) {
    ofs << std::setw(4) << globalData << std::endl;
    ofs.close();
  } else {
    return -1;
  }
  return 0;
}

int incrementServicesUpTime() {

  int retVal = 0;
  UpCountDays = globalData["licenseconfig"][0]["servicesUpCountDays"];
  Globalvalidcount = globalData["licenseconfig"][0]["globalLicenseValidity"];

  UpCountDays = UpCountDays + 1;
  globalData["licenseconfig"][0]["servicesUpCountDays"] = UpCountDays;

  retVal = updateJson();
  if (retVal != 0) {
    std::cerr << "Failed to open the license.json file for writing."
              << std::endl;
    return -1;
  }

  return checkValidity();
}

void signalHandler(int signum) {
  if (signum == SIGALRM) {
    DEBUG(std::cout << "SIGALRM has been generated.." << std::endl;);

    int ret = incrementServicesUpTime();
    if (ret != 0) {
      std::cout << "Exiting licence control" << std::endl;
      exitSchedulerTask = true;
    }
    AlertNotificationLicenseControl = "";

    for (const auto &entry : serviceDates) {
      AlertNotificationLicenseControl +=
          (entry.first + COLON + entry.second + SEMICOLON);
    }
  }
}

void scheduler() {
  while (1) {
    std::signal(SIGALRM, signalHandler);
    const int secondsToTrigger = secToTriggerValidation;
    std::chrono::seconds interval(secondsToTrigger);
    std::chrono::steady_clock::time_point nextSignalTime =
        std::chrono::steady_clock::now() + interval;
    while (!exitSchedulerTask) {
      std::chrono::steady_clock::time_point currentTime =
          std::chrono::steady_clock::now();
      std::chrono::steady_clock::duration timeUntilSignal =
          nextSignalTime - currentTime;

      std::this_thread::sleep_for(timeUntilSignal);
      std::raise(SIGALRM);

      nextSignalTime += interval;
    }
    sleep(5);
  }
}

// Function to update service validity in the JSON
int updateServiceValidity(json &globalData, const std::string &service,
                          int validity) {
  int retVal = 0;
  auto &licensableServices = globalData["licensableServices"];

  for (auto &serviceInfo : licensableServices) {
    if (serviceInfo["serviceName"] == service) {
      serviceInfo["LicenseValidity"] = validity;
      break;
    }
  }

  auto &licenseConfig = globalData["licenseconfig"];
  for (auto &config : licenseConfig) {
    config["globalLicenseValidity"] = validity;
  }

  retVal = updateJson();
  if (retVal != 0) {
    std::cerr << "Failed to open the license.json file for writing."
              << std::endl;
    return -1;
  }
  return 0;
}

int updateValidityFromLicensePeriod(const std::string &licensePeriod) {
  size_t startPos = 0;
  int retVal = 0;

  while (startPos < licensePeriod.size()) {
    size_t colonPos = licensePeriod.find(COLON, startPos);
    size_t semicolonPos = licensePeriod.find(SEMICOLON, colonPos);

    if (colonPos != std::string::npos) {
      std::string service = licensePeriod.substr(startPos, colonPos - startPos);
      int validity = 0;
      if (semicolonPos != std::string::npos) {
        validity = std::stoi(
            licensePeriod.substr(colonPos + 1, semicolonPos - colonPos - 1));
      } else {
        // GLOBAL service validity if no semicolon is found
        validity = std::stoi(licensePeriod.substr(colonPos + 1));
      }

      DEBUG(std::cout << "service -" << service << " validity " << validity
                      << std::endl;);
      retVal = updateServiceValidity(globalData, service, validity);
      if (retVal != 0) {
        return -1;
      }

      if (semicolonPos != std::string::npos) {
        startPos = semicolonPos + 1;
      } else {
        break; // Exit the loop if there is no semicolon
      }
    } else {
      break;
    }
  }
  return 0;
}

int parseValidityData(const std::string &token) {
  int retVal = 0;

  std::string timestampData = extractDataFromToken(token, "TIMESTAMP");
  std::string validityData = extractDataFromToken(token, "VALIDITY");
  std::string macData = extractDataFromToken(token, "MAC");

  if (timestampData.empty() || validityData.empty() || macData.empty()) {
    std::cerr << "Error parsing input: invalid format" << std::endl;
    return 1;
  }

  DEBUG(std::cout << "-TIMESTAMP- = " << timestampData << std::endl;);
  DEBUG(std::cout << "-VALIDITY- = " << validityData << std::endl;);
  DEBUG(std::cout << "-MAC- = " << macData << std::endl;);

  retVal = updateValidityFromLicensePeriod(validityData);
  if (retVal != 0) {
    return 1;
  }

  globalData["licenseconfig"][0]["MACId"] = macData;

  return 0;
}

int main() {
  std::string licenseToken = {};
  int ret = 0;
  int attempt = 0;
  int maxRetries = 3;
  int delaySeconds = 60;
  auto bus = sdbusplus::bus::new_default();

  bus.request_name("xyz.openbmc_project.License");
  sdbusplus::server::manager_t objManager(bus, objPath);

  if (std::filesystem::exists(licenseValidityTokenPath)) {

    DEBUG(std::cout << "File path exists: " << licenseValidityTokenPath
                    << std::endl;);

    std::ifstream fileStream(licenseValidityTokenPath);

    if (!loadJsonFromFile(licenseJsonFilePath)) {
      return 1;
    }

    if (fileStream.is_open()) {
      std::getline(fileStream, licenseToken);

      do {
        ret = validateTimeStampRunTime(licenseToken);
        if (ret == 0) {
          break;
        }

        attempt++;
        std::cout << "Invalid BMC Time Stamp. Attempt " << attempt << " of "
                  << maxRetries << std::endl;

        if (attempt < maxRetries) {
          std::this_thread::sleep_for(std::chrono::seconds(delaySeconds));
        }
      } while (attempt < maxRetries);

      if (ret != 0) {
        ret = controlGlobalProcess("stop");
        if (ret != 0) {
          std::cerr << "Error stopping Global services" << std::endl;
          return ret;
        }

        exitSchedulerTask = true;
      }

      ret = parseValidityData(licenseToken);
      if (ret != 0) {
        return 1;
      }

      ret = updateJson();
      if (ret != 0) {
        std::cerr << "Failed to open the license.json file for writing."
                  << std::endl;
        return 1;
      }

      alertCountValue = globalData["licenseconfig"][0]["userAlertCount"];
      UpCountDays = globalData["licenseconfig"][0]["servicesUpCountDays"];
      Globalvalidcount = globalData["licenseconfig"][0]["globalLicenseValidity"];

      fileStream.close();
    } else {
      std::cerr << "Failed to open the file for reading." << std::endl;
    }
  } else {
    std::cout << "File path does not exist: " << licenseValidityTokenPath
              << std::endl;
  }

  LicenseControlImp licensecontrol(bus, objPath);
  licensecontrol.userAlertCount(alertCountValue);

  ret = checkValidity();
  if (ret == 1) {
    exitSchedulerTask = true;
  }

  auto eventHandler = std::async(std::launch::async, scheduler);

  bus.process_loop();
  eventHandler.wait();

  return 0;
}
