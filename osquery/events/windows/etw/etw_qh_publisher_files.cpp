/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <ctime>

#include <osquery/core/flags.h>
#include <osquery/events/windows/etw/etw_qh_publisher_files.h>
#include <osquery/utils/conversions/windows/strings.h>
#include <osquery/utils/map_take.h>

namespace osquery {

FLAG(bool,
     enable_etw_qh_file_events,
     false,
     "Enables the etw_qh_file_events publisher");

// ETW Event publisher registration into the Osquery pub-sub framework
REGISTER_ETW_PUBLISHER(EtwQhPublisherFiles, kEtwQhFilePublisherName.c_str());

// Create Cache map for storing fileobj <-> filepath mapping
// 
CacheFilePath g_cacheFilePath;

// Publisher constructor
EtwQhPublisherFiles::EtwQhPublisherFiles()
    : EtwPublisherBase(kEtwQhFilePublisherName) {
  initializeHardVolumeConversions();
};

// There are multiple ETW providers being setup here. Events arriving from
// these providers will be aggregated in the post-processing phase.
Status EtwQhPublisherFiles::setUp() {
  if (!FLAGS_enable_etw_qh_file_events) {
    return Status::failure(kEtwQhFilePublisherName +
                           " qh file publisher disabled via configuration.");
  }
  // ETW Initialization logic
  const EtwProviderConfig::EtwBitmask fileOpsKeyword =
      KERNEL_FILE_KEYWORD_FILENAME | 
      KERNEL_FILE_KEYWORD_DELETE_PATH |
      KERNEL_FILE_KEYWORD_CREATE_NEW_FILE |
      KERNEL_FILE_KEYWORD_RENAME_SETLINK_PATH | 
      KERNEL_FILE_KEYWORD_CREATE;

  // Userspace ETW Provider configuration
  EtwProviderConfig userEtwProviderConfig;
  userEtwProviderConfig.setName("Microsoft-Windows-Kernel-File");
  userEtwProviderConfig.setAnyBitmask(fileOpsKeyword);
  userEtwProviderConfig.setPreProcessor(getPreProcessorCallback());
  userEtwProviderConfig.setPostProcessor(getPostProcessorCallback());
  userEtwProviderConfig.addEventTypeToHandle(EtwEventType::CreateNewFile);
  userEtwProviderConfig.addEventTypeToHandle(EtwEventType::NameDelete);
  userEtwProviderConfig.addEventTypeToHandle(EtwEventType::Create);
  userEtwProviderConfig.addEventTypeToHandle(EtwEventType::RenamePath);
  userEtwProviderConfig.addEventTypeToHandle(EtwEventType::DeletePath);

  // Adding the provider to the ETW Engine
  Status userProviderAddStatus = EtwEngine().addProvider(userEtwProviderConfig);
  if (!userProviderAddStatus.ok()) {
    return userProviderAddStatus;
  }

  return Status::success();
}

// Callback to perform post-processing logic
void EtwQhPublisherFiles::providerPostProcessor(
    const EtwEventDataRef& eventData) {
  auto event_context = createEventContext();

  // Sanity check on event types that this callback will handle
  if (eventData->Header.Type != EtwEventType::CreateNewFile &&
      eventData->Header.Type != EtwEventType::NameDelete &&
      eventData->Header.Type != EtwEventType::Create &&
      eventData->Header.Type != EtwEventType::RenamePath &&
      eventData->Header.Type != EtwEventType::DeletePath) {
    return;
  }

  // Payload update and event dispatch
  if (eventData->Header.Type == EtwEventType::CreateNewFile) {

    // sanity check on variant type
    if (!std::holds_alternative<EtwCreateNewFileDataRef>(eventData->Payload)) {
      return;
    }

    // sanity check on payload content
    auto createNewFileData =
        std::get<EtwCreateNewFileDataRef>(eventData->Payload);
    if (createNewFileData == nullptr) {
      return;
    }

    updateHardVolumeWithLogicalDrive(createNewFileData->FileName);

    // Event dispatch
    event_context->data = std::move(eventData);
    fire(event_context);

  } 
  else if (eventData->Header.Type == EtwEventType::NameDelete) {

    // sanity check on variant type
    if (!std::holds_alternative<EtwNameDeleteDataRef>(eventData->Payload)) {
      return;
    }

    // sanity check on payload content
    auto deletePathData = std::get<EtwNameDeleteDataRef>(eventData->Payload);
    if (deletePathData == nullptr) {
      return;
    }

    updateHardVolumeWithLogicalDrive(deletePathData->FileName);

    // Event dispatch
    event_context->data = std::move(eventData);
    fire(event_context);
  } 
  else if (eventData->Header.Type == EtwEventType::Create) {
    // sanity check on variant type
    if (!std::holds_alternative<EtwCreateDataRef>(eventData->Payload)) {
      return;
    }
    // sanity check on payload content
    auto createData = std::get<EtwCreateDataRef>(eventData->Payload);
    if (createData == nullptr) {
      return;
    }

    updateHardVolumeWithLogicalDrive(createData->FileName);

    g_cacheFilePath.addToMap(createData->FileObj, createData->FileName);

    // Event dispatch
    //event_context->data = std::move(eventData);
    //fire(event_context);
  } 
  else if (eventData->Header.Type == EtwEventType::RenamePath) {
    // sanity check on variant type
    if (!std::holds_alternative<EtwRenamePathDataRef>(eventData->Payload)) {
      return;
    }
    // sanity check on payload content
    auto renameData = std::get<EtwRenamePathDataRef>(eventData->Payload);
    if (renameData == nullptr) {
      return;
    }

    updateHardVolumeWithLogicalDrive(renameData->RenamedFilePath);

    //Populate old file path
    g_cacheFilePath.retrievePath(renameData->FileObj, renameData->OldFilePath);

    // Event dispatch
    event_context->data = std::move(eventData);
    fire(event_context);
  } 
  else if (eventData->Header.Type == EtwEventType::DeletePath) {
    // sanity check on variant type
    if (!std::holds_alternative<EtwDeletePathDataRef>(eventData->Payload)) {
      return;
    }

    // sanity check on payload content
    auto delPathData = std::get<EtwDeletePathDataRef>(eventData->Payload);
    if (delPathData == nullptr) {
      return;
    }

    updateHardVolumeWithLogicalDrive(delPathData->FilePath);

    // Event dispatch
    event_context->data = std::move(eventData);
    fire(event_context);
  }
}

// Callback to perform pre-processing logic
void EtwQhPublisherFiles::providerPreProcessor(
    const EVENT_RECORD& rawEvent, const krabs::trace_context& traceCtx) {
  // Helper accessors for userspace events
  const EVENT_HEADER& eventHeader = rawEvent.EventHeader;
  const unsigned int eventVersion = eventHeader.EventDescriptor.Version;

  // Checking if new event is a supported one
  if (!isSupportedEvent(eventHeader)) {
    return;
  }

  // ETW event schema parsing
  krabs::schema schema(rawEvent, traceCtx.schema_locator);
  krabs::parser parser(schema);

  // Internal ETW Event allocation - This event will be populated and dispatched
  std::shared_ptr<EtwEventData> newEvent = std::make_shared<EtwEventData>();
  if (newEvent == nullptr) {
    LOG(WARNING) << "Cannot allocate new EtwEventData event";
    return;
  }

  // Parsing ETW Event payload based on its type
  bool eventShouldBeDispatched = false;
  // This is an ETW event coming from a userspace provider

  if (isSupportedCreateNewFileEvent(eventHeader)) {
    // Event type initialization
    newEvent->Header.Type = EtwEventType::CreateNewFile;

    // Allocating payload
    EtwCreateNewFileDataRef createNewFileData =
        std::make_shared<EtwCreateNewFileData>();
    if (!createNewFileData) {
      return;
    }

    createNewFileData->ProcessId = eventHeader.ProcessId;
    createNewFileData->EventTime.dwLowDateTime = eventHeader.TimeStamp.LowPart;
    createNewFileData->EventTime.dwHighDateTime = eventHeader.TimeStamp.HighPart;
    createNewFileData->FileName.assign(
        wstringToString(parser.parse<std::wstring>(L"FileName")));

    createNewFileData->UserDataReady = true;
    newEvent->Payload = std::move(createNewFileData);

    eventShouldBeDispatched = true;
  }

  if (isSupportedNameDeleteEvent(eventHeader)) {
    // Event type initialization
    newEvent->Header.Type = EtwEventType::NameDelete;

    // Allocating payload
    EtwNameDeleteDataRef nameDeleteData = std::make_shared<EtwNameDeleteData>();
    if (!nameDeleteData) {
      return;
    }

    nameDeleteData->ProcessId = eventHeader.ProcessId;
    nameDeleteData->EventTime.dwLowDateTime = eventHeader.TimeStamp.LowPart;
    nameDeleteData->EventTime.dwHighDateTime =
        eventHeader.TimeStamp.HighPart;
    nameDeleteData->FileName.assign(
        wstringToString(parser.parse<std::wstring>(L"FileName")));

    nameDeleteData->UserDataReady = true;
    newEvent->Payload = std::move(nameDeleteData);

    eventShouldBeDispatched = true;
  }

  if (isSupportedCreateEvent(eventHeader)) {
    // Event type initialization
    newEvent->Header.Type = EtwEventType::Create;

    // Allocating payload
    EtwCreateDataRef createData = std::make_shared<EtwCreateData>();
    if (!createData) {
      return;
    }

    createData->ProcessId = eventHeader.ProcessId;
    createData->EventTime.dwLowDateTime = eventHeader.TimeStamp.LowPart;
    createData->EventTime.dwHighDateTime = eventHeader.TimeStamp.HighPart;
    createData->FileName.assign(
        wstringToString(parser.parse<std::wstring>(L"FileName")));
    struct krabs::pointer pFileObj;
    pFileObj = parser.parse<krabs::pointer>(L"FileObject");
    createData->FileObj = pFileObj.address;

    createData->UserDataReady = true;
    newEvent->Payload = std::move(createData);

    eventShouldBeDispatched = true;
  }
  
  if (isSupportedRenamePathEvent(eventHeader)) {
    // Event type initialization
    newEvent->Header.Type = EtwEventType::RenamePath;

    // Allocating payload
    EtwRenamePathDataRef renamePathData = std::make_shared<EtwRenamePathData>();
    if (!renamePathData) {
      return;
    }

    renamePathData->ProcessId = eventHeader.ProcessId;
    renamePathData->EventTime.dwLowDateTime = eventHeader.TimeStamp.LowPart;
    renamePathData->EventTime.dwHighDateTime = eventHeader.TimeStamp.HighPart;
    renamePathData->RenamedFilePath.assign(
        wstringToString(parser.parse<std::wstring>(L"FilePath")));
    struct krabs::pointer pFileObj;
    pFileObj = parser.parse<krabs::pointer>(L"FileObject");
    renamePathData->FileObj = pFileObj.address;

    renamePathData->UserDataReady = true;
    newEvent->Payload = std::move(renamePathData);

    eventShouldBeDispatched = true;
  }

  if (isSupportedDeletePathEvent(eventHeader)) {
    // Event type initialization
    newEvent->Header.Type = EtwEventType::DeletePath;

    // Allocating payload
    EtwDeletePathDataRef delPathData = std::make_shared<EtwDeletePathData>();
    if (!delPathData) {
      return;
    }

    delPathData->ProcessId = eventHeader.ProcessId;
    delPathData->EventTime.dwLowDateTime = eventHeader.TimeStamp.LowPart;
    delPathData->EventTime.dwHighDateTime = eventHeader.TimeStamp.HighPart;
    delPathData->FilePath.assign(
        wstringToString(parser.parse<std::wstring>(L"FilePath")));

    delPathData->UserDataReady = true;
    newEvent->Payload = std::move(delPathData);

    eventShouldBeDispatched = true;
  }


  // Returning if event should not be sent for post processing
  if (!eventShouldBeDispatched) {
    return;
  }

  // Raw Header update
  newEvent->Header.RawHeader = rawEvent.EventHeader;

  // Dispatch the event
  EtwController::instance().dispatchETWEvents(std::move(newEvent));
}

// Checking if given ETW event is a supported DeletePath event
bool EtwQhPublisherFiles::isSupportedDeletePathEvent(
    const EVENT_HEADER& header) {
  return header.EventDescriptor.Id == etwDeletePathID;
}

// Checking if given ETW event is a supported Rename event
bool EtwQhPublisherFiles::isSupportedRenamePathEvent(
    const EVENT_HEADER& header) {
  return header.EventDescriptor.Id == etwRenamePathID;
}

// Checking if given ETW event is a supported Create event
bool EtwQhPublisherFiles::isSupportedCreateEvent(
    const EVENT_HEADER& header) {
  return header.EventDescriptor.Id == etwCreateID;
}

// Checking if given ETW event is a supported Create New File event
bool EtwQhPublisherFiles::isSupportedCreateNewFileEvent(
    const EVENT_HEADER& header) {
  return header.EventDescriptor.Id == etwCreateNewFileID ;
}

// Checking if given ETW event is a supported Create New File event
bool EtwQhPublisherFiles::isSupportedNameDeleteEvent(
    const EVENT_HEADER& header) {
  return header.EventDescriptor.Id == etwNameDeleteID;
}

// Checking if given ETW event ID is supported by preprocessor logic
bool EtwQhPublisherFiles::isSupportedEvent(const EVENT_HEADER& header) {
  return (isSupportedNameDeleteEvent(header) ||
          isSupportedCreateNewFileEvent(header) ||
          isSupportedCreateEvent(header) ||
          isSupportedRenamePathEvent(header) || 
          isSupportedDeletePathEvent(header));
}

void EtwQhPublisherFiles::initializeHardVolumeConversions() {
  const auto& validDriveLetters = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";

  for (auto& driveLetter : validDriveLetters) {
    std::string queryPath;
    queryPath.push_back(driveLetter);
    queryPath.push_back(':');

    char hardVolume[MAX_PATH + 1] = {0};
    if (QueryDosDeviceA(queryPath.c_str(), hardVolume, MAX_PATH)) {
      hardVolumeDrives_.insert({hardVolume, queryPath});
    }
  }
}

void EtwQhPublisherFiles::updateHardVolumeWithLogicalDrive(
    std::string& path) {
  // Updating the hardvolume entries with logical volume data
  for (const auto& [hardVolume, logicalDrive] : hardVolumeDrives_) {
    size_t pos = 0;
    if ((pos = path.find(hardVolume, pos)) != std::string::npos) {
      path.replace(pos, hardVolume.length(), logicalDrive);
      break;
    }
  }
}

void CacheFilePath::addToMap(uint64_t fileobj, std::string path) {
  WriteLock lock(cache_mutex);
  //Check if map is full. 
  if (_max_size <= _fileobj_map.size()) {
    //Remove the last element from map and vector
    _fileobj_map.erase(_fileobj_vec.front());
    _fileobj_vec.erase(_fileobj_vec.begin());
    //insert new element at the end of vector
    _fileobj_vec.push_back(fileobj);
    //insert new pair in the map
    _fileobj_map.insert(std::make_pair(fileobj, path));
  } else {
    //check if key exists in the map
    if (_fileobj_map.end() != _fileobj_map.find(fileobj)) {
      _fileobj_map[fileobj] = path;
      //find the key in the vector and remove it
      for (auto it = _fileobj_vec.begin(); it != _fileobj_vec.end();++it) {
        if (*it == fileobj) {
          _fileobj_vec.erase(it);
          break;
        }
      }
      // Add the key at the back.
      _fileobj_vec.push_back(fileobj);
    } else { // key does not exist in the map
      _fileobj_map.insert(std::make_pair(fileobj, path));
      _fileobj_vec.push_back(fileobj);
    }
  }
}

void CacheFilePath::retrievePath(const uint64_t fileobj, std::string& path) {
  if (_fileobj_map.end() == _fileobj_map.find(fileobj)) {
    path.clear();
    return;
  } else {
    path.assign(_fileobj_map[fileobj]);
  }
}
}
