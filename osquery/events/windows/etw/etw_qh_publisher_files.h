/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#pragma once

#include <osquery/events/windows/etw/etw_publisher.h>
#include <unordered_map>
#include <vector>

namespace osquery {

/**
 * @brief Subscriptioning details for EtwPublisherProcesses events.
 */
struct EtwQhFileEventSubContext : public SubscriptionContext {
 private:
  friend class EtwQhPublisherFiles;
};

/**
 * @brief Event details for EtwQhPublisherFiles events.
 */
struct EtwQhFileEventContext : public EventContext {
  EtwEventDataRef data;
};

using EtwQhFileEventContextRef = std::shared_ptr<EtwQhFileEventContext>;
using EtwQhFileEventSubContextRef = std::shared_ptr<EtwQhFileEventSubContext>;

/**
 * @brief Publisher Name
 */
const std::string kEtwQhFilePublisherName = "etw_qh_file_publisher";

/**
 * @brief Implements an EtwPublisher that collects and
 * dispatches ETW events with process-start and process-stop OS information.
 */
class EtwQhPublisherFiles
    : public EtwPublisherBase,
      public EventPublisher<EtwQhFileEventSubContext, EtwQhFileEventContext> {
  /**
   * @brief Publisher constants
   */
  static const USHORT etwCreateNewFileID = 30;
  static const USHORT etwNameDeleteID = 11;
  static const USHORT etwCreateID = 12;
  static const USHORT etwRenamePathID = 27;
  static const USHORT etwDeletePathID = 26;

  /**
   * @brief Publisher type declaration
   */
  DECLARE_PUBLISHER(kEtwQhFilePublisherName);

 public:
  EtwQhPublisherFiles();

  /**
   * @brief Used to configure the ETW providers to listen, along with
   * its configuration parameters and processing callbacks.
   *
   * @return Status of the provider setup process.
   */
  Status setUp() override;

 private:
  /**
   * @brief Provides the c-function callback in charge of performing the pre
   * processing logic. This is the entry point for the event arriving from the
   * ETW OS interface. This callback gets called from the OS for every new ETW
   * event. There should be lightweight logic here, with no significant
   * performance implications.
   *
   * @param rawEvent is the RAW ETW event obtained from OS ETW provider. It
   * comprises an EVENT_HEADER common to all ETW providers and a UserData field
   * with provider-specific content.
   * https://learn.microsoft.com/en-us/windows/win32/api/evntcons/ns-evntcons-event_record
   *
   * @param traceCtx This is a helper class that it is used to parse the ETW
   * event manifest when needed.
   */
  static void providerPreProcessor(const EVENT_RECORD& rawEvent,
                                   const krabs::trace_context& traceCtx);

  /**
   * @brief Provides the std::function callback in charge of performing the
   * post processing logic. This logic is used to enrich, aggregate and modify
   * the event data before dispatching it to the event subscribers.
   */
  void providerPostProcessor(const EtwEventDataRef& data) override;

  void updateHardVolumeWithLogicalDrive(std::string& path);

  void initializeHardVolumeConversions();
  static inline bool isSupportedCreateEvent(const EVENT_HEADER& header);
  static inline bool isSupportedRenamePathEvent(const EVENT_HEADER& header);
  static inline bool isSupportedCreateNewFileEvent(const EVENT_HEADER& header);
  static inline bool isSupportedNameDeleteEvent(const EVENT_HEADER& header);
  static inline bool isSupportedEvent(const EVENT_HEADER& header);
  static inline bool isSupportedDeletePathEvent(const EVENT_HEADER& header);
  

 private:
  using HardVolumeDriveCollection =
      std::unordered_map<std::string, std::string>;

  HardVolumeDriveCollection hardVolumeDrives_;
};

/**
* Global map to store fileobject to filepath mappings.
*/
class CacheFilePath {
  size_t _max_size;
  std::unordered_map<uint64_t, std::string> _fileobj_map;
  // Use vector as a queue.
  std::vector<uint64_t> _fileobj_vec;
  /// Mutex for the map access
  Mutex cache_mutex;
 public:
  CacheFilePath() {
    _max_size = MAX_FILEOBJ_CACHE;
  };
  void addToMap(uint64_t fileobj, std::string path);
  void retrievePath(const uint64_t fileobj, std::string& path);
};
} // namespace osquery
