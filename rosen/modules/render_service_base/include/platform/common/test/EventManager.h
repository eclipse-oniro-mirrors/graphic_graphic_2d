#pragma once
#include<iostream>
#include<string>
#include<map>
#include<chrono>
#include<mutex>
#include "EventDetector.h"

namespace OHOS {
	namespace Rosen {
		struct RSSysEventMsg final {
			std::string stringId;
			std::string msg;
			int eventType;
		};

		struct RSEventState final {
			int eventIntervalMs = 60000; // unit:ms  the mini time interval between two event 
			uint64_t prevEventTimeStampMs = 0;
		};


		class SysEventManager final
		{
		public:
			static SysEventManager& Instance();
			void UpdateParam(); // Update Param: timeout\Event Frequency...
			uint64_t GetSysTimeMs();
			void EventReport(const RSSysEventMsg& eventMsg);
			void AddEvent(const std::shared_ptr<BaseEventDetector>& detectorPtr, int eventIntervalMs = 60000); // 60000: 1min
			void RemoveEvent(std::string stringId);

		private:
			SysEventManager();
			~SysEventManager();
			SysEventManager(const SysEventManager&) = delete;
			SysEventManager(const SysEventManager&&) = delete;
			SysEventManager& operator=(const SysEventManager&) = delete;
			SysEventManager& operator=(const SysEventManager&&) = delete;

			void UpdateDetectorParam(std::shared_ptr<BaseEventDetector> detectorPtr);
			void UpdateEventIntervalMs(std::shared_ptr<BaseEventDetector> detectorPtr);

			std::map<std::string, std::weak_ptr<BaseEventDetector>> eventDetectorList_;
			std::map<std::string, RSEventState> eventStateList_;
			std::mutex listMutex_;
			int updateCount_ = 0;



		};


	}

}