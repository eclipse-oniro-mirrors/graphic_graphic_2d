#include "EventManager.h"


namespace OHOS {
	namespace Rosen {

		SysEventManager& SysEventManager::Instance()
		{
			static SysEventManager eventManager;
			return eventManager;
		}

		SysEventManager::SysEventManager()
		{

		}

		SysEventManager::~SysEventManager()
		{

		}

		std::string GetParam(std::string paraName)
		{
			return "1000";
		}

		void SysEventManager::UpdateDetectorParam(std::shared_ptr<BaseEventDetector> detectorPtr)
		{
			auto paramList = detectorPtr->GetParamList();
			for (auto& item : paramList) {
				std::string paraName = "rosen.RsDFXEvent." + detectorPtr->GetStringId() +
					"." + item.first;
				std::cout << "paraname is " << paraName << std::endl;
				detectorPtr->SetParam(item.first, GetParam(paraName));
			}
		}

		void SysEventManager::UpdateEventIntervalMs(std::shared_ptr<BaseEventDetector> detectorPtr)
		{
			if (eventStateList_.count(detectorPtr->GetStringId()) == 0) {
				return;
			}
			std::string paraName = "rosen.RsDFXEvent." + detectorPtr->GetStringId() +
				".eventIntervalMs";
			std::cout << "UpdateEventIntervalMs paraname is " << paraName << std::endl;
			int valueInt = atoi(GetParam(paraName).c_str());
			if (valueInt <= 0 || valueInt > 1000000) {
				std::cout << "UpdateEventIntervalMs:: Invaild Value " << std::endl;
				return;
			}
			eventStateList_[detectorPtr->GetStringId()].eventIntervalMs = valueInt;
			std::cout << "eventIntervalMs " << valueInt << std::endl;
		}

		void SysEventManager::UpdateParam()
		{
			updateCount_++;
			if (updateCount_ % 200 != 0) {
				return;
			}

			std::unique_lock<std::mutex> listLock(listMutex_);
			for (auto& item : eventDetectorList_) {
				auto detectorPtr = item.second.lock();
				if (detectorPtr == nullptr) {
					return;
				}
				UpdateDetectorParam(detectorPtr);
				UpdateEventIntervalMs(detectorPtr);
			}

		}

		void SysEventManager::AddEvent(const std::shared_ptr<BaseEventDetector>& detectorPtr, int eventIntervalMs)
		{
			std::weak_ptr<BaseEventDetector> detectorWeakPtr(detectorPtr);
			{
				std::unique_lock<std::mutex> listLock(listMutex_);
				if (eventDetectorList_.count(detectorPtr->GetStringId()) != 0) {
					return;
				}
				eventDetectorList_[detectorPtr->GetStringId()] = detectorWeakPtr;
				RSEventState state = {
					eventIntervalMs,
					0
				};
				eventStateList_[detectorPtr->GetStringId()] = state;
			}
		}

		void SysEventManager::RemoveEvent(std::string stringId)
		{
			std::cout << "remove ok " << std::endl;
			std::unique_lock<std::mutex> listLock(listMutex_);
			if (eventDetectorList_.count(stringId) != 0) {
				return;
			}
			eventDetectorList_.erase(stringId);
			eventStateList_.erase(stringId);
		}

		uint64_t SysEventManager::GetSysTimeMs()
		{
			auto now = std::chrono::steady_clock::now().time_since_epoch();
			return std::chrono::duration_cast<std::chrono::milliseconds>(now).count();
		}

		void SysEventManager::EventReport(const RSSysEventMsg& eventMsg)
		{

			std::unique_lock<std::mutex> listLock(listMutex_);
			std::cout << "eventMsg.stringId " << eventMsg.stringId << std::endl;
			if (eventStateList_.count(eventMsg.stringId) == 0) {
				return;
			}
			RSEventState& state = eventStateList_[eventMsg.stringId];
			uint64_t currentTimeMs = GetSysTimeMs();
			if (currentTimeMs > state.prevEventTimeStampMs&&
				currentTimeMs - state.prevEventTimeStampMs > state.eventIntervalMs) {
				std::cout << "hhhhhhhh " << std::endl;
				state.prevEventTimeStampMs = currentTimeMs;
			}

		}


	}
}