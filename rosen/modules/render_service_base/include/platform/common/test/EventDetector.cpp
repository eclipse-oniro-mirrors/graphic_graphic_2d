#include "EventManager.h"

namespace OHOS {
	namespace Rosen {

		std::shared_ptr<BaseEventDetector> BaseEventDetector::CreateRSTimeOutDetector(int timeOutThreadMs, std::string detectorStringId) {
			std::shared_ptr<RSTimeOutDetector> eventPtr(new RSTimeOutDetector(timeOutThreadMs, detectorStringId));
			return  eventPtr;
		}

		RSTimeOutDetector::RSTimeOutDetector(int timeOutThreadMs, std::string detectorStringId) :BaseEventDetector(detectorStringId) {
			std::cout << "RSTimeOutDetector :: timeOutThreadMs is  " << timeOutThreadMs << std::endl;
			timeOutThreadMs_ = timeOutThreadMs;
			paramList_["timeOutThreadMs"] = std::to_string(timeOutThreadMs_);
		}


		void RSTimeOutDetector::SetParam(const std::string& key, const std::string& value) {
			if (paramList_.count(key) == 0) {
				std::cout << "RSTimeOutDetector:: Invaild Key " << std::endl;
				return;
			}
			int valueInt = atoi(value.c_str());
			if (valueInt <= 0 || valueInt > 1000000) {
				std::cout << "RSTimeOutDetector:: Invaild Value " << std::endl;
				return;
			}

			timeOutThreadMs_ = valueInt;
		}


		void RSTimeOutDetector::SetLoopStartTag()
		{
			startTimeStampMs_ = SysEventManager::Instance().GetSysTimeMs();
		}

		void RSTimeOutDetector::SetLoopFinishTag()
		{
			uint64_t finishTimeStampMs = SysEventManager::Instance().GetSysTimeMs();
			if (finishTimeStampMs > startTimeStampMs_&& finishTimeStampMs - startTimeStampMs_ > timeOutThreadMs_) {
				EventReport();
			}

		}

		void RSTimeOutDetector::EventReport()
		{
			std::string msg = "hhhhhhh";
			RSSysEventMsg eventMsg = {
				stringId_,
				msg,
				1
			};
			SysEventManager::Instance().EventReport(eventMsg);
		}

	}
}