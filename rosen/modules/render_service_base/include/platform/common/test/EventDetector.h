#pragma once
#include <map>
#include <iostream>
#include <string>
#include <memory>

namespace OHOS {
	namespace Rosen {

		class BaseEventDetector
		{
		public:
			static std::shared_ptr<BaseEventDetector> CreateRSTimeOutDetector(int timeOutThreadMs, std::string detectorStringId);

			virtual ~BaseEventDetector() {
				paramList_.clear();
				std::map<std::string, std::string> tempParamList;
				paramList_.swap(tempParamList);
				std::cout << "~BaseEventDetector ok" << std::endl;
			}

			std::string GetStringId() {
				return stringId_;
			}

			virtual void SetParam(const std::string& key, const std::string& value) = 0;
			virtual void SetLoopStartTag() = 0;
			virtual void SetLoopFinishTag() = 0;


			std::map<std::string, std::string> GetParamList() {
				return paramList_;
			}


		protected:
			BaseEventDetector() = default;
			BaseEventDetector(std::string stringId) {
				stringId_ = stringId;
			}

			std::map<std::string, std::string> paramList_; // key: paramName 
			std::string stringId_;
		private:

		};


		class RSTimeOutDetector : public BaseEventDetector
		{
		public:
			RSTimeOutDetector(int timeOutThreadNs, std::string detectorStringId);
			~RSTimeOutDetector() = default;

			void SetParam(const std::string& key, const std::string& value) override;
			void SetLoopStartTag() override;
			void SetLoopFinishTag() override;

		private:
			void EventReport();
			int timeOutThreadMs_ = INT_MAX; // default: No Detector 
			uint64_t startTimeStampMs_ = 0;

		};





	}
}
