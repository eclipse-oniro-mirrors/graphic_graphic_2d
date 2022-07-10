/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef RENDER_SERVICE_BASE_COMMON_RS_DETECTOR_H
#define RENDER_SERVICE_BASE_COMMON_RS_DETECTOR_H

#include <map>
#include <memory>
#include <rs_log.h>
namespace OHOS {
namespace Rosen {
class BaseEventDetector {
public:
	static std::shared_ptr<BaseEventDetector> CreateRSTimeOutDetector(int timeOutThreadMs, std::string detectorStringId);
	virtual ~BaseEventDetector()
    {
		ClearParamList();
        RS_LOGD("BaseEventDetector::~BaseEventDetector finish");
	}

	std::string GetStringId()
    {
		return stringId_;
	}

    std::map<std::string, std::string> GetParamList()
    {
		return paramList_;
	}

	virtual void SetParam(const std::string& key, const std::string& value) = 0;
	virtual void SetLoopStartTag() = 0;
	virtual void SetLoopFinishTag() = 0;

protected:
	BaseEventDetector() = default;
    BaseEventDetector(std::string stringId)
    {
		stringId_ = stringId;
	}

    void ClearParamList()
    {
        paramList_.clear();
		std::map<std::string, std::string> tempParamList;
		paramList_.swap(tempParamList);
        RS_LOGD("BaseEventDetector::ClearParamList finish");
    }

	std::map<std::string, std::string> paramList_; // key: paramName 
	std::string stringId_;
};


class RSTimeOutDetector : public BaseEventDetector {
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


#endif // RENDER_SERVICE_BASE_COMMON_RS_DETECTOR_H