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

#include "platform/common/rs_event_manager.h"

namespace OHOS {
namespace Rosen {
std::shared_ptr<BaseEventDetector> BaseEventDetector::CreateRSTimeOutDetector(int timeOutThreadMs, std::string detectorStringId)
{
	std::shared_ptr<RSTimeOutDetector> eventPtr(new RSTimeOutDetector(timeOutThreadMs, detectorStringId));
	return  eventPtr;
}

RSTimeOutDetector::RSTimeOutDetector(int timeOutThreadMs, std::string detectorStringId) :BaseEventDetector(detectorStringId)
{
    RS_LOGD("RSTimeOutDetector ::RSTimeOutDetector timeOutThreadMs is %d ", timeOutThreadMs);
	timeOutThreadMs_ = timeOutThreadMs;
	paramList_["timeOutThreadMs"] = std::to_string(timeOutThreadMs_);
}


void RSTimeOutDetector::SetParam(const std::string& key, const std::string& value)
{
	if (paramList_.count(key) == 0) {
        RS_LOGD("RSTimeOutDetector :: SetParam Invaild Key ");
		return;
	}
	int valueInt = atoi(value.c_str());
	if (valueInt <= 0 || valueInt > 1000000) { // 1000000Ms->1000s
		RS_LOGD("RSTimeOutDetector :: SetParam Invaild Value ");
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
	if (finishTimeStampMs > startTimeStampMs_ && finishTimeStampMs - startTimeStampMs_ > timeOutThreadMs_) {
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