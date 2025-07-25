/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef POLICY_CONFIG_VISITOR_MOCK_H
#define POLICY_CONFIG_VISITOR_MOCK_H

#include <gmock/gmock.h>

#include "hgm_command.h"

namespace OHOS {
namespace Rosen {
namespace Mock {
class PolicyConfigVisitorMock : public PolicyConfigVisitor {
public:
    PolicyConfigVisitorMock() = default;
    virtual ~PolicyConfigVisitorMock() = default;

    MOCK_CONST_METHOD0(GetXmlData, const PolicyConfigData&());
    MOCK_METHOD1(SetSettingModeId, void(int32_t));
    MOCK_METHOD1(SetXmlModeId, void(const std::string&));
    MOCK_METHOD1(ChangeScreen, void(const std::string&));
    MOCK_CONST_METHOD2(GetStrategyConfig, HgmErrCode(const std::string&, PolicyConfigData::StrategyConfig&));
    MOCK_CONST_METHOD0(GetScreenSetting, const PolicyConfigData::ScreenSetting&());
    MOCK_CONST_METHOD0(GetAceSceneDynamicSettingMap, const PolicyConfigData::DynamicSettingMap&());
    MOCK_CONST_METHOD3(GetAppStrategyConfig,
        HgmErrCode(const std::string&, int32_t, PolicyConfigData::StrategyConfig&));
    MOCK_CONST_METHOD2(GetDynamicAppStrategyConfig, HgmErrCode(const std::string&, PolicyConfigData::StrategyConfig&));
    MOCK_CONST_METHOD1(GetGameNodeName, std::string(const std::string&));
};
} // namespace Mock
} // namespace Rosen
} // namespace OHOS
#endif // POLICY_CONFIG_VISITOR_MOCK_H