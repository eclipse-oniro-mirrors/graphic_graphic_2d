/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#ifndef RS_GRAPHIC_TEST_HEALTH_H
#define RS_GRAPHIC_TEST_HEALTH_H

#include <string>

namespace OHOS {
namespace Rosen {

struct EmulatorHealthStatus {
    bool rsAlive = false;
    bool screenOn = false;
    // DisplayState::ON is the public readiness signal, not a keyguard proof.
    bool screenUnlocked = false;
};

class IEmulatorHealthProbe {
public:
    virtual ~IEmulatorHealthProbe() = default;
    virtual EmulatorHealthStatus Check() = 0;
};

class DefaultEmulatorHealthProbe final : public IEmulatorHealthProbe {
public:
    EmulatorHealthStatus Check() override;
};

bool ValidateSuiteHealth(const EmulatorHealthStatus& status, std::string& error);

} // namespace Rosen
} // namespace OHOS

#endif // RS_GRAPHIC_TEST_HEALTH_H
