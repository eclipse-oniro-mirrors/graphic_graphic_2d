/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef ROSEN_RENDER_SERVICE_BASE_RS_VARIABLE_FRAME_RATE_H
#define ROSEN_RENDER_SERVICE_BASE_RS_VARIABLE_FRAME_RATE_H

#include <vector>
#include <parcel.h>

#include "common/rs_macros.h"

namespace OHOS {
namespace Rosen {

// Used for refresh rate decisions in the HGM module
struct EventInfo {
    std::string eventName;   // unique ID assigned by HGM, e.g."VOTER_THERMAL"
    bool eventStatus;        // true-enter, false-exit
    uint32_t minRefreshRate; // the desired min refresh rate, e.g.60
    uint32_t maxRefreshRate; // the desired max refresh rate, e.g.120
    std::string description; // the extend description for eventName，e.g."SCENE_APP_START_ANIMATION"
};

} // namespace Rosen
} // namespace OHOS

#endif
