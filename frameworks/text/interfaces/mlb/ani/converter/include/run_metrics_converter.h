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

#ifndef OHOS_TEXT_ANI_RUN_METRICS_CONVERTER_H
#define OHOS_TEXT_ANI_RUN_METRICS_CONVERTER_H

#include <ani.h>
#include <map>

#include "typography.h"

namespace OHOS::Text::NAI {
class RunMetricsConverter {
public:
    static ani_object ParseRunMetricsToAni(ani_env* env, const std::map<size_t, OHOS::Rosen::RunMetrics>& map);
};
} // namespace OHOS::Text::NAI
#endif // OHOS_TEXT_ANI_RUN_METRICS_CONVERTER_H