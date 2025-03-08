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

#ifndef OFFSCREEN_PARAM_H
#define OFFSCREEN_PARAM_H

#include "feature_param.h"

namespace OHOS::Rosen {
class RotateOffScreenParam : public FeatureParam {
public:
    RotateOffScreenParam() = default;
    ~RotateOffScreenParam() = default;

    bool GetRotateOffScreenDisplayNodeEnable() const;

protected:
    void SetRotateOffScreenDisplayNodeEnable(bool enable);
private:
    bool isRotateOffScreenDisplayNodeEnable_ = false;

    friend class RotateOffScreenParamParse;
};
} // namespace OHOS::Rosen
#endif // OFFSCREEN_PARAM_H