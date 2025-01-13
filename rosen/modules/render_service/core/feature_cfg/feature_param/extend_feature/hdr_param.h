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

#ifndef HDR_PARAM_H
#define HDR_PARAM_H

#include "feature_param.h"

namespace OHOS::Rosen {
class HDRParam : public FeatureParam {
public:
    HDRParam() = default;
    ~HDRParam() = default;

    bool IsHdrVideoEnable() const;
    bool IsHdrImageEnable() const;

    void SetHdrVideoEnable(bool isEnable);
    void SetHdrImageEnable(bool isEnable);

private:
    bool isHdrVideoEnable_;
    bool isHdrImageEnable_;

};
} // namespace OHOS::Rosen
#endif // HDR_PARAM_H