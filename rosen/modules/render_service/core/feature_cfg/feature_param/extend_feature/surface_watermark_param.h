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

#ifndef SURFACE_WATERMARK_PARAM_H
#define SURFACE_WATERMARK_PARAM_H

#include "feature_param.h"

namespace OHOS::Rosen {
class SurfaceWatermarkParam : public FeatureParam {
public:
    SurfaceWatermarkParam() = default;
    ~SurfaceWatermarkParam() = default;

    bool IsSurfaceWatermarkEnable() const;

protected:
    void SetSurfaceWatermarkEnable(bool isEnable);

private:
    bool isSurfaceWatermarkEnable_ = true;

    friend class SurfaceWatermarkParamParse;
};
} // namespace OHOS::Rosen
#endif // SURFACE_WATERMARK_PARAM_H

