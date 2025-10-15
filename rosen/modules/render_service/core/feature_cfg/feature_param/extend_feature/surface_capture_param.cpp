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

#include "surface_capture_param.h"

namespace OHOS::Rosen {
bool SurfaceCaptureParam::IsUseOptimizedFlushAndSubmitEnabled() const
{
    return useOptimizedFlushAndSubmitEnabled_;
}

bool SurfaceCaptureParam::IsDeferredDmaSurfaceReleaseEnabled() const
{
    return deferredDmaSurfaceReleaseEnabled_;
}

void SurfaceCaptureParam::SetUseOptimizedFlushAndSubmitEnabled(bool enabled)
{
    useOptimizedFlushAndSubmitEnabled_ = enabled;
}

void SurfaceCaptureParam::SetDeferredDmaSurfaceReleaseEnabled(bool enabled)
{
    deferredDmaSurfaceReleaseEnabled_ = enabled;
}
} // namespace OHOS::Rosen