/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#ifndef RENDER_SERVICE_BASE_DRAWING_RS_SURFACE_FRAME_H
#define RENDER_SERVICE_BASE_DRAWING_RS_SURFACE_FRAME_H

#include <memory>

#include "include/core/SkCanvas.h"

namespace OHOS {
namespace Rosen {
#ifdef ACE_ENABLE_GL
class RenderContext;
#endif
class RSSurfaceFrame {
public:
    RSSurfaceFrame() = default;
    virtual ~RSSurfaceFrame() = default;

    virtual void SetDamageRegion(int32_t left, int32_t top, int32_t width, int32_t height) {};
    virtual SkCanvas* GetCanvas() = 0;
#ifdef ACE_ENABLE_GL
    virtual void SetRenderContext(RenderContext* context) = 0;
#endif
protected:
    std::shared_ptr<SkCanvas> canvas_;
private:
};

} // namespace Rosen
} // namespace OHOS

#endif // RENDER_SERVICE_BASE_DRAWING_RS_SURFACE_FRAME_H
