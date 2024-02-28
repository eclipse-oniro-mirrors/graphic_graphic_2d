/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef RENDER_SERVICE_BASE_DRAWABLE_RS_RENDER_NODE_DRAWABLE_H
#define RENDER_SERVICE_BASE_DRAWABLE_RS_RENDER_NODE_DRAWABLE_H

#include <memory>

#include "common/rs_macros.h"
#include "drawable/rs_drawable.h"

namespace OHOS::Rosen {
class RSRenderNode;

// Used by RSUniRenderThread and RSChildrenDrawable
class RSB_EXPORT RSRenderNodeDrawable {
public:
    explicit RSRenderNodeDrawable(std::shared_ptr<const RSRenderNode>&& node);
    virtual ~RSRenderNodeDrawable() = default;

    virtual void OnDraw(RSPaintFilterCanvas& canvas) const;

    using Ptr = std::unique_ptr<RSRenderNodeDrawable>;

protected:
    std::shared_ptr<const RSRenderNode> renderNode_;
    // not public visible
    static Ptr OnGenerate(std::shared_ptr<const RSRenderNode> node);
    friend class RSChildrenDrawable;
};

} // namespace OHOS::Rosen
#endif // RENDER_SERVICE_BASE_DRAWABLE_RS_RENDER_NODE_DRAWABLE_H
