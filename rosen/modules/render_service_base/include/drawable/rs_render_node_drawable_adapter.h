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

#ifndef RENDER_SERVICE_BASE_DRAWABLE_RS_RENDER_NODE_DRAWABLE_ADAPTER_H
#define RENDER_SERVICE_BASE_DRAWABLE_RS_RENDER_NODE_DRAWABLE_ADAPTER_H

#include <memory>
#include <unordered_map>

#include "common/rs_common_def.h"
#include "common/rs_macros.h"

namespace OHOS::Rosen {
class RSRenderNode;
namespace Drawing {
class Canvas;
}

namespace DrawableV2 {
class RSB_EXPORT RSRenderNodeDrawableAdapter {
public:
    explicit RSRenderNodeDrawableAdapter(std::shared_ptr<const RSRenderNode>&& node);
    virtual ~RSRenderNodeDrawableAdapter() = default;

    // delete
    RSRenderNodeDrawableAdapter(const RSRenderNodeDrawableAdapter&) = delete;
    RSRenderNodeDrawableAdapter(const RSRenderNodeDrawableAdapter&&) = delete;
    RSRenderNodeDrawableAdapter& operator=(const RSRenderNodeDrawableAdapter&) = delete;
    RSRenderNodeDrawableAdapter& operator=(const RSRenderNodeDrawableAdapter&&) = delete;

    using Ptr = RSRenderNodeDrawableAdapter*;
    using SharedPtr = std::shared_ptr<RSRenderNodeDrawableAdapter>;
    using WeakPtr = std::weak_ptr<RSRenderNodeDrawableAdapter>;

    virtual void Draw(Drawing::Canvas& canvas) = 0;
    virtual void DrawWithoutShadow(Drawing::Canvas& canvas) = 0;
    virtual void DrawShadow(Drawing::Canvas& canvas) = 0;
    virtual void OnDraw(Drawing::Canvas& canvas) = 0;
    virtual void OnCapture(Drawing::Canvas& canvas) = 0;
    static SharedPtr OnGenerate(const std::shared_ptr<const RSRenderNode>& node);
    virtual void DumpDrawableTree(int32_t depth, std::string& out) const = 0;

protected:
    using Generator = Ptr (*)(std::shared_ptr<const RSRenderNode>);
    static std::unordered_map<RSRenderNodeType, Generator> GeneratorMap;

    std::shared_ptr<const RSRenderNode> renderNode_;

    template<RSRenderNodeType type, Generator generator>
    class RenderNodeDrawableRegistrar {
    public:
        RenderNodeDrawableRegistrar()
        {
            RSRenderNodeDrawableAdapter::GeneratorMap.emplace(type, generator);
        }
    };
};
} // namespace DrawableV2
} // namespace OHOS::Rosen
#endif // RENDER_SERVICE_BASE_DRAWABLE_RS_RENDER_NODE_DRAWABLE_ADAPTER_H