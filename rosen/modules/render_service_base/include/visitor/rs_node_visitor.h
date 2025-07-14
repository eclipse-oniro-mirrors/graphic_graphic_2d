/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#ifndef RENDER_SERVICE_CLIENT_CORE_RENDER_RS_NODE_VISITOR_H
#define RENDER_SERVICE_CLIENT_CORE_RENDER_RS_NODE_VISITOR_H

#include <memory>

namespace OHOS {
namespace Rosen {
class RSRenderNode;
class RSCanvasRenderNode;
class RSScreenRenderNode;
class RSLogicalDisplayRenderNode;
class RSProxyRenderNode;
class RSRootRenderNode;
class RSSurfaceRenderNode;
class RSEffectRenderNode;

class RSNodeVisitor : public std::enable_shared_from_this<RSNodeVisitor> {
public:
    RSNodeVisitor() = default;
    RSNodeVisitor(const RSNodeVisitor&) = delete;
    RSNodeVisitor(RSNodeVisitor&&) = delete;
    RSNodeVisitor& operator=(const RSNodeVisitor&) = delete;
    RSNodeVisitor& operator=(RSNodeVisitor&&) = delete;
    virtual ~RSNodeVisitor() = default;

    virtual void QuickPrepareChildren(RSRenderNode& node) {}
    virtual void QuickPrepareCanvasRenderNode(RSCanvasRenderNode& node) {}
    virtual void QuickPrepareScreenRenderNode(RSScreenRenderNode& node) {}
    virtual void QuickPrepareEffectRenderNode(RSEffectRenderNode& node) {}
    virtual void QuickPrepareLogicalDisplayRenderNode(RSLogicalDisplayRenderNode& node) {}
    virtual void QuickPrepareSurfaceRenderNode(RSSurfaceRenderNode& node) {}

    virtual void PrepareChildren(RSRenderNode& node) = 0;
    virtual void PrepareCanvasRenderNode(RSCanvasRenderNode& node) = 0;
    virtual void PrepareScreenRenderNode(RSScreenRenderNode& node) = 0;
    virtual void PrepareEffectRenderNode(RSEffectRenderNode& node) = 0;
    virtual void PrepareLogicalDisplayRenderNode(RSLogicalDisplayRenderNode& node) = 0;
    virtual void PrepareProxyRenderNode(RSProxyRenderNode& node) = 0;
    virtual void PrepareRootRenderNode(RSRootRenderNode& node) = 0;
    virtual void PrepareSurfaceRenderNode(RSSurfaceRenderNode& node) = 0;

    virtual void ProcessChildren(RSRenderNode& node) = 0;
    virtual void ProcessCanvasRenderNode(RSCanvasRenderNode& node) = 0;
    virtual void ProcessScreenRenderNode(RSScreenRenderNode& node) = 0;
    virtual void ProcessProxyRenderNode(RSProxyRenderNode& node) = 0;
    virtual void ProcessLogicalDisplayRenderNode(RSLogicalDisplayRenderNode& node) = 0;
    virtual void ProcessRootRenderNode(RSRootRenderNode& node) = 0;
    virtual void ProcessSurfaceRenderNode(RSSurfaceRenderNode& node) = 0;
    virtual void ProcessEffectRenderNode(RSEffectRenderNode& node) = 0;
    virtual void RegisterHpaeCallback(RSRenderNode& node) {};
    virtual void AddSurfaceChangedCallBack(uint64_t id,
        const std::function<void(float, float, float, float)>& callback) {};
    virtual void RemoveSurfaceChangedCallBack(uint64_t id) {};
};

} // namespace Rosen
} // namespace OHOS

#endif // RENDER_SERVICE_CLIENT_CORE_RENDER_RS_NODE_VISITOR_H
