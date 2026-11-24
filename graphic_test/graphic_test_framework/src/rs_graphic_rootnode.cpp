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

#include "rs_graphic_rootnode.h"
#include "rs_graphic_test_director.h"
#include "platform/common/rs_system_properties.h"
#include "transaction/rs_interfaces.h"
#include "ui/rs_root_node.h"
#include "rs_graphic_errors.h"
#include "rs_graphic_log.h"

namespace OHOS {
namespace Rosen {
namespace {
constexpr int BOUNDS_WIDTH_INDEX = 2;
constexpr int BOUNDS_HEIGHT_INDEX = 3;
} // namespace

RSGraphicRootNode::RSGraphicRootNode()
{
    // The value is cached by RSSystemProperties after RSUIDirector::Init, so this costs no extra IPC.
    isDividedRender_ = !RSSystemProperties::GetUniRenderEnabled();
    RSSurfaceNodeConfig config;
    config.SurfaceNodeName = "TestScreenSurface";
    screenSurfaceNode_ = RSSurfaceNode::Create(config, RSSurfaceNodeType::LEASH_WINDOW_NODE, true, false,
        RSGraphicTestDirector::Instance().GetRSUIContext());
    if (!screenSurfaceNode_) {
        LOGE("RSGraphicRootNode::RSGraphicRootNode create screen surface node failed");
    }
}

std::shared_ptr<RSRootNode> RSGraphicRootNode::BindDividedRenderRoot(const std::shared_ptr<RSSurfaceNode>& surface)
{
    if (!isDividedRender_ || !surface) {
        return nullptr;
    }
    auto root = std::static_pointer_cast<RSRootNode>(
        RSRootNode::Create(false, false, RSGraphicTestDirector::Instance().GetRSUIContext()));
    if (!root) {
        LOGE("RSGraphicRootNode::BindDividedRenderRoot create root node failed");
        return nullptr;
    }
    // The root draws in the surface's own coordinate space; it repaints the surface background because
    // the client render thread does not draw surface node properties into the buffer.
    const auto& properties = surface->GetStagingProperties();
    const Vector4f bounds = properties.GetBounds();
    root->SetBounds({0, 0, bounds[BOUNDS_WIDTH_INDEX], bounds[BOUNDS_HEIGHT_INDEX]});
    root->SetFrame({0, 0, bounds[BOUNDS_WIDTH_INDEX], bounds[BOUNDS_HEIGHT_INDEX]});
    root->SetBackgroundColor(properties.GetBackgroundColor().AsRgbaInt());
    RSGraphicTestDirector::Instance().BindRootToSurface(surface, root);
    return root;
}

std::shared_ptr<RSNode> RSGraphicRootNode::GetMainDrawParent() const
{
    if (isDividedRender_ && !testRootNodes_.empty() && testRootNodes_.back()) {
        return testRootNodes_.back();
    }
    if (testSurfaceNodes_.empty()) {
        return nullptr;
    }
    return testSurfaceNodes_.back();
}

void RSGraphicRootNode::SyncTestSurfaceBounds(const Vector4f& bounds)
{
    if (!isDividedRender_ || testRootNodes_.empty() || !testRootNodes_.back()) {
        return;
    }
    testRootNodes_.back()->SetBounds({0, 0, bounds[BOUNDS_WIDTH_INDEX], bounds[BOUNDS_HEIGHT_INDEX]});
    testRootNodes_.back()->SetFrame({0, 0, bounds[BOUNDS_WIDTH_INDEX], bounds[BOUNDS_HEIGHT_INDEX]});
}

void RSGraphicRootNode::SyncTestSurfaceColor(uint32_t color)
{
    if (!isDividedRender_ || testRootNodes_.empty() || !testRootNodes_.back()) {
        return;
    }
    testRootNodes_.back()->SetBackgroundColor(color);
}

void RSGraphicRootNode::SetTestSurface(
    std::shared_ptr<OHOS::Rosen::RSSurfaceNode> node)
{
    if (!screenSurfaceNode_) {
        LOGE("RSGraphicRootNode::SetTestSurface screenSurfaceNode_ is null");
        return;
    }
    if (!node) {
        LOGE("RSGraphicRootNode::SetTestSurface node is null");
        return;
    }
    testSurfaceNodes_.push_back(node);
    screenSurfaceNode_->AddChild(testSurfaceNodes_.back(), -1);
    if (isDividedRender_) {
        testRootNodes_.push_back(BindDividedRenderRoot(node));
    }
}

void RSGraphicRootNode::ResetTestSurface()
{
    if (screenSurfaceNode_) {
        screenSurfaceNode_->ClearChildren();
    } else {
        LOGE("RSGraphicRootNode::ResetTestSurface screenSurfaceNode_ is null");
    }
    testSurfaceNodes_.clear();
    testRootNodes_.clear();
    nodes_.clear();
}

void RSGraphicRootNode::AddChild(std::shared_ptr<RSNode> child, int index)
{
    auto parent = GetMainDrawParent();
    if (!parent) {
        LOGE("RSGraphicRootNode::AddChild test surface node is null");
        return;
    }
    parent->AddChild(child, index);
}

void RSGraphicRootNode::RemoveChild(std::shared_ptr<RSNode> child)
{
    if (testSurfaceNode_) {
        testSurfaceNode_->RemoveChild(child);
    }
}

void RSGraphicRootNode::ClearChildren()
{
    if (testSurfaceNode_) {
        testSurfaceNode_->ClearChildren();
    }
}

void RSGraphicRootNode::RegisterNode(std::shared_ptr<RSNode> node)
{
    nodes_.push_back(node);
}

void RSGraphicRootNode::SetScreenId(ScreenId id)
{
    screenId_ = id;
}

void RSGraphicRootNode::SetMainWindowZ(float mainZ)
{
    mainWindowZ_ = mainZ;
}

float RSGraphicRootNode::GetMainWindowZ() const
{
    return mainWindowZ_;
}

std::shared_ptr<RSSurfaceNode> RSGraphicRootNode::CreateContentNode(
    SubWindowId id, const SubWindowOptions& options)
{
    RSSurfaceNodeConfig contentConfig;
    contentConfig.SurfaceNodeName =
        "SubWindowSurface_" + std::to_string(id);
    auto contentNode = RSSurfaceNode::Create(
        contentConfig, RSSurfaceNodeType::APP_WINDOW_NODE, true, false,
        RSGraphicTestDirector::Instance().GetRSUIContext());
    if (!contentNode) {
        LOGE("RSGraphicRootNode::CreateContentNode create failed");
        return nullptr;
    }

    float width = options.bounds[BOUNDS_WIDTH_INDEX];
    float height = options.bounds[BOUNDS_HEIGHT_INDEX];
    contentNode->SetBounds({0, 0, width, height});
    contentNode->SetFrame({0, 0, width, height});
    contentNode->SetBackgroundColor(options.contentBgColor);
    return contentNode;
}

SubWindowId RSGraphicRootNode::CreateSubWindow(const SubWindowOptions& options)
{
    if (!screenSurfaceNode_) {
        LOGE("RSGraphicRootNode::CreateSubWindow screenSurfaceNode_ is null");
        return INVALID_SUB_WINDOW_ID;
    }

    SubWindowId id = nextSubWindowId_++;

    RSSurfaceNodeConfig leashConfig;
    leashConfig.SurfaceNodeName = "SubWindow_" + std::to_string(id);
    auto leashNode = RSSurfaceNode::Create(
        leashConfig, RSSurfaceNodeType::LEASH_WINDOW_NODE, true, false,
        RSGraphicTestDirector::Instance().GetRSUIContext());
    if (!leashNode) {
        LOGE("RSGraphicRootNode::CreateSubWindow create leash node failed");
        return INVALID_SUB_WINDOW_ID;
    }

    leashNode->SetBounds(options.bounds);
    leashNode->SetFrame(options.bounds);
    leashNode->SetBackgroundColor(0);
    leashNode->AttachToDisplay(screenId_);

    float zValue = 0.0f;
    switch (options.order) {
        case SubWindowOrder::ABOVE_MAIN:
            zValue = mainWindowZ_ + 1.0f;
            break;
        case SubWindowOrder::BELOW_MAIN:
            zValue = mainWindowZ_ - 1.0f;
            break;
        case SubWindowOrder::ABSOLUTE:
            zValue = options.absoluteZ;
            break;
    }
    leashNode->SetPositionZ(zValue);

    auto contentNode = CreateContentNode(id, options);
    if (!contentNode) {
        leashNode->RemoveFromTree();
        return INVALID_SUB_WINDOW_ID;
    }

    leashNode->AddChild(contentNode, -1);
    subWindows_[id] = {leashNode, contentNode, BindDividedRenderRoot(contentNode)};
    return id;
}

std::shared_ptr<RSSurfaceNode> RSGraphicRootNode::GetSubWindow(
    SubWindowId id) const
{
    auto it = subWindows_.find(id);
    if (it == subWindows_.end()) {
        LOGE("RSGraphicRootNode::GetSubWindow invalid id %{public}u", id);
        return nullptr;
    }
    return it->second.leashNode;
}

std::shared_ptr<RSSurfaceNode> RSGraphicRootNode::GetSubWindowTestSurface(
    SubWindowId id) const
{
    auto it = subWindows_.find(id);
    if (it == subWindows_.end()) {
        LOGE("RSGraphicRootNode::GetSubWindowTestSurface invalid id "
            "%{public}u", id);
        return nullptr;
    }
    return it->second.contentNode;
}

bool RSGraphicRootNode::AddChildToSubWindow(
    SubWindowId id, std::shared_ptr<RSNode> child, int childIndex)
{
    auto it = subWindows_.find(id);
    if (it == subWindows_.end()) {
        LOGE("RSGraphicRootNode::AddChildToSubWindow invalid id "
            "%{public}u", id);
        return false;
    }
    if (!it->second.contentNode) {
        LOGE("RSGraphicRootNode::AddChildToSubWindow content node is null");
        return false;
    }
    if (it->second.contentRoot) {
        it->second.contentRoot->AddChild(child, childIndex);
    } else {
        it->second.contentNode->AddChild(child, childIndex);
    }
    return true;
}

bool RSGraphicRootNode::RemoveSubWindow(SubWindowId id)
{
    auto it = subWindows_.find(id);
    if (it == subWindows_.end()) {
        LOGE("RSGraphicRootNode::RemoveSubWindow invalid id %{public}u", id);
        return false;
    }
    it->second.leashNode->ClearChildren();
    it->second.leashNode->RemoveFromTree();
    subWindows_.erase(it);
    return true;
}

void RSGraphicRootNode::ResetSubWindows()
{
    for (auto& [id, entry] : subWindows_) {
        if (entry.leashNode) {
            entry.leashNode->ClearChildren();
            entry.leashNode->RemoveFromTree();
        }
    }
    subWindows_.clear();
}

bool RSGraphicRootNode::HasSubWindows() const
{
    return !subWindows_.empty();
}

} // namespace Rosen
} // namespace OHOS
