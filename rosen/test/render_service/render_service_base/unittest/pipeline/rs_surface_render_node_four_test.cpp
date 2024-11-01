/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, Hardware
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <gtest/gtest.h>

#include "pipeline/rs_context.h"
#include "params/rs_surface_render_params.h"
#include "pipeline/rs_surface_render_node.h"
#include "pipeline/rs_render_thread_visitor.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace Rosen {
class RSSurfaceRenderNodeFourTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
    static inline NodeId id;
};

void RSSurfaceRenderNodeFourTest::SetUpTestCase() {}
void RSSurfaceRenderNodeFourTest::TearDownTestCase() {}
void RSSurfaceRenderNodeFourTest::SetUp() {}
void RSSurfaceRenderNodeFourTest::TearDown() {}

class CustomBufferClearCallback : public RSIBufferClearCallback {
public:
    CustomBufferClearCallback() = default;
    ~CustomBufferClearCallback() override {}
    void OnBufferClear() override {}
    sptr<IRemoteObject> AsObject() override
    {
        return nullptr;
    }
};

class CustomBufferAvailableCallback : public RSIBufferAvailableCallback {
public:
    CustomBufferAvailableCallback() = default;
    ~CustomBufferAvailableCallback() override {}
    void OnBufferAvailable() override {}
    sptr<IRemoteObject> AsObject() override
    {
        return nullptr;
    }
};

/**
 * @tc.name: ProcessAnimatePropertyAfterChildren
 * @tc.desc: test results of ProcessAnimatePropertyAfterChildren
 * @tc.type:FUNC ProcessAnimatePropertyAfterChildren
 * @tc.require:
 */
HWTEST_F(RSSurfaceRenderNodeFourTest, ProcessAnimatePropertyAfterChildren, TestSize.Level2)
{
    auto rsContext = std::make_shared<RSContext>();
    auto node = std::make_shared<RSSurfaceRenderNode>(id, rsContext);
    node->stagingRenderParams_ = std::make_unique<RSSurfaceRenderParams>(id);
    Drawing::Canvas canvas;
    RSPaintFilterCanvas filterCanvas(&canvas);
    node->needDrawAnimateProperty_ = false;
    node->ProcessAnimatePropertyAfterChildren(filterCanvas);
    node->needDrawAnimateProperty_ = true;
    node->ProcessAnimatePropertyAfterChildren(filterCanvas);
    node->cacheType_ = CacheType::ANIMATE_PROPERTY;
    node->needDrawAnimateProperty_ = false;
    node->ProcessAnimatePropertyAfterChildren(filterCanvas);
    node->needDrawAnimateProperty_ = true;
    node->ProcessAnimatePropertyAfterChildren(filterCanvas);
    node->nodeType_ = RSSurfaceNodeType::SELF_DRAWING_NODE;
    node->ProcessAnimatePropertyAfterChildren(filterCanvas);
    ASSERT_TRUE(node->GetSurfaceNodeType() == RSSurfaceNodeType::SELF_DRAWING_NODE);
}

/**
 * @tc.name: SetForceHardwareAndFixRotation
 * @tc.desc: test results of SetForceHardwareAndFixRotation
 * @tc.type:FUNC SetForceHardwareAndFixRotation
 * @tc.require:
 */
HWTEST_F(RSSurfaceRenderNodeFourTest, SetForceHardwareAndFixRotation, TestSize.Level2)
{
    auto rsContext = std::make_shared<RSContext>();
    auto node = std::make_shared<RSSurfaceRenderNode>(id, rsContext);
    node->needDrawAnimateProperty_ = false;
    node->SetForceHardwareAndFixRotation(true);
    node->stagingRenderParams_ = std::make_unique<RSSurfaceRenderParams>(id);
    node->SetForceHardwareAndFixRotation(true);
    ASSERT_TRUE(true);
}

/**
 * @tc.name: SetSkipLayer
 * @tc.desc: test results of SetSkipLayer
 * @tc.type:FUNC SetSkipLayer
 * @tc.require:
 */
HWTEST_F(RSSurfaceRenderNodeFourTest, SetSkipLayer, TestSize.Level2)
{
    auto rsContext = std::make_shared<RSContext>();
    auto node = std::make_shared<RSSurfaceRenderNode>(id, rsContext);
    node->SetSkipLayer(true);
    ASSERT_FALSE(node->skipLayerIds_.empty());
    node->SetSkipLayer(false);
    ASSERT_TRUE(node->skipLayerIds_.empty());
}

/**
 * @tc.name: SyncSecurityInfoToFirstLevelNode
 * @tc.desc: test results of SyncSecurityInfoToFirstLevelNode
 * @tc.type:FUNC SyncSecurityInfoToFirstLevelNode
 * @tc.require:
 */
HWTEST_F(RSSurfaceRenderNodeFourTest, SyncSecurityInfoToFirstLevelNode, TestSize.Level2)
{
    auto rsContext = std::make_shared<RSContext>();
    auto node = std::make_shared<RSSurfaceRenderNode>(id, rsContext);
    rsContext->GetMutableNodeMap().renderNodeMap_.clear();
    node->SyncSecurityInfoToFirstLevelNode();
    ASSERT_EQ(node->GetFirstLevelNode(), nullptr);
    rsContext->GetMutableNodeMap().renderNodeMap_[id] = node;
    node->firstLevelNodeId_ = id;
    node->SyncSecurityInfoToFirstLevelNode();
    ASSERT_NE(node->GetFirstLevelNode(), nullptr);
    ASSERT_FALSE(node->GetFirstLevelNodeId() != node->GetId());
    auto nodeTwo = std::make_shared<RSSurfaceRenderNode>(id + 1, rsContext);
    rsContext->GetMutableNodeMap().renderNodeMap_[id + 1] = nodeTwo;
    node->firstLevelNodeId_ = id + 1;
    node->SyncSecurityInfoToFirstLevelNode();
    ASSERT_NE(node->GetFirstLevelNode(), nullptr);
    ASSERT_TRUE(node->GetFirstLevelNodeId() != node->GetId());
    node->isSecurityLayer_ = true;
    node->SyncSecurityInfoToFirstLevelNode();
    ASSERT_NE(node->GetFirstLevelNode(), nullptr);
    node->isOnTheTree_ = true;
    node->isSecurityLayer_ = false;
    node->SyncSecurityInfoToFirstLevelNode();
    ASSERT_NE(node->GetFirstLevelNode(), nullptr);
    node->isOnTheTree_ = true;
    node->isSecurityLayer_ = true;
    node->SyncSecurityInfoToFirstLevelNode();
    ASSERT_NE(node->GetFirstLevelNode(), nullptr);
}

/**
 * @tc.name: SyncSkipInfoToFirstLevelNode
 * @tc.desc: test results of SyncSkipInfoToFirstLevelNode
 * @tc.type:FUNC SyncSkipInfoToFirstLevelNode
 * @tc.require:
 */
HWTEST_F(RSSurfaceRenderNodeFourTest, SyncSkipInfoToFirstLevelNode, TestSize.Level2)
{
    auto rsContext = std::make_shared<RSContext>();
    auto node = std::make_shared<RSSurfaceRenderNode>(id, rsContext);
    rsContext->GetMutableNodeMap().renderNodeMap_.clear();
    node->SyncSkipInfoToFirstLevelNode();
    ASSERT_EQ(node->GetFirstLevelNode(), nullptr);
    rsContext->GetMutableNodeMap().renderNodeMap_[id] = node;
    node->firstLevelNodeId_ = id;
    node->SyncSkipInfoToFirstLevelNode();
    ASSERT_NE(node->GetFirstLevelNode(), nullptr);
    ASSERT_FALSE(node->GetFirstLevelNodeId() != node->GetId());
    auto nodeTwo = std::make_shared<RSSurfaceRenderNode>(id + 1, rsContext);
    rsContext->GetMutableNodeMap().renderNodeMap_[id + 1] = nodeTwo;
    node->firstLevelNodeId_ = id + 1;
    node->SyncSkipInfoToFirstLevelNode();
    ASSERT_NE(node->GetFirstLevelNode(), nullptr);
    ASSERT_TRUE(node->GetFirstLevelNodeId() != node->GetId());
    node->isSkipLayer_ = true;
    node->SyncSkipInfoToFirstLevelNode();
    ASSERT_NE(node->GetFirstLevelNode(), nullptr);
    node->isOnTheTree_ = true;
    node->isSkipLayer_ = false;
    node->SyncSkipInfoToFirstLevelNode();
    ASSERT_NE(node->GetFirstLevelNode(), nullptr);
    node->isOnTheTree_ = true;
    node->isSkipLayer_ = true;
    node->SyncSkipInfoToFirstLevelNode();
    ASSERT_NE(node->GetFirstLevelNode(), nullptr);
}

/**
 * @tc.name: SyncProtectedInfoToFirstLevelNode
 * @tc.desc: test results of SyncProtectedInfoToFirstLevelNode
 * @tc.type:FUNC SyncProtectedInfoToFirstLevelNode
 * @tc.require:
 */
HWTEST_F(RSSurfaceRenderNodeFourTest, SyncProtectedInfoToFirstLevelNode, TestSize.Level2)
{
    auto rsContext = std::make_shared<RSContext>();
    auto node = std::make_shared<RSSurfaceRenderNode>(id, rsContext);
    rsContext->GetMutableNodeMap().renderNodeMap_.clear();
    node->SyncProtectedInfoToFirstLevelNode();
    node->isProtectedLayer_ = true;
    node->SyncProtectedInfoToFirstLevelNode();
    ASSERT_EQ(node->GetFirstLevelNode(), nullptr);
    rsContext->GetMutableNodeMap().renderNodeMap_[id] = node;
    node->firstLevelNodeId_ = id;
    node->SyncProtectedInfoToFirstLevelNode();
    ASSERT_NE(node->GetFirstLevelNode(), nullptr);
    ASSERT_FALSE(node->GetFirstLevelNodeId() != node->GetId());
    auto nodeTwo = std::make_shared<RSSurfaceRenderNode>(id + 1, rsContext);
    rsContext->GetMutableNodeMap().renderNodeMap_[id + 1] = nodeTwo;
    node->firstLevelNodeId_ = id + 1;
    node->SyncProtectedInfoToFirstLevelNode();
    ASSERT_NE(node->GetFirstLevelNode(), nullptr);
    ASSERT_TRUE(node->GetFirstLevelNodeId() != node->GetId());
    node->isOnTheTree_ = true;
    node->SyncProtectedInfoToFirstLevelNode();
    ASSERT_NE(node->GetFirstLevelNode(), nullptr);
}

/**
 * @tc.name: UpdateSurfaceDefaultSize
 * @tc.desc: test results of UpdateSurfaceDefaultSize
 * @tc.type:FUNC UpdateSurfaceDefaultSize
 * @tc.require:
 */
HWTEST_F(RSSurfaceRenderNodeFourTest, UpdateSurfaceDefaultSize, TestSize.Level2)
{
    auto rsContext = std::make_shared<RSContext>();
    auto node = std::make_shared<RSSurfaceRenderNode>(id, rsContext, true);
    node->UpdateSurfaceDefaultSize(1920.0f, 1080.0f);
    node->GetRSSurfaceHandler()->consumer_ = IConsumerSurface::Create();
    node->UpdateSurfaceDefaultSize(1920.0f, 1080.0f);
    ASSERT_NE(node->GetRSSurfaceHandler()->consumer_, nullptr);
    node->surfaceHandler_ = nullptr;
    node->UpdateSurfaceDefaultSize(1920.0f, 1080.0f);
    ASSERT_EQ(node->GetRSSurfaceHandler(), nullptr);
}

/**
 * @tc.name: NeedClearBufferCache
 * @tc.desc: test results of NeedClearBufferCache
 * @tc.type:FUNC NeedClearBufferCache
 * @tc.require:
 */
HWTEST_F(RSSurfaceRenderNodeFourTest, NeedClearBufferCache, TestSize.Level2)
{
    auto rsContext = std::make_shared<RSContext>();
    auto node = std::make_shared<RSSurfaceRenderNode>(id, rsContext);
    node->NeedClearBufferCache();
    ASSERT_NE(node->GetRSSurfaceHandler(), nullptr);
    ASSERT_EQ(node->GetRSSurfaceHandler()->GetBuffer(), nullptr);
    ASSERT_EQ(node->GetRSSurfaceHandler()->GetPreBuffer(), nullptr);
    node->stagingRenderParams_ = std::make_unique<RSSurfaceRenderParams>(id);
    node->GetRSSurfaceHandler()->buffer_.buffer = SurfaceBuffer::Create();
    node->NeedClearBufferCache();
    ASSERT_NE(node->GetRSSurfaceHandler(), nullptr);
    ASSERT_NE(node->GetRSSurfaceHandler()->GetBuffer(), nullptr);
    ASSERT_EQ(node->GetRSSurfaceHandler()->GetPreBuffer(), nullptr);
    node->GetRSSurfaceHandler()->buffer_.buffer = nullptr;
    node->GetRSSurfaceHandler()->preBuffer_.buffer = SurfaceBuffer::Create();
    node->NeedClearBufferCache();
    ASSERT_NE(node->GetRSSurfaceHandler(), nullptr);
    ASSERT_EQ(node->GetRSSurfaceHandler()->GetBuffer(), nullptr);
    ASSERT_NE(node->GetRSSurfaceHandler()->GetPreBuffer(), nullptr);
    node->GetRSSurfaceHandler()->buffer_.buffer = SurfaceBuffer::Create();
    node->GetRSSurfaceHandler()->preBuffer_.buffer = SurfaceBuffer::Create();
    node->NeedClearBufferCache();
    ASSERT_NE(node->GetRSSurfaceHandler(), nullptr);
    ASSERT_NE(node->GetRSSurfaceHandler()->GetBuffer(), nullptr);
    ASSERT_NE(node->GetRSSurfaceHandler()->GetPreBuffer(), nullptr);
    node->surfaceHandler_ = nullptr;
    node->NeedClearBufferCache();
    ASSERT_EQ(node->GetRSSurfaceHandler(), nullptr);
}

/**
 * @tc.name: RegisterBufferAvailableListener
 * @tc.desc: test results of RegisterBufferAvailableListener
 * @tc.type:FUNC RegisterBufferAvailableListener
 * @tc.require:
 */
HWTEST_F(RSSurfaceRenderNodeFourTest, RegisterBufferAvailableListener, TestSize.Level2)
{
    auto rsContext = std::make_shared<RSContext>();
    auto node = std::make_shared<RSSurfaceRenderNode>(id, rsContext);
    sptr<RSIBufferAvailableCallback> callback;
    node->isNotifyUIBufferAvailable_ = true;
    node->RegisterBufferAvailableListener(callback, true);
    ASSERT_TRUE(node->isNotifyUIBufferAvailable_);
    node->RegisterBufferAvailableListener(callback, false);
    ASSERT_FALSE(node->isNotifyUIBufferAvailable_);
}

/**
 * @tc.name: SetNotifyRTBufferAvailable
 * @tc.desc: test results of SetNotifyRTBufferAvailable
 * @tc.type:FUNC SetNotifyRTBufferAvailable
 * @tc.require:
 */
HWTEST_F(RSSurfaceRenderNodeFourTest, SetNotifyRTBufferAvailable, TestSize.Level2)
{
    auto rsContext = std::make_shared<RSContext>();
    auto node = std::make_shared<RSSurfaceRenderNode>(id, rsContext);
    node->SetNotifyRTBufferAvailable(true);
    ASSERT_EQ(node->clearBufferCallback_, nullptr);
    sptr<RSIBufferClearCallback> callback = new CustomBufferClearCallback();
    node->RegisterBufferClearListener(callback);
    node->SetNotifyRTBufferAvailable(true);
    ASSERT_NE(node->clearBufferCallback_, nullptr);
}

/**
 * @tc.name: NotifyRTBufferAvailable
 * @tc.desc: test results of NotifyRTBufferAvailable
 * @tc.type:FUNC NotifyRTBufferAvailable
 * @tc.require:
 */
HWTEST_F(RSSurfaceRenderNodeFourTest, NotifyRTBufferAvailable, TestSize.Level2)
{
    auto rsContext = std::make_shared<RSContext>();
    auto node = std::make_shared<RSSurfaceRenderNode>(id, rsContext);
    node->NotifyRTBufferAvailable(true);
    node->NotifyRTBufferAvailable(false);
    node->isNotifyRTBufferAvailable_ = false;
    node->NotifyRTBufferAvailable(true);
    node->NotifyRTBufferAvailable(false);
    node->isNotifyRTBufferAvailable_ = true;
    node->NotifyRTBufferAvailable(true);
    node->NotifyRTBufferAvailable(false);
    node->isRefresh_ = true;
    node->NotifyRTBufferAvailable(true);
    node->NotifyRTBufferAvailable(false);
    node->isRefresh_ = false;
    node->NotifyRTBufferAvailable(true);
    node->NotifyRTBufferAvailable(false);
    sptr<RSIBufferAvailableCallback> callback = new CustomBufferAvailableCallback();
    node->RegisterBufferAvailableListener(callback, true);
    node->NotifyRTBufferAvailable(true);
    node->NotifyRTBufferAvailable(false);
    node->isRefresh_ = true;
    node->NotifyRTBufferAvailable(true);
    node->NotifyRTBufferAvailable(false);
    ASSERT_TRUE(true);
}

/**
 * @tc.name: NotifyUIBufferAvailable
 * @tc.desc: test results of NotifyUIBufferAvailable
 * @tc.type:FUNC NotifyUIBufferAvailable
 * @tc.require:
 */
HWTEST_F(RSSurfaceRenderNodeFourTest, NotifyUIBufferAvailable, TestSize.Level2)
{
    auto rsContext = std::make_shared<RSContext>();
    auto node = std::make_shared<RSSurfaceRenderNode>(id, rsContext);
    node->isNotifyUIBufferAvailable_ = false;
    node->isWaitUifirstFirstFrame_ = false;
    node->NotifyUIBufferAvailable();
    ASSERT_TRUE(node->isNotifyUIBufferAvailable_);
    node->isNotifyUIBufferAvailable_ = true;
    node->isWaitUifirstFirstFrame_ = true;
    node->NotifyUIBufferAvailable();
    ASSERT_TRUE(node->isNotifyUIBufferAvailable_);
    node->isNotifyUIBufferAvailable_ = false;
    node->isWaitUifirstFirstFrame_ = true;
    node->NotifyUIBufferAvailable();
    ASSERT_FALSE(node->isNotifyUIBufferAvailable_);
    node->isNotifyUIBufferAvailable_ = true;
    node->isWaitUifirstFirstFrame_ = false;
    node->NotifyUIBufferAvailable();
    ASSERT_TRUE(node->isNotifyUIBufferAvailable_);
    sptr<RSIBufferAvailableCallback> callback = new CustomBufferAvailableCallback();
    node->isNotifyUIBufferAvailable_ = false;
    node->isWaitUifirstFirstFrame_ = false;
    node->callbackFromUI_ = callback;
    node->NotifyUIBufferAvailable();
    ASSERT_FALSE(node->IsAppWindow());
    node->nodeType_ = RSSurfaceNodeType::APP_WINDOW_NODE;
    node->isNotifyUIBufferAvailable_ = false;
    node->isWaitUifirstFirstFrame_ = false;
    node->NotifyUIBufferAvailable();
    ASSERT_TRUE(node->IsAppWindow());
}

/**
 * @tc.name: UpdateDirtyIfFrameBufferConsumed
 * @tc.desc: test results of UpdateDirtyIfFrameBufferConsumed
 * @tc.type:FUNC UpdateDirtyIfFrameBufferConsumed
 * @tc.require:
 */
HWTEST_F(RSSurfaceRenderNodeFourTest, UpdateDirtyIfFrameBufferConsumed, TestSize.Level2)
{
    auto rsContext = std::make_shared<RSContext>();
    auto node = std::make_shared<RSSurfaceRenderNode>(id, rsContext);
    ASSERT_FALSE(node->UpdateDirtyIfFrameBufferConsumed());
    node->surfaceHandler_->isCurrentFrameBufferConsumed_ = true;
    ASSERT_TRUE(node->UpdateDirtyIfFrameBufferConsumed());
}

/**
 * @tc.name: QueryIfAllHwcChildrenForceDisabledByFilter
 * @tc.desc: test results of QueryIfAllHwcChildrenForceDisabledByFilter
 * @tc.type:FUNC QueryIfAllHwcChildrenForceDisabledByFilter
 * @tc.require:
 */
HWTEST_F(RSSurfaceRenderNodeFourTest, QueryIfAllHwcChildrenForceDisabledByFilter, TestSize.Level2)
{
    auto rsContext = std::make_shared<RSContext>();
    auto node = std::make_shared<RSSurfaceRenderNode>(id, rsContext);
    ASSERT_TRUE(node->QueryIfAllHwcChildrenForceDisabledByFilter());
    auto child1 = std::make_shared<RSSurfaceRenderNode>(id + 1, rsContext);
    auto child2 = std::make_shared<RSSurfaceRenderNode>(id + 2, rsContext);
    auto child3 = std::make_shared<RSRenderNode>(id + 3);
    child2->nodeType_ = RSSurfaceNodeType::APP_WINDOW_NODE;
    std::vector<std::shared_ptr<RSRenderNode>> children;
    children.push_back(child1);
    children.push_back(child2);
    children.push_back(child3);
    node->fullChildrenList_ = std::make_shared<std::vector<std::shared_ptr<RSRenderNode>>>(children);
    ASSERT_TRUE(node->QueryIfAllHwcChildrenForceDisabledByFilter());
    node->nodeType_ = RSSurfaceNodeType::APP_WINDOW_NODE;
    ASSERT_TRUE(node->QueryIfAllHwcChildrenForceDisabledByFilter());
    auto weakChild4 = std::make_shared<RSSurfaceRenderNode>(id + 4, rsContext);
    auto weakChild5 = std::make_shared<RSSurfaceRenderNode>(id + 5, rsContext);
    child2->childHardwareEnabledNodes_.emplace_back(weakChild4);
    child2->childHardwareEnabledNodes_.emplace_back(weakChild5);
    ASSERT_FALSE(node->QueryIfAllHwcChildrenForceDisabledByFilter());
    weakChild4->isHardwareForcedDisabledByFilter_ = true;
    ASSERT_FALSE(node->QueryIfAllHwcChildrenForceDisabledByFilter());
}

/**
 * @tc.name: GetWindowCornerRadius
 * @tc.desc: test results of GetWindowCornerRadius
 * @tc.type:FUNC GetWindowCornerRadius
 * @tc.require:
 */
HWTEST_F(RSSurfaceRenderNodeFourTest, GetWindowCornerRadius, TestSize.Level2)
{
    auto rsContext = std::make_shared<RSContext>();
    auto node = std::make_shared<RSSurfaceRenderNode>(id, rsContext);
    Vector4f empty;
    ASSERT_EQ(node->GetWindowCornerRadius(), empty);
    auto parent = std::make_shared<RSSurfaceRenderNode>(id + 1);
    node->parent_ = parent;
    ASSERT_FALSE(parent->IsLeashWindow());
    ASSERT_EQ(node->GetWindowCornerRadius(), empty);
    parent->nodeType_ = RSSurfaceNodeType::LEASH_WINDOW_NODE;
    ASSERT_TRUE(parent->IsLeashWindow());
    ASSERT_EQ(node->GetWindowCornerRadius(), empty);
    Vector4f radius = {1.0f, 2.0f, 3.0f, 4.0f};
    parent->GetMutableRenderProperties().SetCornerRadius(radius);
    ASSERT_EQ(node->GetWindowCornerRadius(), radius);
    parent = nullptr;
    node->parent_ = parent;
    node->GetMutableRenderProperties().SetCornerRadius(radius);
    ASSERT_EQ(node->GetWindowCornerRadius(), radius);
}

/**
 * @tc.name: UpdateUIFirstFrameGravity
 * @tc.desc: test results of UpdateUIFirstFrameGravity
 * @tc.type:FUNC UpdateUIFirstFrameGravity
 * @tc.require:
 */
HWTEST_F(RSSurfaceRenderNodeFourTest, UpdateUIFirstFrameGravity, TestSize.Level2)
{
    auto rsContext = std::make_shared<RSContext>();
    auto node = std::make_shared<RSSurfaceRenderNode>(id, rsContext);
    node->UpdateUIFirstFrameGravity();
    node->nodeType_ = RSSurfaceNodeType::LEASH_WINDOW_NODE;
    node->stagingRenderParams_ = std::make_unique<RSSurfaceRenderParams>(id);
    node->UpdateUIFirstFrameGravity();
    ASSERT_TRUE(node->IsLeashWindow());
    std::vector<std::shared_ptr<RSRenderNode>> children;
    auto child1 = std::make_shared<RSSurfaceRenderNode>(id + 1, rsContext);
    children.push_back(child1);
    node->fullChildrenList_ = std::make_shared<std::vector<std::shared_ptr<RSRenderNode>>>(children);
    node->UpdateUIFirstFrameGravity();
    ASSERT_TRUE(node->IsLeashWindow());
    auto child2 = std::make_shared<RSRenderNode>(id + 2, rsContext);
    std::vector<std::shared_ptr<RSRenderNode>> children2;
    children2.push_back(child1);
    children2.push_back(child2);
    node->fullChildrenList_ = std::make_shared<std::vector<std::shared_ptr<RSRenderNode>>>(children2);
    node->UpdateUIFirstFrameGravity();
    ASSERT_TRUE(node->IsLeashWindow());
}

/**
 * @tc.name: SetAbilityState
 * @tc.desc: test results of SetAbilityState
 * @tc.type:FUNC SetAbilityState
 * @tc.require:
 */
HWTEST_F(RSSurfaceRenderNodeFourTest, SetAbilityState, TestSize.Level2)
{
    auto rsContext = std::make_shared<RSContext>();
    auto node = std::make_shared<RSSurfaceRenderNode>(id, rsContext);
    node->SetAbilityState(RSSurfaceNodeAbilityState::FOREGROUND);
    ASSERT_TRUE(node->abilityState_ == RSSurfaceNodeAbilityState::FOREGROUND);
    node->SetAbilityState(RSSurfaceNodeAbilityState::BACKGROUND);
    ASSERT_FALSE(node->abilityState_ == RSSurfaceNodeAbilityState::FOREGROUND);
    node->SetAbilityState(RSSurfaceNodeAbilityState::BACKGROUND);
}

/**
 * @tc.name: GetAbilityState
 * @tc.desc: test results of GetAbilityState
 * @tc.type:FUNC GetAbilityState
 * @tc.require:
 */
HWTEST_F(RSSurfaceRenderNodeFourTest, GetAbilityState, TestSize.Level2)
{
    auto rsContext = std::make_shared<RSContext>();
    auto node = std::make_shared<RSSurfaceRenderNode>(id, rsContext);
    auto abilityState = node->GetAbilityState();
    ASSERT_TRUE(abilityState == RSSurfaceNodeAbilityState::FOREGROUND);
    node->abilityState_ = RSSurfaceNodeAbilityState::BACKGROUND;
    abilityState = node->GetAbilityState();
    ASSERT_FALSE(abilityState == RSSurfaceNodeAbilityState::FOREGROUND);
}

/**
 * @tc.name: QuickPrepareTest001
 * @tc.desc: QuickPrepareTest
 * @tc.type: FUNC
 * @tc.require: issueIB0UQV
 */
HWTEST_F(RSSurfaceRenderNodeFourTest, QuickPrepareTest001, TestSize.Level1)
{
    std::shared_ptr<RSRenderThreadVisitor> visitor = std::make_shared<RSRenderThreadVisitor>();
    ASSERT_NE(visitor, nullptr);
    auto rsContext = std::make_shared<RSContext>();
    auto node = std::make_shared<RSSurfaceRenderNode>(id, rsContext);
    node->childrenBlurBehindWindow_.emplace(id + 1);
    node->QuickPrepare(visitor);
    ASSERT_TRUE(node->oldHasChildrenBlurBehindWindow_);
}

/**
 * @tc.name: ChildrenBlurBehindWindowTest
 * @tc.desc: Test ChildrenBlurBehindWindow and NeedUpdateDrawableBehindWindow
 * @tc.type: FUNC
 * @tc.require: issueIB0UQV
 */
HWTEST_F(RSSurfaceRenderNodeFourTest, ChildrenBlurBehindWindowTest, TestSize.Level1)
{
    auto rsContext = std::make_shared<RSContext>();
    auto node = std::make_shared<RSSurfaceRenderNode>(0, rsContext);
    NodeId idOne = 1;
    NodeId idTwo = 2;
    node->AddChildBlurBehindWindow(idOne);
    ASSERT_TRUE(!node->childrenBlurBehindWindow_.empty());
    ASSERT_TRUE(node->NeedUpdateDrawableBehindWindow());
    ASSERT_TRUE(node->GetMutableRenderProperties().GetNeedDrawBehindWindow());
    ASSERT_TRUE(node->NeedDrawBehindWindow());
    node->RemoveChildBlurBehindWindow(idTwo);
    ASSERT_TRUE(node->NeedDrawBehindWindow());
    node->RemoveChildBlurBehindWindow(idOne);
    ASSERT_FALSE(node->NeedDrawBehindWindow());
}
} // namespace Rosen
} // namespace OHOS