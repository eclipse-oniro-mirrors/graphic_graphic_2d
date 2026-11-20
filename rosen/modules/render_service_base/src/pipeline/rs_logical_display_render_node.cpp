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
#include <unordered_set>

#include "rs_trace.h"

#include "pipeline/rs_context.h"
#include "pipeline/rs_logical_display_render_node.h"
#include "params/rs_logical_display_render_params.h"
#include "pipeline/rs_screen_render_node.h"
#include "pipeline/rs_surface_render_node.h"
#include "property/rs_point_light_manager.h"
#include "visitor/rs_node_visitor.h"

namespace OHOS::Rosen {
namespace {
constexpr size_t MAX_RECORD_SURFACE_ANCESTOR_DEPTH = 256;

struct WindowRecordSurface {
    bool paintable = false;
    NodeId displayId = INVALID_NODEID;
    bool isMainWindow = false;
    DrawableV2::RSRenderNodeDrawableAdapter::SharedPtr drawable;
};

// Returns the real owning display and ancestor-aware paintability; stamped logicalDisplayNodeId_ is
// stale after reparenting. Off-tree, display-less or over-deep chains fail closed.
WindowRecordSurface ResolveWindowRecordSurfaceState(const RSSurfaceRenderNode& surfaceNode)
{
    WindowRecordSurface surface;
    if (!surfaceNode.IsOnTheTree()) {
        return surface;
    }
    surface.paintable = surfaceNode.ShouldPaint();
    auto parent = surfaceNode.GetParent().lock();
    for (size_t depth = 0; parent != nullptr && depth < MAX_RECORD_SURFACE_ANCESTOR_DEPTH; ++depth) {
        surface.paintable = surface.paintable && parent->ShouldPaint();
        if (parent->GetType() == RSRenderNodeType::LOGICAL_DISPLAY_NODE) {
            surface.displayId = parent->GetId();
            return surface;
        }
        parent = parent->GetParent().lock();
    }
    // Fail closed: a display-less or over-deep chain opens neither gate.
    return WindowRecordSurface{};
}

// Cache each configured node and its parent-chain state once for anchor selection and collection.
std::vector<WindowRecordSurface> ResolveWindowRecordSurfaces(
    const RSRenderNodeMap& nodeMap, const std::vector<NodeId>& ids)
{
    std::vector<WindowRecordSurface> surfaces;
    surfaces.reserve(ids.size());
    for (NodeId windowId : ids) {
        auto surfaceNode = nodeMap.GetRenderNode<RSSurfaceRenderNode>(windowId);
        if (surfaceNode == nullptr) {
            continue;
        }
        auto surface = ResolveWindowRecordSurfaceState(*surfaceNode);
        surface.isMainWindow = surfaceNode->IsMainWindowType();
        if (surface.isMainWindow) {
            surface.drawable = surfaceNode->GetRenderDrawable();
        }
        surfaces.emplace_back(std::move(surface));
    }
    return surfaces;
}

// First main window with both drawables owns the recording (existing selection rule). The anchor
// display id comes from the live parent chain, and the anchor's real parent screen must match its
// screen id because the screen relation follows that parent.
std::shared_ptr<RSLogicalDisplayRenderNode> SelectWindowRecordSourceDisplay(
    const RSRenderNodeMap& nodeMap, const std::vector<WindowRecordSurface>& surfaces)
{
    for (const auto& surface : surfaces) {
        if (!surface.isMainWindow || surface.drawable == nullptr || surface.displayId == INVALID_NODEID) {
            continue;
        }
        auto candidate = nodeMap.GetRenderNode<RSLogicalDisplayRenderNode>(surface.displayId);
        if (candidate == nullptr || candidate->GetRenderDrawable() == nullptr) {
            continue;
        }
        auto parentScreen = RSBaseRenderNode::ReinterpretCast<RSScreenRenderNode>(candidate->GetParent().lock());
        if (parentScreen == nullptr || parentScreen->GetScreenId() != candidate->GetScreenId()) {
            continue;
        }
        return candidate;
    }
    return nullptr;
}
} // namespace

bool RSLogicalDisplayRenderNode::IsOnVirtualScreen() const
{
    if (screenId_ == INVALID_SCREEN_ID) {
        return false;
    }
    auto parent = GetParent().lock();
    auto screenNode = RSBaseRenderNode::ReinterpretCast<RSScreenRenderNode>(parent);
    return screenNode != nullptr && screenNode->GetScreenProperty().IsVirtual();
}

void RSLogicalDisplayRenderNode::SetWindowRecordConfig(const RSWindowRecordConfig& config)
{
    if (config.surfaceNodeIds.size() > MAX_WINDOW_RECORD_SURFACE_NUM) {
        RS_LOGE("RSLogicalDisplayRenderNode::%{public}s too many record surfaces:%{public}zu, keep previous",
            __func__, config.surfaceNodeIds.size());
        return;
    }
    // A new config invalidates the previous frame's publication; the next publication reselects.
    recordPublicationDone_ = false;
    windowRecordConfig_ = config;
}

std::unordered_set<NodeId> RSLogicalDisplayRenderNode::BuildEffectiveRecordWhiteListIds() const
{
    if (windowRecordConfig_.surfaceNodeIds.empty()) {
        return {};
    }
    auto context = GetContext().lock();
    if (!context) {
        return {};
    }
    auto& nodeMap = context->GetNodeMap();
    std::unordered_set<NodeId> whiteListIds;
    bool hasMainWindow = false;
    for (NodeId id : windowRecordConfig_.surfaceNodeIds) {
        // Keep both client-supplied id spaces so a leashless child can match by its node id during
        // record-only capture. Zero is invalid in both spaces and must not become an allow-all id.
        if (id == INVALID_NODEID) {
            continue;
        }
        whiteListIds.insert(id);
        if (!hasMainWindow) {
            auto surfaceNode = nodeMap.GetRenderNode<RSSurfaceRenderNode>(id);
            hasMainWindow = surfaceNode && surfaceNode->IsMainWindowType();
        }
    }
    // Only keep the non-zero ids when at least one main window resolves: capture needs it for bbox
    // and source-display resolution, and an empty list makes the caller skip the frame.
    if (!hasMainWindow) {
        return {};
    }
    return whiteListIds;
}

void RSLogicalDisplayRenderNode::ResolveWindowRecordSnapshot(RSLogicalDisplayRenderParams& param)
{
    param.recordSurfaceDrawables_.clear();
    param.recordWhiteListIds_.clear();
    param.recordSourceDisplayDrawable_.reset();
    param.hasPaintableRecordSurface_ = false;
    if (windowRecordConfig_.surfaceNodeIds.empty()) {
        recordPublicationDone_ = false;
        return;
    }
    // A record session is only valid on a virtual MIRROR output. Fail closed here for both the
    // published and unpublished/direct snapshot paths when the mode changed without ending the
    // session; the publication state is kept so a later MIRROR frame still follows publication.
    if (!IsMirrorDisplay()) {
        param.MarkWindowRecordSnapshotSynced();
        return;
    }
    auto context = GetContext().lock();
    if (!context) {
        return;
    }
    // Main thread, per-frame prepare: the only place that may query RSRenderNodeMap and walk the
    // node tree. The render thread later consumes just the snapshots written here.
    auto& nodeMap = context->GetNodeMap();
    param.recordWhiteListIds_ = BuildEffectiveRecordWhiteListIds();
    auto surfaces = ResolveWindowRecordSurfaces(nodeMap, windowRecordConfig_.surfaceNodeIds);
    std::shared_ptr<RSLogicalDisplayRenderNode> sourceDisplay;
    if (recordPublicationDone_) {
        // Consume the relation published before this prepare. A published frame with no anchor
        // stays source-less; an anchor that only becomes resolvable after publication waits for
        // the next publication instead of triggering a same-frame reselect.
        sourceDisplay = GetMirrorSource().lock();
    } else {
        // Direct callers that skipped publication resolve with the same rule once.
        sourceDisplay = SelectWindowRecordSourceDisplay(nodeMap, surfaces);
    }
    auto sourceDrawable = sourceDisplay ? sourceDisplay->GetRenderDrawable() : nullptr;
    if (sourceDrawable == nullptr) {
        // No display can take the recording this frame; keep the snapshot empty so the bbox and
        // paintability gates stay closed.
        param.MarkWindowRecordSnapshotSynced();
        return;
    }
    param.recordSourceDisplayDrawable_ = std::move(sourceDrawable);
    // isSecurityExemption_ is written by the visitor's common UpdateVirtualDisplaySecurityExemption;
    // UpdateRenderParams copies that value and the record path must not recompute it.
    const NodeId anchorDisplayId = sourceDisplay->GetId();
    param.recordSurfaceDrawables_.reserve(surfaces.size());
    // Filter after anchor selection so earlier non-main surfaces still contribute paintability.
    for (auto& surface : surfaces) {
        if (surface.displayId != anchorDisplayId || !surface.paintable) {
            continue;
        }
        param.hasPaintableRecordSurface_ = true;
        if (!surface.isMainWindow || surface.drawable == nullptr) {
            continue;
        }
        param.recordSurfaceDrawables_.emplace_back(std::move(surface.drawable));
    }
    param.MarkWindowRecordSnapshotSynced();
}

std::shared_ptr<RSLogicalDisplayRenderNode> RSLogicalDisplayRenderNode::ResolveWindowRecordSourceDisplay() const
{
    auto context = GetContext().lock();
    if (!context || windowRecordConfig_.surfaceNodeIds.empty()) {
        return nullptr;
    }
    auto& nodeMap = context->GetNodeMap();
    auto surfaces = ResolveWindowRecordSurfaces(nodeMap, windowRecordConfig_.surfaceNodeIds);
    return SelectWindowRecordSourceDisplay(nodeMap, surfaces);
}

void RSLogicalDisplayRenderNode::PublishWindowRecordMirrorSource()
{
    if (!IsWindowRecordActive()) {
        recordPublicationDone_ = false;
        return;
    }
    // Mark completion before resolving so a no-anchor result is a valid published outcome rather
    // than an unpublished state that the later snapshot could retry with a newly valid anchor.
    recordPublicationDone_ = true;
    // Fail closed on an output that cannot hold a mirror relation: SetMirrorSource() no-ops outside
    // MIRROR mode, and an active record must never keep a stale configured source.
    if (!IsMirrorDisplay()) {
        ResetMirrorSource();
        return;
    }
    auto sourceDisplay = ResolveWindowRecordSourceDisplay();
    if (sourceDisplay == nullptr) {
        // Keep the session but drop the record-owned relation: never emit the configured
        // whole-screen mirror while no drawable anchor exists. Recovery is automatic.
        ResetMirrorSource();
        return;
    }
    SetMirrorSource(std::move(sourceDisplay));
}

void RSLogicalDisplayRenderNode::EndWindowRecordSession()
{
    const bool wasActive = IsWindowRecordActive();
    ClearWindowRecordSession();
    if (!wasActive) {
        return;
    }
    // Release both record-owned layers: this display's relation and the parent output screen's
    // relation that early publication mirrored from it. The screen helper keeps its shared-source
    // count balanced and is idempotent when the relation is already empty.
    ResetMirrorSource();
    auto screenNode = RSBaseRenderNode::ReinterpretCast<RSScreenRenderNode>(GetParent().lock());
    if (screenNode != nullptr) {
        screenNode->PublishRecordScreenMirrorSource(nullptr);
    }
}

RSLogicalDisplayRenderNode::RSLogicalDisplayRenderNode(NodeId id,
    const RSDisplayNodeConfig& config, const std::weak_ptr<RSContext>& context, bool isTextureExportNode)
    : RSRenderNode(id, context, isTextureExportNode), screenId_(config.screenId)
{
    RS_TRACE_NAME_FMT("RSLogicalDisplayRenderNode ctor id[%" PRIu64 "], %s", id, config.ToString().c_str());

    RS_LOGI("RSLogicalDisplayRenderNode ctor id[%{public}" PRIu64 "], %{public}s", id, config.ToString().c_str());
}

RSLogicalDisplayRenderNode::~RSLogicalDisplayRenderNode()
{
    RS_TRACE_NAME_FMT("RSLogicalDisplayRenderNode dtor, NodeId[%" PRIu64 "], screenId[%" PRIu64 "]", GetId(),
        screenId_);

    RS_LOGI("RSLogicalDisplayRenderNode dtor, NodeId[%{public}" PRIu64 "], screenId[%{public}" PRIu64 "]", GetId(),
        screenId_);

    RSPointLightManager::ReleaseInstance(GetLogicalDisplayNodeId());
}

void RSLogicalDisplayRenderNode::InitRenderParams()
{
    stagingRenderParams_ = std::make_unique<RSLogicalDisplayRenderParams>(GetId());
    DrawableV2::RSRenderNodeDrawableAdapter::OnGenerate(shared_from_this());
    if (renderDrawable_ == nullptr) {
        HILOG_COMM_ERROR("RSLogicalDisplayRenderNode::InitRenderParams failed");
        return;
    }
}

void RSLogicalDisplayRenderNode::OnSync()
{
    RSRenderNode::OnSync();
}

void RSLogicalDisplayRenderNode::QuickPrepare(const std::shared_ptr<RSNodeVisitor>& visitor,
    bool isParentPrepareInReverseOrder)
{
    if (!visitor) {
        return;
    }
    ApplyModifiers();
    visitor->QuickPrepareLogicalDisplayRenderNode(*this, isParentPrepareInReverseOrder);
    RSPointLightManager::Instance(GetLogicalDisplayNodeId())->PrepareLight();
}

void RSLogicalDisplayRenderNode::Prepare(const std::shared_ptr<RSNodeVisitor>& visitor)
{
    if (!visitor) {
        return;
    }
    ApplyModifiers();
    visitor->PrepareLogicalDisplayRenderNode(*this);
    RSPointLightManager::Instance(GetLogicalDisplayNodeId())->PrepareLight();
}

void RSLogicalDisplayRenderNode::Process(const std::shared_ptr<RSNodeVisitor>& visitor)
{
    if (!visitor) {
        return;
    }
    RSRenderNode::RenderTraceDebug();
    visitor->ProcessLogicalDisplayRenderNode(*this);
}

void RSLogicalDisplayRenderNode::UpdateRenderParams()
{
    auto logicalDisplayRenderParam = static_cast<RSLogicalDisplayRenderParams*>(stagingRenderParams_.get());
    if (logicalDisplayRenderParam == nullptr) {
        RS_LOGE("RSLogicalDisplayRenderNode::UpdateRenderParams logicalDisplayRenderParam is null");
        return;
    }
    logicalDisplayRenderParam->screenId_ = screenId_;
    logicalDisplayRenderParam->SetDisplayContentRect(contentRect_);
    logicalDisplayRenderParam->SetTopSurfaceOpaqueRects(std::move(topSurfaceOpaqueRects_));
    logicalDisplayRenderParam->screenRotation_ = GetScreenRotation();
    logicalDisplayRenderParam->nodeRotation_ = GetRotation();
    logicalDisplayRenderParam->displayMode_ = displayMode_;
    logicalDisplayRenderParam->specialLayerManager_ = specialLayerManager_;
    // Mute is an output property and must reach the render thread even when no mirror source
    // resolves.
    logicalDisplayRenderParam->virtualScreenMuteStatus_ = virtualScreenMuteStatus_;
    auto mirroredNode = GetMirrorSource().lock();
    if (mirroredNode) {
        logicalDisplayRenderParam->mirrorSourceDrawable_ = mirroredNode->GetRenderDrawable();
        logicalDisplayRenderParam->specialLayerManager_ = mirroredNode->GetSpecialLayerMgr();
        logicalDisplayRenderParam->SetMirrorSourceRotation(mirrorSourceRotation_);
    } else {
        logicalDisplayRenderParam->mirrorSourceDrawable_.reset();
    }
    logicalDisplayRenderParam->isSecurityDisplay_ = GetSecurityDisplay();
    logicalDisplayRenderParam->displaySpecialSurfaceChanged_ = displaySpecialSurfaceChanged_;
    logicalDisplayRenderParam->isSecurityExemption_ = isSecurityExemption_;
    logicalDisplayRenderParam->hasSecLayerInVisibleRect_ = hasSecLayerInVisibleRect_;
    logicalDisplayRenderParam->compositeType_ = compositeType_;
    logicalDisplayRenderParam->hasSecLayerInVisibleRectChanged_ = hasSecLayerInVisibleRectChanged_;
    logicalDisplayRenderParam->hasCaptureWindow_ = hasCaptureWindow_;
    logicalDisplayRenderParam->SetHasDstAlphaBlendModeNode(HasDstAlphaBlendModeNode());
    auto screenNode = GetParent().lock();
    auto screenDrawable = screenNode ? screenNode->GetRenderDrawable() : nullptr;
    logicalDisplayRenderParam->SetAncestorScreenDrawable(screenDrawable);
    logicalDisplayRenderParam->fixedWidth_ = fixedWidth_;
    logicalDisplayRenderParam->fixedHeight_ = fixedHeight_;
    logicalDisplayRenderParam->SetWindowRecordConfig(windowRecordConfig_);
    logicalDisplayRenderParam->SetOnVirtualScreen(IsOnVirtualScreen());
    ResolveWindowRecordSnapshot(*logicalDisplayRenderParam);
    auto& boundGeo = GetRenderProperties().GetBoundsGeometry();
    if (boundGeo) {
        logicalDisplayRenderParam->offsetX_ = boundGeo->GetX();
        logicalDisplayRenderParam->offsetY_ = boundGeo->GetY();
    }
    RSRenderNode::UpdateRenderParams();
}

Occlusion::Region RSLogicalDisplayRenderNode::GetTopSurfaceOpaqueRegion() const
{
    Occlusion::Region topSurfaceOpaqueRegion;
    for (const auto& rect : topSurfaceOpaqueRects_) {
        topSurfaceOpaqueRegion.OrSelf(rect);
    }
    return topSurfaceOpaqueRegion;
}

void RSLogicalDisplayRenderNode::SetBootAnimation(bool isBootAnimation)
{
    ROSEN_LOGD("SetBootAnimation:: id:%{public}" PRIu64 "isBootAnimation %{public}d",
        GetId(), isBootAnimation);
    isBootAnimation_ = isBootAnimation;
    if (auto parent = GetParent().lock()) {
        parent->SetBootAnimation(isBootAnimation);
    }
}

bool RSLogicalDisplayRenderNode::GetBootAnimation() const
{
    return isBootAnimation_;
}

void RSLogicalDisplayRenderNode::ClearModifiersByPid(pid_t pid)
{
    RS_LOGI("RSLogicalDisplayRenderNode::ClearModifiersByPid %{public}u", static_cast<uint32_t>(pid));
    for (uint16_t i = 0; i < ModifierNG::MODIFIER_TYPE_COUNT; i++) {
        ModifierNG::RSModifierType type = static_cast<ModifierNG::RSModifierType>(i);
        const ModifierNGContainer& slot = GetModifiersNG(type);
        if (slot.empty()) {
            continue;
        }
        for (auto& modifier : slot) {
            if (modifier && (ExtractPid(modifier->GetId()) == pid)) {
                RemoveModifier(type, modifier->GetId());
            }
        }
    }
}

void RSLogicalDisplayRenderNode::SetIsOnTheTree(bool flag, NodeId instanceRootNodeId, NodeId firstLevelNodeId,
    NodeId uifirstRootNodeId, NodeId screenNodeId, NodeId logicalDisplayNodeId)
{
    RSRenderNode::SetIsOnTheTree(flag, instanceRootNodeId, firstLevelNodeId, uifirstRootNodeId, screenNodeId, GetId());
}

void RSLogicalDisplayRenderNode::SetWindowContainer(std::shared_ptr<RSBaseRenderNode> container)
{
    if (auto oldContainer = std::exchange(windowContainer_, container)) {
        if (container) {
            RS_LOGD_IF(DEBUG_NODE, "RSLogicalDisplayRenderNode::SetWindowContainer oldContainer: %{public}" PRIu64
                ", newContainer: %{public}" PRIu64, oldContainer->GetId(), container->GetId());
        } else {
            RS_LOGD_IF(DEBUG_NODE, "RSLogicalDisplayRenderNode::SetWindowContainer oldContainer: %{public}" PRIu64,
                oldContainer->GetId());
        }
    }
}

std::shared_ptr<RSBaseRenderNode> RSLogicalDisplayRenderNode::GetWindowContainer() const
{
    return windowContainer_;
}

bool RSLogicalDisplayRenderNode::IsOnlyHDRAnimation()
{
    const auto& modifiers = GetModifiersNG(ModifierNG::RSModifierType::HDR_BRIGHTNESS);
    if (modifiers.empty()) {
        return false;
    }
    if (!GetAnimationManager()) {
        return false;
    }
    const auto& animationsMap = GetAnimationManager()->GetAnimations();
    for (const auto& modifier : modifiers) {
        if (!modifier) {
            continue;
        }
        auto hdrBrightnessFactor = modifier->GetProperty(ModifierNG::RSPropertyType::HDR_BRIGHTNESS_FACTOR);
        if (!hdrBrightnessFactor) {
            continue;
        }
        PropertyId id = hdrBrightnessFactor->GetId();
        for (const auto& [_, animation] : animationsMap) {
            if (!animation) {
                continue;
            }
            if (animation->GetPropertyId() != id) {
                return false;
            }
        }
        RS_TRACE_NAME_FMT("RSLogicalDisplayRenderNode::IsOnlyHDRAnimation return true");
        return true;
    }
    return false;
}

void RSLogicalDisplayRenderNode::SetScreenSwitchFinishTask(ScreenSwitchFinishTask task)
{
    screenSwitchFinishTask_ = task;
}

void RSLogicalDisplayRenderNode::NotifyScreenSwitchFinish(ScreenId id)
{
    if (screenSwitchFinishTask_ && id != INVALID_SCREEN_ID) {
        screenSwitchFinishTask_(id);
        ROSEN_LOGI("RSLogicalDisplayRenderNode::NotifyScreenSwitchFinish ScreenId: %{public}" PRIu64, id);
        RS_TRACE_NAME_FMT("NotifyScreenSwitchFinish");
    }
}

ScreenRotation RSLogicalDisplayRenderNode::GetRotation() const
{
    auto& boundsGeoPtr = (GetRenderProperties().GetBoundsGeometry());
    if (boundsGeoPtr == nullptr) {
        return ScreenRotation::ROTATION_0;
    }
    // -90.0f: convert rotation degree to 4 enum values
    return static_cast<ScreenRotation>(static_cast<int32_t>(std::roundf(boundsGeoPtr->GetRotation() / -90.0f)) % 4);
}

bool RSLogicalDisplayRenderNode::IsRotationChanged() const
{
    auto& boundsGeoPtr = (GetRenderProperties().GetBoundsGeometry());
    if (boundsGeoPtr == nullptr) {
        return false;
    }
    // boundsGeoPtr->IsNeedClientCompose() return false if rotation degree is times of 90
    // which means rotation is end.
    bool isRotationEnd = !boundsGeoPtr->IsNeedClientCompose();
    return !(ROSEN_EQ(boundsGeoPtr->GetRotation(), lastRotation_) && isRotationEnd);
}

void RSLogicalDisplayRenderNode::UpdateRotation()
{
#ifdef RS_ENABLE_GPU
    auto displayParams = static_cast<RSLogicalDisplayRenderParams*>(stagingRenderParams_.get());
    if (displayParams == nullptr) {
        RS_LOGE("%{public}s displayParams is nullptr", __func__);
        return;
    }
    AddToPendingSyncList();

    auto& boundsGeoPtr = (GetRenderProperties().GetBoundsGeometry());
    if (boundsGeoPtr == nullptr) {
        return;
    }
    lastRotationChanged_ = IsRotationChanged();
    lastRotation_ = boundsGeoPtr->GetRotation();
    preRotationStatus_ = curRotationStatus_;
    curRotationStatus_ = IsRotationChanged();
    displayParams->SetRotationChanged(curRotationStatus_);
#endif
}

bool RSLogicalDisplayRenderNode::IsLastRotationChanged() const
{
    return lastRotationChanged_;
}

bool RSLogicalDisplayRenderNode::GetPreRotationStatus() const
{
    return preRotationStatus_;
}

bool RSLogicalDisplayRenderNode::GetCurRotationStatus() const
{
    return curRotationStatus_;
}

void RSLogicalDisplayRenderNode::UpdateOffscreenRenderParams(bool needOffscreen)
{
    auto displayParams = static_cast<RSLogicalDisplayRenderParams*>(stagingRenderParams_.get());
    if (displayParams == nullptr) {
        RS_LOGE("RSLogicalDisplayRenderNode::UpdateOffscreenRenderParams displayParams is null");
        return;
    }
    displayParams->SetNeedOffscreen(needOffscreen);
}

void RSLogicalDisplayRenderNode::SetSecurityDisplay(bool isSecurityDisplay)
{
    isSecurityDisplay_ = isSecurityDisplay;
}

bool RSLogicalDisplayRenderNode::GetSecurityDisplay() const
{
    return isSecurityDisplay_;
}

void RSLogicalDisplayRenderNode::SetMirrorSource(SharedPtr node)
{
    if (displayMode_ != DisplayMode::MIRROR || node == nullptr) {
        return;
    }
    mirrorSource_ = node;
}

void RSLogicalDisplayRenderNode::ResetMirrorSource()
{
    mirrorSource_.reset();
}

RSLogicalDisplayRenderNode::WeakPtr RSLogicalDisplayRenderNode::GetMirrorSource() const
{
    return mirrorSource_;
}

void RSLogicalDisplayRenderNode::SetDisplayMode(DisplayMode displayMode)
{
    displayMode_ = displayMode;

    RS_TRACE_NAME_FMT("RSLogicalDisplayRenderNode::%s, nodeId[%" PRIu64 "], displayMode[%d]", __func__, GetId(),
        static_cast<int>(displayMode_));

    RS_LOGI("RSLogicalDisplayRenderNode::%{public}s, nodeId[%{public}" PRIu64 "], displayMode[%{public}d]", __func__,
        GetId(), static_cast<int>(displayMode_));
}

DisplayMode RSLogicalDisplayRenderNode::GetDisplayMode() const
{
    return displayMode_;
}

bool RSLogicalDisplayRenderNode::IsMirrorDisplay() const
{
    return displayMode_ == DisplayMode::MIRROR;
}

void RSLogicalDisplayRenderNode::SetVirtualScreenMuteStatus(bool virtualScreenMuteStatus)
{
    virtualScreenMuteStatus_ = virtualScreenMuteStatus;
}

bool RSLogicalDisplayRenderNode::GetVirtualScreenMuteStatus() const
{
    return virtualScreenMuteStatus_;
}

void RSLogicalDisplayRenderNode::SetDisplaySpecialSurfaceChanged(bool displaySpecialSurfaceChanged)
{
    displaySpecialSurfaceChanged_ = displaySpecialSurfaceChanged;
}

RSSpecialLayerManager& RSLogicalDisplayRenderNode::GetMultableSpecialLayerMgr()
{
    return specialLayerManager_;
}

const RSSpecialLayerManager& RSLogicalDisplayRenderNode::GetSpecialLayerMgr() const
{
    return specialLayerManager_;
}

void RSLogicalDisplayRenderNode::AddSecurityLayer(NodeId id)
{
    securityLayerList_.emplace_back(id);
}

void RSLogicalDisplayRenderNode::ClearSecurityLayerList()
{
    securityLayerList_.clear();
}

const std::vector<NodeId>& RSLogicalDisplayRenderNode::GetSecurityLayerList()
{
    return securityLayerList_;
}

void RSLogicalDisplayRenderNode::AddSecurityVisibleLayer(NodeId id)
{
    securityVisibleLayerList_.emplace_back(id);
}

void RSLogicalDisplayRenderNode::ClearSecurityVisibleLayerList()
{
    securityVisibleLayerList_.clear();
}

const std::vector<NodeId>& RSLogicalDisplayRenderNode::GetSecurityVisibleLayerList()
{
    return securityVisibleLayerList_;
}

void RSLogicalDisplayRenderNode::SetSecurityExemption(bool isSecurityExemption)
{
    isSecurityExemption_ = isSecurityExemption;
}

bool RSLogicalDisplayRenderNode::GetSecurityExemption() const
{
    return isSecurityExemption_;
}

void RSLogicalDisplayRenderNode::SetHasSecLayerInVisibleRect(bool hasSecLayer)
{
    bool lastHasSecLayerInVisibleRect = hasSecLayerInVisibleRect_;
    hasSecLayerInVisibleRect_ = hasSecLayer;
    hasSecLayerInVisibleRectChanged_ =
        lastHasSecLayerInVisibleRect != hasSecLayerInVisibleRect_;
}

CompositeType RSLogicalDisplayRenderNode::GetCompositeType() const
{
    return compositeType_;
}

void RSLogicalDisplayRenderNode::SetCompositeType(CompositeType type)
{
    compositeType_ = type;
}

void RSLogicalDisplayRenderNode::UpdateFixedSize()
{
    auto& boundGeo = GetRenderProperties().GetBoundsGeometry();
    fixedWidth_ = boundGeo->GetWidth();
    fixedHeight_ = boundGeo->GetHeight();
    auto rotation = GetRotation();
    if (rotation == ScreenRotation::ROTATION_90 ||
        rotation == ScreenRotation::ROTATION_270) {
        std::swap(fixedWidth_, fixedHeight_);
    }
}

float RSLogicalDisplayRenderNode::GetFixedWidth() const
{
    return fixedWidth_;
}

float RSLogicalDisplayRenderNode::GetFixedHeight() const
{
    return fixedHeight_;
}

bool RSLogicalDisplayRenderNode::HasNonlinearBlendMode(int blendMode)
{
    return IsInBlendModeGroup(blendMode, NonlinearBlendModes);
}

bool RSLogicalDisplayRenderNode::HasChildBlendMode(int blendMode)
{
    return IsInBlendModeGroup(blendMode, ChildBlendModes);
}

bool RSLogicalDisplayRenderNode::HasEmptyBlendMode(int blendMode)
{
    return IsInBlendModeGroup(blendMode, EmptyBlendModes);
}

bool RSLogicalDisplayRenderNode::HasParentBlendMode(int blendMode)
{
    return IsInBlendModeGroup(blendMode, ParentBlendModes);
}

void RSLogicalDisplayRenderNode::IncreaseBlendModeNode(NodeId id)
{
    blendModeNodeMap_[id]++;
}

void RSLogicalDisplayRenderNode::RemoveBlendModeNode(NodeId id)
{
    auto it = blendModeNodeMap_.find(id);
    bool needErase = it != blendModeNodeMap_.end();
    // directly remove id in map
    if (needErase) {
        blendModeNodeMap_.erase(it);
    }
}

bool RSLogicalDisplayRenderNode::HasDstAlphaBlendModeNode() const
{
    return !blendModeNodeMap_.empty();
}

bool RSLogicalDisplayRenderNode::CheckAncestorChildBlendMode(
    int blendMode, int currentBlendMode, bool IsEmptyBlendMode, bool IsParentBlendMode)
{
    if (blendMode == static_cast<int>(RSColorBlendMode::NONE)) {
        bool isEmpty = HasEmptyBlendMode(currentBlendMode) || IsEmptyBlendMode;
        if (isEmpty) {
            return true;
        }
    }
    bool isParent = HasParentBlendMode(currentBlendMode) || IsParentBlendMode;
    if (!isParent) {
        return false;
    }
    return HasChildBlendMode(blendMode);
}

} // namespace OHOS::Rosen
