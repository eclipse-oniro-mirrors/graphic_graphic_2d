/*
 * Copyright (c) 2025-2026 Huawei Device Co., Ltd.
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

#include "rs_drm_util.h"
#include <algorithm>
#include <cmath>
#include <parameters.h>
#include <string>
#include "common/rs_background_thread.h"
#include "common/rs_obj_abs_geometry.h"
#include "common/rs_optional_trace.h"
#include "graphic_feature_param_manager.h"
#include "pipeline/main_thread/rs_main_thread.h"
#include "pipeline/render_thread/rs_uni_render_thread.h"
#include "pipeline/render_thread/rs_uni_render_util.h"
#include "pipeline/rs_effect_render_node.h"
#include "platform/common/rs_log.h"
#include "rs_render_composer_manager.h"
#include "screen_manager/screen_types.h"

namespace OHOS {
namespace Rosen {
constexpr const int BLUR_MIN_ALPHA = 100;

namespace {
constexpr float NORMALIZED_MAX = 1.0f;
constexpr float NORMALIZED_MIN = 0.0f;

// Temporary log of the cross node conversion, removed after the cross screen issue is located.
std::string DebugMatrix(const Drawing::Matrix& matrix)
{
    Drawing::Matrix::Buffer buffer;
    matrix.GetAll(buffer);
    std::string result;
    for (const Drawing::Matrix::Index index : { Drawing::Matrix::SCALE_X, Drawing::Matrix::SKEW_X,
        Drawing::Matrix::TRANS_X, Drawing::Matrix::SKEW_Y, Drawing::Matrix::SCALE_Y, Drawing::Matrix::TRANS_Y }) {
        result += std::to_string(buffer[index]) + " ";
    }
    return result;
}

// Absolute matrix of a node in the frame of the display owning it. The cached absolute matrix of a cross node is
// rewritten by every prepare, including the prepare under the parent of the clone on another display, so it is rebuilt
// from the matrix relative to the real parent and the cached matrix of that parent, which no such prepare touches.
Drawing::Matrix CalcOwnDisplayAbsMatrix(const RSSurfaceRenderNode& node)
{
    auto geo = node.GetRenderProperties().GetBoundsGeometry();
    Drawing::Matrix absMatrix = geo ? geo->GetMatrix() : Drawing::Matrix();
    if (auto parent = node.GetParent().lock()) {
        auto parentGeo = parent->GetRenderProperties().GetBoundsGeometry();
        absMatrix.PostConcat(parentGeo ? parentGeo->GetAbsMatrix() : Drawing::Matrix());
    }
    return absMatrix;
}

// Absolute matrix of the source node under the parent of the clone, in the frame of the display composing the clone.
Drawing::Matrix CalcCloneDisplayAbsMatrix(const RSSurfaceRenderNode& sourceNode, const RSSurfaceRenderNode& cloneNode,
    const RSScreenRenderNode& screenNode)
{
    auto geo = sourceNode.GetRenderProperties().GetBoundsGeometry();
    Drawing::Matrix absMatrix = geo ? geo->GetMatrix() : Drawing::Matrix();
    if (sourceNode.GetGlobalPositionEnabled()) {
        const auto& screenProperty = screenNode.GetScreenProperty();
        absMatrix.PostTranslate(-screenProperty.GetOffsetX(), -screenProperty.GetOffsetY());
    }
    if (auto parent = cloneNode.GetParent().lock()) {
        auto parentGeo = parent->GetRenderProperties().GetBoundsGeometry();
        absMatrix.PostConcat(parentGeo ? parentGeo->GetAbsMatrix() : Drawing::Matrix());
    }
    return absMatrix;
}

// Map a point of the destination rect, expressed in normalized coordinates of the whole displayed rect, onto the
// normalized coordinates of the source rect. The hardware applies transformType to the source image before scaling it
// into the destination rect, so the cropped part of the destination rect has to be mapped in the same way.
// transformType follows RSBaseRenderUtil::RotateEnumToInt, where GRAPHIC_ROTATE_270 is produced by the layer matrix
// [0 1; -1 0]: the source x axis points up on the screen, so the left edge of the source is at the bottom of the
// destination rect. GRAPHIC_ROTATE_90 is the opposite rotation.
void MapNormalizedPointToSrc(float dstU, float dstV, GraphicTransformType transformType, float& srcU, float& srcV)
{
    switch (RSBaseRenderUtil::GetRotateTransform(transformType)) {
        case GraphicTransformType::GRAPHIC_ROTATE_90: {
            srcU = dstV;
            srcV = NORMALIZED_MAX - dstU;
            break;
        }
        case GraphicTransformType::GRAPHIC_ROTATE_180: {
            srcU = NORMALIZED_MAX - dstU;
            srcV = NORMALIZED_MAX - dstV;
            break;
        }
        case GraphicTransformType::GRAPHIC_ROTATE_270: {
            srcU = NORMALIZED_MAX - dstV;
            srcV = dstU;
            break;
        }
        default: {
            srcU = dstU;
            srcV = dstV;
            break;
        }
    }
    const auto flip = RSBaseRenderUtil::GetFlipTransform(transformType);
    if (flip == GraphicTransformType::GRAPHIC_FLIP_H) {
        srcU = NORMALIZED_MAX - srcU;
    } else if (flip == GraphicTransformType::GRAPHIC_FLIP_V) {
        srcV = NORMALIZED_MAX - srcV;
    }
}

// Map the cropped part of the destination rect, expressed in normalized coordinates, onto the bounding rect of the
// source rect. The bounding rect is used so that the mapping does not depend on the direction of the rotation.
void MapDstRectToSrcBounds(float left, float top, float right, float bottom, GraphicTransformType transformType,
    float& minU, float& maxU, float& minV, float& maxV)
{
    minU = NORMALIZED_MAX;
    maxU = NORMALIZED_MIN;
    minV = NORMALIZED_MAX;
    maxV = NORMALIZED_MIN;
    for (const float dstU : { left, right }) {
        for (const float dstV : { top, bottom }) {
            float srcU = NORMALIZED_MIN;
            float srcV = NORMALIZED_MIN;
            MapNormalizedPointToSrc(dstU, dstV, transformType, srcU, srcV);
            minU = std::min(minU, srcU);
            maxU = std::max(maxU, srcU);
            minV = std::min(minV, srcV);
            maxV = std::max(maxV, srcV);
        }
    }
}

// Map the destination rect with the outward rounding used for the draw areas of the nodes.
GraphicIRect MapCrossNodeDstRect(const Drawing::Matrix& matrix, const GraphicIRect& dstRect)
{
    const RectI mapped = RSObjAbsGeometry::MapRect(RectF(static_cast<float>(dstRect.x),
        static_cast<float>(dstRect.y), static_cast<float>(dstRect.w), static_cast<float>(dstRect.h)), matrix);
    return { mapped.left_, mapped.top_, mapped.width_, mapped.height_ };
}

// Same truncation as the layer size handed to the composer by RSUniRenderProcessor::GetLayerInfo.
GraphicIRect ToGraphicIRect(const Drawing::Rect& rect)
{
    return { static_cast<int32_t>(rect.GetLeft()), static_cast<int32_t>(rect.GetTop()),
        static_cast<int32_t>(rect.GetWidth()), static_cast<int32_t>(rect.GetHeight()) };
}
} // namespace

void RSDrmUtil::ClearDrmNodes()
{
    drmNodes_.clear();
}

bool RSDrmUtil::IsDrmNode(const RSRenderNode& node)
{
    const auto it = drmNodes_.find(node.GetFirstLevelNodeId());
    if (it == drmNodes_.end()) {
        return false;
    }
    return std::any_of(it->second.begin(), it->second.end(),
        [&node](const std::shared_ptr<RSSurfaceRenderNode>& drmNode) {
            return drmNode != nullptr && drmNode->GetId() == node.GetId();
        });
}

void RSDrmUtil::CollectDrmNodes(const std::shared_ptr<RSSurfaceRenderNode>& surfaceNode)
{
    auto firstLevelNode = RSBaseRenderNode::ReinterpretCast<RSSurfaceRenderNode>(
        surfaceNode->GetFirstLevelNode());
    if (firstLevelNode && firstLevelNode->IsOnTheTree()) {
        drmNodes_[firstLevelNode->GetId()].push_back(surfaceNode);
    }
}

void RSDrmUtil::AddDrmCloneCrossNode(const std::shared_ptr<RSSurfaceRenderNode>& surfaceNode,
    DrawablesVec& hardwareEnabledDrawables)
{
    auto sourceNode = surfaceNode->GetSourceCrossNode().lock();
    auto sourceSurface = sourceNode == nullptr ? nullptr : sourceNode->ReinterpretCastTo<RSSurfaceRenderNode>();
    auto leashWindowNode = sourceSurface == nullptr ? nullptr :
        RSBaseRenderNode::ReinterpretCast<RSSurfaceRenderNode>(sourceSurface->GetFirstLevelNode());
    if (leashWindowNode && leashWindowNode->GetSpecialLayerMgr().Find(SpecialLayerType::HAS_PROTECTED) &&
        surfaceNode->GetScreenNodeId() != INVALID_NODEID) {
        if (const auto it = drmNodes_.find(leashWindowNode->GetId()); it != drmNodes_.end()) {
            for (const auto& node : it->second) {
                if (node->IsOnTheTree()) {
                    hardwareEnabledDrawables.emplace_back(surfaceNode->GetScreenNodeId(),
                        node->GetLogicalDisplayNodeId(), node->GetRenderDrawable());
                }
            }
        }
    }
}

bool RSDrmUtil::CalcCrossNodeLayerConversion(const RSSurfaceRenderNode& sourceNode,
    const RSSurfaceRenderNode& cloneNode, const RSScreenRenderNode& screenNode, Drawing::Matrix& conversion)
{
    if (drmNodes_.find(sourceNode.GetFirstLevelNodeId()) == drmNodes_.end()) {
        return false;
    }
    // The layer matrix is accumulated along the real parent chain, so the conversion starts from the frame of the
    // display owning the source node rather than from its cached absolute matrix.
    const Drawing::Matrix ownMatrix = CalcOwnDisplayAbsMatrix(sourceNode);
    if (!ownMatrix.Invert(conversion)) {
        return false;
    }
    const Drawing::Matrix cloneMatrix = CalcCloneDisplayAbsMatrix(sourceNode, cloneNode, screenNode);
    conversion.PostConcat(cloneMatrix);
    // Temporary log of the cross node conversion, removed after the cross screen issue is located.
    const auto& screenProperty = screenNode.GetScreenProperty();
    RS_LOGW("[RSCrossNode] calc source:%{public}" PRIu64 " first:%{public}" PRIu64 " clone:%{public}" PRIu64
        " screen:%{public}" PRIu64 " offset:[%{public}d,%{public}d] own:[%{public}s] cloneAbs:[%{public}s]"
        " conversion:[%{public}s]", sourceNode.GetId(), sourceNode.GetFirstLevelNodeId(), cloneNode.GetId(),
        screenNode.GetId(), screenProperty.GetOffsetX(), screenProperty.GetOffsetY(),
        DebugMatrix(ownMatrix).c_str(), DebugMatrix(cloneMatrix).c_str(), DebugMatrix(conversion).c_str());
    return true;
}

void RSDrmUtil::UpdateDrmCrossNodeConversion(const RSSurfaceRenderNode& crossNode, NodeId screenNodeId,
    const Drawing::Matrix& conversion)
{
    // The drm nodes are collected before the prepare, while the layer conversion of the cross node is calculated
    // during the cross node prepare of this frame. Delivering it here keeps it in the same frame as the dst rect of the
    // drm layers. Delivering it before the prepare uses the conversion of the last frame, which is missing on the
    // first cross screen frame and moves the drm layers off the screen for one frame.
    const auto it = drmNodes_.find(crossNode.GetFirstLevelNodeId());
    if (it == drmNodes_.end()) {
        // Temporary log of the cross node conversion, removed after the cross screen issue is located.
        RS_LOGW("[RSCrossNode] deliver first:%{public}" PRIu64 " screen:%{public}" PRIu64 " drmCount:0",
            crossNode.GetFirstLevelNodeId(), screenNodeId);
        return;
    }
    // Temporary log of the cross node conversion, removed after the cross screen issue is located.
    RS_LOGW("[RSCrossNode] deliver first:%{public}" PRIu64 " screen:%{public}" PRIu64 " drmCount:%{public}d"
        " conversion:[%{public}s]", crossNode.GetFirstLevelNodeId(), screenNodeId,
        static_cast<int32_t>(it->second.size()), DebugMatrix(conversion).c_str());
    for (const auto& node : it->second) {
        if (node == nullptr || !node->IsOnTheTree()) {
            continue;
        }
        // The drm nodes are prepared under the cross node before this call, so their params are already filled.
        // Record the matrix on the params directly, otherwise it would only reach the render thread a frame later.
        node->UpdateCrossNodeLayerConversionMatrices(screenNodeId, conversion);
        auto nodeParams = static_cast<RSSurfaceRenderParams*>(node->GetStagingRenderParams().get());
        if (nodeParams != nullptr) {
            nodeParams->SetCrossNodeLayerConversionMatrix(screenNodeId, conversion);
        }
        node->AddToPendingSyncList();
    }
}

void RSDrmUtil::RecordDstRectDisplay(RSSurfaceRenderNode& node,
    const std::shared_ptr<RSScreenRenderNode>& screenNode)
{
    // The layers of the drm nodes are the only ones converted, so only they need the display whose frame their dst
    // rect is in. Every prepare rebuilds the dst rect in the frame of the display being prepared and adds the offset of
    // that display to it, so the display is recorded on every prepare, not only on the prepare of the clone: the layer
    // is composed with the rect of the last prepare of the node, which is usually the one of the display owning it. The
    // other nodes record none, which keeps the record of a node that is no longer composed on another display from
    // outliving the composition.
    if (screenNode == nullptr || !IsDrmNode(node)) {
        node.SetDstRectDisplay(INVALID_NODEID);
        return;
    }
    // The offset of that display is recorded where it is added to the rect, so a prepare that skips the global position
    // update keeps a zero offset here.
    node.SetDstRectDisplay(screenNode->GetId());
    const auto& screenProperty = screenNode->GetScreenProperty();
    // Temporary log of the cross node conversion, removed after the cross screen issue is located.
    RS_LOGW("[RSCrossNode] recordDstDisplay node:%{public}" PRIu64 " screen:%{public}" PRIu64
        " dstDisplay:%{public}" PRIu64 " screenOffset:[%{public}d,%{public}d]", node.GetId(), screenNode->GetId(),
        node.GetDstRectDisplayNodeId(), screenProperty.GetOffsetX(), screenProperty.GetOffsetY());
}

bool RSDrmUtil::ConvertCrossNodeLayerInfo(const RSSurfaceRenderParams& params, NodeId screenNodeId,
    RSLayerInfo& layerInfo)
{
    const auto& conversionMatrices = params.GetCrossNodeLayerConversionMatrices();
    const auto conversion = conversionMatrices.find(screenNodeId);
    if (conversion == conversionMatrices.end()) {
        return false;
    }
    // When the rect is restored into the local frame of this screen, only the matrix still has to be converted.
    const bool dstInThisFrame = RestoreCrossNodeDstRect(params, screenNodeId, layerInfo);
    ApplyCrossNodeLayerConversion(conversion->second, layerInfo, !dstInThisFrame);
    return true;
}

bool RSDrmUtil::RestoreCrossNodeDstRect(const RSSurfaceRenderParams& params, NodeId screenNodeId,
    RSLayerInfo& layerInfo)
{
    // The dstRect is built in the frame of the display the node was last prepared on and the offset of that display is
    // added to it, while the conversions start from the frame of the display owning the node. The rect is moved back
    // by the offset of the display that built it first: it is already in this frame when this screen built it, and it
    // is in the frame of the owning display otherwise, or moved back to it with the inverse of the conversion
    // recorded for that display.
    const NodeId dstDisplayId = params.GetLayerDstDisplayNodeId();
    // Temporary log of the cross node conversion, removed after the cross screen issue is located.
    RS_LOGW("[RSCrossNode] restore node:%{public}" PRIu64 " screen:%{public}" PRIu64 " dstDisplay:%{public}" PRIu64
        " offset:[%{public}d,%{public}d] dstIn:[%{public}d,%{public}d,%{public}d,%{public}d]", params.GetId(),
        screenNodeId, dstDisplayId, params.GetLayerDstDisplayOffsetX(), params.GetLayerDstDisplayOffsetY(),
        layerInfo.dstRect.x, layerInfo.dstRect.y, layerInfo.dstRect.w, layerInfo.dstRect.h);
    if (dstDisplayId == INVALID_NODEID) {
        return false;
    }
    layerInfo.dstRect.x -= params.GetLayerDstDisplayOffsetX();
    layerInfo.dstRect.y -= params.GetLayerDstDisplayOffsetY();
    if (dstDisplayId == screenNodeId) {
        // Temporary log of the cross node conversion, removed after the cross screen issue is located.
        RS_LOGW("[RSCrossNode] restore same screen dstOut:[%{public}d,%{public}d,%{public}d,%{public}d]",
            layerInfo.dstRect.x, layerInfo.dstRect.y, layerInfo.dstRect.w, layerInfo.dstRect.h);
        return true;
    }
    const auto& conversionMatrices = params.GetCrossNodeLayerConversionMatrices();
    const auto conversion = conversionMatrices.find(dstDisplayId);
    Drawing::Matrix inverse;
    if (conversion == conversionMatrices.end() || !conversion->second.Invert(inverse)) {
        // No conversion ends on the display that built the rect, so the node is owned by that display and the rect is
        // already in the frame the conversions start from.
        // Temporary log of the cross node conversion, removed after the cross screen issue is located.
        RS_LOGW("[RSCrossNode] restore own display dstOut:[%{public}d,%{public}d,%{public}d,%{public}d]",
            layerInfo.dstRect.x, layerInfo.dstRect.y, layerInfo.dstRect.w, layerInfo.dstRect.h);
        return false;
    }
    layerInfo.dstRect = MapCrossNodeDstRect(inverse, layerInfo.dstRect);
    // Temporary log of the cross node conversion, removed after the cross screen issue is located.
    RS_LOGW("[RSCrossNode] restore map dstOut:[%{public}d,%{public}d,%{public}d,%{public}d] inverse:[%{public}s]",
        layerInfo.dstRect.x, layerInfo.dstRect.y, layerInfo.dstRect.w, layerInfo.dstRect.h,
        DebugMatrix(inverse).c_str());
    return false;
}

void RSDrmUtil::ApplyCrossNodeLayerConversion(const Drawing::Matrix& conversion, RSLayerInfo& layerInfo,
    bool convertDstRect)
{
    if (convertDstRect) {
        layerInfo.dstRect = MapCrossNodeDstRect(conversion, layerInfo.dstRect);
    }
    layerInfo.matrix.PostConcat(conversion);
    // The conversion may change the rotation carried by the matrix, so transformType is recalculated to stay
    // consistent with it, following the same pattern as DRMCreateLayer.
    layerInfo.transformType = RSBaseRenderUtil::RotateEnumToInt(
        RSUniRenderUtil::GetRotationFromMatrix(layerInfo.matrix) % RS_ROTATION_360,
        RSBaseRenderUtil::GetFlipTransform(layerInfo.transformType));
    RS_OPTIONAL_TRACE_NAME_FMT("cross node layer convert, dstRect:[%d, %d, %d, %d] transformType:%d",
        layerInfo.dstRect.x, layerInfo.dstRect.y, layerInfo.dstRect.w, layerInfo.dstRect.h,
        static_cast<int32_t>(layerInfo.transformType));
}

void RSDrmUtil::CropCrossNodeLayerInfo(const Drawing::Rect& composedDstRect, const Drawing::Rect& screenRect,
    RSLayerInfo& layerInfo)
{
    Drawing::Rect clippedRect = composedDstRect;
    if (!clippedRect.Intersect(screenRect)) {
        return; // The layer is out of the screen, the destination rect is not clipped either.
    }
    const GraphicIRect composed = ToGraphicIRect(composedDstRect);
    const GraphicIRect cropped = ToGraphicIRect(clippedRect);
    const auto srcRect = layerInfo.srcRect;
    if ((cropped.x == composed.x && cropped.y == composed.y && cropped.w == composed.w && cropped.h == composed.h) ||
        composed.w <= 0 || composed.h <= 0 || srcRect.w <= 0 || srcRect.h <= 0) {
        return;
    }
    layerInfo.dstRect = cropped;
    float minU = NORMALIZED_MIN;
    float maxU = NORMALIZED_MIN;
    float minV = NORMALIZED_MIN;
    float maxV = NORMALIZED_MIN;
    MapDstRectToSrcBounds(static_cast<float>(cropped.x - composed.x) / composed.w,
        static_cast<float>(cropped.y - composed.y) / composed.h,
        static_cast<float>(cropped.x + cropped.w - composed.x) / composed.w,
        static_cast<float>(cropped.y + cropped.h - composed.y) / composed.h, layerInfo.transformType,
        minU, maxU, minV, maxV);
    const int32_t srcLeft = srcRect.x + static_cast<int32_t>(std::floor(minU * static_cast<float>(srcRect.w)));
    const int32_t srcTop = srcRect.y + static_cast<int32_t>(std::floor(minV * static_cast<float>(srcRect.h)));
    const int32_t srcRight = std::clamp(srcLeft + static_cast<int32_t>(std::ceil((maxU - minU) *
        static_cast<float>(srcRect.w))), srcRect.x, srcRect.x + srcRect.w);
    const int32_t srcBottom = std::clamp(srcTop + static_cast<int32_t>(std::ceil((maxV - minV) *
        static_cast<float>(srcRect.h))), srcRect.y, srcRect.y + srcRect.h);
    const int32_t leftInSrc = std::clamp(srcLeft, srcRect.x, srcRect.x + srcRect.w);
    const int32_t topInSrc = std::clamp(srcTop, srcRect.y, srcRect.y + srcRect.h);
    layerInfo.srcRect = { leftInSrc, topInSrc, srcRight - leftInSrc, srcBottom - topInSrc };
    RS_OPTIONAL_TRACE_NAME_FMT("cross node layer crop, dstRect:[%d, %d, %d, %d] srcRect:[%d, %d, %d, %d]",
        layerInfo.dstRect.x, layerInfo.dstRect.y, layerInfo.dstRect.w, layerInfo.dstRect.h,
        layerInfo.srcRect.x, layerInfo.srcRect.y, layerInfo.srcRect.w, layerInfo.srcRect.h);
}

void RSDrmUtil::DRMCreateLayer(std::shared_ptr<RSProcessor> processor, Drawing::Matrix canvasMatrix)
{
    auto& hardwareDrawables =
        RSUniRenderThread::Instance().GetRSRenderThreadParams()->GetHardwareEnabledTypeDrawables();
    for (const auto& [screenNodeId, _, drawable] : hardwareDrawables) {
        if (UNLIKELY(!drawable) || !drawable->GetRenderParams()) {
            continue;
        }
        auto surfaceDrawable = std::static_pointer_cast<DrawableV2::RSSurfaceRenderNodeDrawable>(drawable);
        if (UNLIKELY(surfaceDrawable == nullptr)) {
            continue;
        }
        auto& params = surfaceDrawable->GetRenderParams();
        if (UNLIKELY(!params)) {
            continue;
        }
        auto surfaceParams = static_cast<RSSurfaceRenderParams*>(params.get());
        if (UNLIKELY(!surfaceParams) || !surfaceParams->GetSpecialLayerMgr().Find(SpecialLayerType::HAS_PROTECTED)) {
            continue;
        }
        // calculate matrix
        auto layerInfo = surfaceParams->GetLayerInfo();
        Drawing::Matrix tmpMatrix = surfaceParams->GetTotalMatrix();
        tmpMatrix.PostConcat(canvasMatrix);
        layerInfo.matrix = tmpMatrix;
        // calculate dstRect
        Drawing::Rect absRect;
        tmpMatrix.MapRect(absRect, surfaceParams->GetBounds());
        layerInfo.dstRect.x = absRect.left_;
        layerInfo.dstRect.y = absRect.top_;
        layerInfo.dstRect.w = absRect.right_ - absRect.left_;
        layerInfo.dstRect.h = absRect.bottom_ - absRect.top_;
        // calculate transformType
        GraphicTransformType rotateEnum =
            RSBaseRenderUtil::RotateEnumToInt(RSUniRenderUtil::GetRotationFromMatrix(tmpMatrix) % 360,
                RSBaseRenderUtil::GetFlipTransform(layerInfo.transformType));
        layerInfo.transformType = rotateEnum;
        surfaceParams->SetLayerInfo(layerInfo);
        processor->CreateLayerForRenderThread(*surfaceDrawable);
    }
}

void RSDrmUtil::MarkBlurIntersectWithDRM(const std::shared_ptr<RSRenderNode>& node,
    const std::vector<std::weak_ptr<RSSurfaceRenderNode>>& drmNodes,
    const std::shared_ptr<RSScreenRenderNode>& curScreenNode)
{
    if (node == nullptr) {
        return;
    }
    static bool isCCMMockAllBlurEffectIntersectWithDRMEnabled = DRMParam::IsMockAllBlurEffectIntersectWithDRMEnable();
    bool isMockAllBlurEffectIntersectWithDRMEnabled = isCCMMockAllBlurEffectIntersectWithDRMEnabled ||
        RSSystemProperties::GetSceneBoardIsPcMode();
    if (isMockAllBlurEffectIntersectWithDRMEnabled) {
        // mark all blurEffect for pc
        MarkAllBlurIntersectWithDRM(node, drmNodes, curScreenNode);
    } else {
        MarkBlurIntersectWithDRM(node, drmNodes);
    }
}

void RSDrmUtil::MarkAllBlurIntersectWithDRM(const std::shared_ptr<RSRenderNode>& node,
    const std::vector<std::weak_ptr<RSSurfaceRenderNode>>& drmNodes,
    const std::shared_ptr<RSScreenRenderNode>& curScreenNode)
{
    if (curScreenNode == nullptr) {
        return;
    }
    
    if (node->GetRenderProperties().GetBackgroundBlurMaskColor().GetAlpha() >= BLUR_MIN_ALPHA) {
        // if alpha is greater than 100, blurEffect is not transparent
        return;
    }
    auto appWindowNodeId = node->GetInstanceRootNodeId();
    const auto& nodeMap = RSMainThread::Instance()->GetContext().GetNodeMap();
    auto appWindowNode = RSBaseRenderNode::ReinterpretCast<RSSurfaceRenderNode>(nodeMap.GetRenderNode(appWindowNodeId));
    if (appWindowNode == nullptr) {
        return;
    }
    static std::vector<std::string> drmKeyWins = DRMParam::GetBlackList();
    for (const auto& win : drmKeyWins) {
        if (appWindowNode->GetName().find(win) != std::string::npos) {
            return;
        }
    }
    for (auto& drmNode : drmNodes) {
        auto drmNodePtr = drmNode.lock();
        if (drmNodePtr == nullptr) {
            continue;
        }
        bool isIntersect =
            drmNodePtr->GetRenderProperties().GetBoundsGeometry()->GetAbsRect().Intersect(node->GetFilterRegion());
        auto drmAppWindow = RSBaseRenderNode::ReinterpretCast<RSSurfaceRenderNode>(drmNodePtr->GetInstanceRootNode());
        bool isVisibleRegionEmpty = drmAppWindow ? drmAppWindow->GetVisibleRegion().IsEmpty() : true;
        if (isIntersect && !isVisibleRegionEmpty && IsDRMBelowFilter(curScreenNode, appWindowNode, drmNodePtr)) {
            node->MarkBlurIntersectWithDRM(true, GetDarkColorMode(node, appWindowNode));
        }
    }
}

void RSDrmUtil::MarkBlurIntersectWithDRM(const std::shared_ptr<RSRenderNode>& node,
    const std::vector<std::weak_ptr<RSSurfaceRenderNode>>& drmNodes)
{
    auto appWindowNodeId = node->GetInstanceRootNodeId();
    const auto& nodeMap = RSMainThread::Instance()->GetContext().GetNodeMap();
    auto appWindowNode = RSBaseRenderNode::ReinterpretCast<RSSurfaceRenderNode>(nodeMap.GetRenderNode(appWindowNodeId));
    if (appWindowNode == nullptr) {
        return;
    }
    static std::vector<std::string> drmKeyWins = DRMParam::GetWhiteList();
    auto effectNode = node->ReinterpretCastTo<RSEffectRenderNode>() ?
        node->ReinterpretCastTo<RSEffectRenderNode>() : nullptr;
    if (effectNode) {
        effectNode->SetEffectIntersectWithDRM(false);
        effectNode->SetDarkColorMode(RSMainThread::Instance()->GetGlobalDarkColorMode());
    }
    for (const auto& win : drmKeyWins) {
        if (appWindowNode->GetName().find(win) == std::string::npos) {
            continue;
        }
        for (auto& drmNode : drmNodes) {
            auto drmNodePtr = drmNode.lock();
            if (drmNodePtr == nullptr) {
                continue;
            }
            bool isIntersect =
                drmNodePtr->GetRenderProperties().GetBoundsGeometry()->GetAbsRect().Intersect(node->GetFilterRegion());
            if (!isIntersect) {
                continue;
            }
            node->MarkBlurIntersectWithDRM(true, RSMainThread::Instance()->GetGlobalDarkColorMode());
            if (effectNode) {
                effectNode->SetEffectIntersectWithDRM(true);
            }
        }
    }
}

bool RSDrmUtil::IsDRMBelowFilter(const std::shared_ptr<RSScreenRenderNode>& curScreenNode,
    const std::shared_ptr<RSSurfaceRenderNode>& appWindowNode,
    const std::shared_ptr<RSSurfaceRenderNode>& drmNode)
{
    auto& curMainAndLeashSurfaces = curScreenNode->GetAllMainAndLeashSurfaces();
    size_t filterNodeIndex = 0;
    size_t drmNodeIndex = 0;
    for (size_t i = 0; i < curMainAndLeashSurfaces.size(); ++i) {
        auto leashWindowNode = RSBaseRenderNode::ReinterpretCast<RSSurfaceRenderNode>(curMainAndLeashSurfaces[i]);
        if (appWindowNode == leashWindowNode) {
            filterNodeIndex = i;
        }
        auto drmLeashNode = RSBaseRenderNode::ReinterpretCast<RSSurfaceRenderNode>(drmNode->GetInstanceRootNode());
        if (drmLeashNode == leashWindowNode) {
            drmNodeIndex = i;
        }
    }
    return drmNodeIndex > filterNodeIndex;
}

bool RSDrmUtil::GetDarkColorMode(const std::shared_ptr<RSRenderNode>& node,
    const std::shared_ptr<RSSurfaceRenderNode>& appWindowNode)
{
    bool isDarkColorMode = RSMainThread::Instance()->GetGlobalDarkColorMode();
    if (appWindowNode->GetName().find("SCBSmartDock") != std::string::npos) {
        float saturation = node->GetRenderProperties().GetBgBrightnessSaturation();
        isDarkColorMode = ROSEN_GNE(saturation, 1.4f) ? false : true;
    }
    return isDarkColorMode;
}

bool RSDrmUtil::IsDRMNodesOnTheTree()
{
    for (const auto& pair : drmNodes_) {
        for (const auto& drmNode : pair.second) {
            const auto& instanceNode = drmNode->GetInstanceRootNode();
            if (instanceNode && instanceNode->IsOnTheTree()) {
                return true;
            }
        }
    }
    return false;
}

void RSDrmUtil::PreAllocProtectedFrameBuffers(const std::shared_ptr<RSSurfaceRenderNode>& surfaceNode,
    const sptr<SurfaceBuffer>& buffer, const std::shared_ptr<RSComposerClientManager>& clientManager)
{
    if (auto screenNode = std::static_pointer_cast<RSScreenRenderNode>(surfaceNode->GetAncestorScreenNode().lock())) {
        RSUniRenderThread::Instance().AddScreenHasProtectedLayerSet(screenNode->GetScreenId());
        if (clientManager != nullptr) {
            RS_TRACE_NAME_FMT("PreAllocProtectedFrameBuffers screenId:%" PRIu64, screenNode->GetScreenId());
            clientManager->PreAllocProtectedFrameBuffers(screenNode->GetScreenId(), buffer);
        }
    }
}

void RSDrmUtil::DealWithDRMNodes(const std::shared_ptr<RSSurfaceRenderNode>& surfaceNode,
    const sptr<SurfaceBuffer>& buffer, const std::shared_ptr<RSComposerClientManager>& clientManager)
{
    CollectDrmNodes(surfaceNode);
    PreAllocProtectedFrameBuffers(surfaceNode, buffer, clientManager);
}

bool RSDrmUtil::HasDRMInVirtualScreen(
    RSPaintFilterCanvas& canvas, RSSurfaceRenderParams& surfaceParams)
{
    auto ancestorDrawable = surfaceParams.GetAncestorScreenDrawable().lock();
    if (ancestorDrawable == nullptr) {
        return false;
    }
    auto& params = ancestorDrawable->GetRenderParams();
    if (params == nullptr) {
        return false;
    }
    auto screenParam = static_cast<RSScreenRenderParams*>(params.get());
    const auto& screenProperty = screenParam->GetScreenProperty();
    if (!screenProperty.IsVirtual()) {
        return false;
    }
    const auto& specialLayerManager = surfaceParams.GetSpecialLayerMgr();
    if (!specialLayerManager.Find(SpecialLayerType::PROTECTED)) {
        return false;
    }
    return true;
}
} // namespace Rosen
} // namespace OHOS