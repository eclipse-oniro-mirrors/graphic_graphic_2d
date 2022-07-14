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

#include "ui/rs_node.h"

#include <algorithm>
#include <memory>
#include <sstream>
#include <string>

#include "animation/rs_animation.h"
#include "animation/rs_implicit_animator.h"
#include "animation/rs_implicit_animator_map.h"
#include "command/rs_node_command.h"
#include "common/rs_color.h"
#include "common/rs_obj_geometry.h"
#include "pipeline/rs_node_map.h"
#include "platform/common/rs_log.h"
#include "render/rs_path.h"
#include "transaction/rs_transaction_proxy.h"
#include "animation/rs_animation_manager_map.h"

namespace OHOS {
namespace Rosen {

RSNode::RSNode(bool isRenderServiceNode)
    : RSBaseNode(isRenderServiceNode), stagingPropertiesExtrator_(GetId())
{
    UpdateImplicitAnimator();
}

RSNode::~RSNode()
{
    FallbackAnimationsToRoot();
    ClearAllModifiers();
}

void RSNode::OpenImplicitAnimation(const RSAnimationTimingProtocol& timingProtocol,
    const RSAnimationTimingCurve& timingCurve, const std::function<void()>& finishCallback)
{
    auto implicitAnimator = RSImplicitAnimatorMap::Instance().GetAnimator(gettid());
    if (implicitAnimator == nullptr) {
        ROSEN_LOGE("Failed to open implicit animation, implicit animator is null!");
        return;
    }

    implicitAnimator->OpenImplicitAnimation(timingProtocol, timingCurve, finishCallback);
}

std::vector<std::shared_ptr<RSAnimation>> RSNode::CloseImplicitAnimation()
{
    auto implicitAnimator = RSImplicitAnimatorMap::Instance().GetAnimator(gettid());
    if (implicitAnimator == nullptr) {
        ROSEN_LOGE("Failed to close implicit animation, implicit animator is null!");
        return {};
    }

    return implicitAnimator->CloseImplicitAnimation();
}

void RSNode::AddKeyFrame(
    float fraction, const RSAnimationTimingCurve& timingCurve, const PropertyCallback& propertyCallback)
{
    auto implicitAnimator = RSImplicitAnimatorMap::Instance().GetAnimator(gettid());
    if (implicitAnimator == nullptr) {
        ROSEN_LOGE("Failed to add keyframe, implicit animator is null!");
        return;
    }

    implicitAnimator->BeginImplicitKeyFrameAnimation(fraction, timingCurve);
    propertyCallback();
    implicitAnimator->EndImplicitKeyFrameAnimation();
}

void RSNode::AddKeyFrame(float fraction, const PropertyCallback& propertyCallback)
{
    auto implicitAnimator = RSImplicitAnimatorMap::Instance().GetAnimator(gettid());
    if (implicitAnimator == nullptr) {
        ROSEN_LOGE("Failed to add keyframe, implicit animator is null!");
        return;
    }

    implicitAnimator->BeginImplicitKeyFrameAnimation(fraction);
    propertyCallback();
    implicitAnimator->EndImplicitKeyFrameAnimation();
}

std::vector<std::shared_ptr<RSAnimation>> RSNode::Animate(const RSAnimationTimingProtocol& timingProtocol,
    const RSAnimationTimingCurve& timingCurve, const PropertyCallback& propertyCallback,
    const std::function<void()>& finishCallback)
{
    if (propertyCallback == nullptr) {
        ROSEN_LOGE("Failed to add curve animation, property callback is null!");
        return {};
    }

    if (RSImplicitAnimatorMap::Instance().GetAnimator(gettid()) == nullptr) {
        ROSEN_LOGE("Failed to add curve animation, implicit animator is null!");
        return {};
    }

    OpenImplicitAnimation(timingProtocol, timingCurve, finishCallback);
    propertyCallback();
    return CloseImplicitAnimation();
}

void RSNode::FallbackAnimationsToRoot()
{
    auto target = RSNodeMap::Instance().GetAnimationFallbackNode();

    if (target == nullptr) {
        ROSEN_LOGE("Failed to move animation to root, root node is null!");
        return;
    }
    for (const auto& [animationId, animation] : animations_) {
        target->AddAnimationInner(animation);
    }
}

void RSNode::AddAnimationInner(const std::shared_ptr<RSAnimation>& animation)
{
    animations_.emplace(animation->GetId(), animation);
    animatingPropertyNum_[animation->GetPropertyId()]++;
}

void RSNode::RemoveAnimationInner(const std::shared_ptr<RSAnimation>& animation)
{
    animations_.erase(animation->GetId());
    animatingPropertyNum_[animation->GetPropertyId()]--;
    if (animatingPropertyNum_[animation->GetPropertyId()] == 0) {
        auto modifier = GetModifier(animation->GetPropertyId());
        if (modifier != nullptr) {
            modifier->SetPropertyOnAllAnimationFinish();
        }
    }
}

void RSNode::FinishAnimationByProperty(const PropertyId& id)
{
    for (const auto& [animationId, animation] : animations_) {
        if (animation->GetPropertyId() == id) {
            animation->Finish();
        }
    }
}

const RSModifierExtractor& RSNode::GetStagingProperties() const
{
    return stagingPropertiesExtrator_;
}

void RSNode::AddAnimation(const std::shared_ptr<RSAnimation>& animation)
{
    if (animation == nullptr) {
        ROSEN_LOGE("Failed to add animation, animation is null!");
        return;
    }

    auto animationId = animation->GetId();
    if (animations_.find(animationId) != animations_.end()) {
        ROSEN_LOGE("Failed to add animation, animation already exists!");
        return;
    }

    if (animation->GetDuration() <= 0) {
        FinishAnimationByProperty(animation->GetPropertyId());
    }

    AddAnimationInner(animation);
    animation->StartInner(std::static_pointer_cast<RSNode>(shared_from_this()));
}

void RSNode::RemoveAllAnimations()
{
    for (const auto& [id, animation] : animations_) {
        RemoveAnimation(animation);
    }
}

void RSNode::RemoveAnimation(const std::shared_ptr<RSAnimation>& animation)
{
    if (animation == nullptr) {
        ROSEN_LOGE("Failed to remove animation, animation is null!");
        return;
    }

    if (animations_.find(animation->GetId()) == animations_.end()) {
        ROSEN_LOGE("Failed to remove animation, animation not exists!");
        return;
    }

    animation->Finish();
}

void RSNode::SetMotionPathOption(const std::shared_ptr<RSMotionPathOption>& motionPathOption)
{
    motionPathOption_ = motionPathOption;
    UpdateModifierMotionPathOption();
}

const std::shared_ptr<RSMotionPathOption> RSNode::GetMotionPathOption() const
{
    return motionPathOption_;
}

bool RSNode::HasPropertyAnimation(const PropertyId& id)
{
    // check if any animation matches the property bitmask
    auto pred = [id](const auto& it) -> bool {
        return it.second > 0 && (static_cast<unsigned long long>(it.first) & static_cast<unsigned long long>(id));
    };
    return std::any_of(animatingPropertyNum_.begin(), animatingPropertyNum_.end(), pred);
}

const std::vector<RSModifierType> RSNode::pathAnimationModifiers_ = {
    RSModifierType::BOUNDS,
    RSModifierType::BOUNDS_POSITION,
    RSModifierType::FRAME,
    RSModifierType::FRAME_POSITION,
    RSModifierType::TRANSLATE
};

bool RSNode::IsPathAnimatableModifier(const RSModifierType& type)
{
    if (find(pathAnimationModifiers_.begin(), pathAnimationModifiers_.end(), type) == pathAnimationModifiers_.end()) {
        return false;
    }

    return true;
}

#define SET_ANIMATABLE_MODIFIER(propertyName, T, value, propertyType, defaultValue)                       \
    do {                                                                                                  \
        auto iter = propertyModifiers_.find(RSModifierType::propertyType);                                \
        if (iter != propertyModifiers_.end()) {                                                           \
            std::static_pointer_cast<RSAnimatableModifier<T>>(iter->second)->Update(value);               \
            break;                                                                                        \
        }                                                                                                 \
        auto property = std::make_shared<RSAnimatableProperty<T>>(defaultValue);                          \
        auto modifier = std::make_shared<RS##propertyName##Modifier>(property);                           \
        modifiers_.emplace(modifier->GetPropertyId(), modifier);                                          \
        propertyModifiers_.emplace(RSModifierType::propertyType, modifier);                               \
        modifier->MarkAddToNode(GetId());                                                                 \
        if (motionPathOption_ != nullptr && IsPathAnimatableModifier(RSModifierType::propertyType)) {     \
            modifier->SetMotionPathOption(motionPathOption_);                                             \
        }                                                                                                 \
        std::unique_ptr<RSCommand> cmd = std::make_unique<RSAddModifier>(                                 \
            GetId(), modifier->CreateRenderModifier());                                                   \
        auto transactionProxy = RSTransactionProxy::GetInstance();                                        \
        if (transactionProxy != nullptr) {                                                                \
            transactionProxy->AddCommand(cmd, IsRenderServiceNode());                                     \
            if (NeedForcedSendToRemote()) {                                                               \
                std::unique_ptr<RSCommand> cmdForRemote =                                                 \
                    std::make_unique<RSAddModifier>(GetId(), modifier->CreateRenderModifier());           \
                transactionProxy->AddCommand(cmdForRemote, true);                                         \
            }                                                                                             \
        }                                                                                                 \
        property->Set(value);                                                                             \
    } while (0)

#define SET_NONANIMATABLE_MODIFIER(propertyName, T, value, propertyType, defaultValue)                    \
    do {                                                                                                  \
        auto iter = propertyModifiers_.find(RSModifierType::propertyType);                                \
        if (iter != propertyModifiers_.end()) {                                                           \
            std::static_pointer_cast<RSAnimatableModifier<T>>(iter->second)->Update(value);               \
            break;                                                                                        \
        }                                                                                                 \
        auto property = std::make_shared<RSProperty<T>>(value);                                           \
        auto modifier = std::make_shared<RS##propertyName##Modifier>(property);                           \
        modifiers_.emplace(modifier->GetPropertyId(), modifier);                                          \
        propertyModifiers_.emplace(RSModifierType::propertyType, modifier);                               \
        modifier->MarkAddToNode(GetId());                                                                 \
        std::unique_ptr<RSCommand> cmd = std::make_unique<RSAddModifier>(                                 \
            GetId(), modifier->CreateRenderModifier());                                                   \
        auto transactionProxy = RSTransactionProxy::GetInstance();                                        \
        if (transactionProxy != nullptr) {                                                                \
            transactionProxy->AddCommand(cmd, IsRenderServiceNode());                                     \
            if (NeedForcedSendToRemote()) {                                                               \
                std::unique_ptr<RSCommand> cmdForRemote =                                                 \
                    std::make_unique<RSAddModifier>(GetId(), modifier->CreateRenderModifier());           \
                transactionProxy->AddCommand(cmdForRemote, true);                                         \
            }                                                                                             \
        }                                                                                                 \
    } while (0)

// alpha
void RSNode::SetAlpha(float alpha)
{
    SET_ANIMATABLE_MODIFIER(Alpha, float, alpha, ALPHA, 1.f);
}

// Bounds
void RSNode::SetBounds(const Vector4f& bounds)
{
    SET_ANIMATABLE_MODIFIER(Bounds, Vector4f, bounds, BOUNDS, Vector4f(0.f));
    OnBoundsSizeChanged();
}

void RSNode::SetBounds(float positionX, float positionY, float width, float height)
{
    SetBounds({ positionX, positionY, width, height });
}

void RSNode::SetBoundsWidth(float width)
{
    auto iter = propertyModifiers_.find(RSModifierType::BOUNDS);
    if (iter == propertyModifiers_.end()) {
        return;
    }
    auto modifier = std::static_pointer_cast<RSAnimatableModifier<Vector4f>>(iter->second);
    if (!modifier) {
        return;
    }
    auto bounds = modifier->property_->Get();
    bounds.z_ = width;
    modifier->Update(bounds);
    OnBoundsSizeChanged();
}

void RSNode::SetBoundsHeight(float height)
{
    auto iter = propertyModifiers_.find(RSModifierType::BOUNDS);
    if (iter == propertyModifiers_.end()) {
        return;
    }
    auto modifier = std::static_pointer_cast<RSAnimatableModifier<Vector4f>>(iter->second);
    if (!modifier) {
        return;
    }
    auto bounds = modifier->property_->Get();
    bounds.w_ = height;
    modifier->Update(bounds);
    OnBoundsSizeChanged();
}

// Frame
void RSNode::SetFrame(const Vector4f& bounds)
{
    SET_ANIMATABLE_MODIFIER(Frame, Vector4f, bounds, FRAME, Vector4f(0.f));
}

void RSNode::SetFrame(float positionX, float positionY, float width, float height)
{
    SetFrame({ positionX, positionY, width, height });
}

void RSNode::SetFramePositionX(float positionX)
{
    auto iter = propertyModifiers_.find(RSModifierType::FRAME);
    if (iter == propertyModifiers_.end()) {
        return;
    }
    auto modifier = std::static_pointer_cast<RSAnimatableModifier<Vector4f>>(iter->second);
    if (!modifier) {
        return;
    }
    auto frame = modifier->property_->Get();
    frame.x_ = positionX;
    modifier->Update(frame);
}

void RSNode::SetFramePositionY(float positionY)
{
    auto iter = propertyModifiers_.find(RSModifierType::FRAME);
    if (iter == propertyModifiers_.end()) {
        return;
    }
    auto modifier = std::static_pointer_cast<RSAnimatableModifier<Vector4f>>(iter->second);
    if (!modifier) {
        return;
    }
    auto frame = modifier->property_->Get();
    frame.y_ = positionY;
    modifier->Update(frame);
}

void RSNode::SetPositionZ(float positionZ)
{
    SET_ANIMATABLE_MODIFIER(PositionZ, float, positionZ, POSITION_Z, 0.f);
}

// pivot
void RSNode::SetPivot(const Vector2f& pivot)
{
    SET_ANIMATABLE_MODIFIER(Pivot, Vector2f, pivot, PIVOT, Vector2f(0.5f, 0.5f));
}

void RSNode::SetPivot(float pivotX, float pivotY)
{
    SetPivot({ pivotX, pivotY });
}

void RSNode::SetPivotX(float pivotX)
{
    auto iter = propertyModifiers_.find(RSModifierType::PIVOT);
    if (iter == propertyModifiers_.end()) {
        return;
    }
    auto modifier = std::static_pointer_cast<RSAnimatableModifier<Vector2f>>(iter->second);
    if (!modifier) {
        return;
    }
    auto pivot = modifier->property_->Get();
    pivot.x_ = pivotX;
    modifier->Update(pivot);
}

void RSNode::SetPivotY(float pivotY)
{
    auto iter = propertyModifiers_.find(RSModifierType::PIVOT);
    if (iter == propertyModifiers_.end()) {
        return;
    }
    auto modifier = std::static_pointer_cast<RSAnimatableModifier<Vector2f>>(iter->second);
    if (!modifier) {
        return;
    }
    auto pivot = modifier->property_->Get();
    pivot.y_ = pivotY;
    modifier->Update(pivot);
}

void RSNode::SetCornerRadius(float cornerRadius)
{
    SetCornerRadius(Vector4f(cornerRadius));
}

void RSNode::SetCornerRadius(const Vector4f& cornerRadius)
{
    SET_ANIMATABLE_MODIFIER(CornerRadius, Vector4f, cornerRadius, CORNER_RADIUS, Vector4f(0.f));
}

// transform
void RSNode::SetRotation(const Quaternion& quaternion)
{
    SET_ANIMATABLE_MODIFIER(Quaternion, Quaternion, quaternion, QUATERNION, Quaternion());
}

void RSNode::SetRotation(float degree)
{
    SET_ANIMATABLE_MODIFIER(Rotation, float, degree, ROTATION, 0.f);
}

void RSNode::SetRotation(float degreeX, float degreeY, float degreeZ)
{
    SetRotationX(degreeX);
    SetRotationY(degreeY);
    SetRotation(degreeZ);
}

void RSNode::SetRotationX(float degree)
{
    SET_ANIMATABLE_MODIFIER(RotationX, float, degree, ROTATION_X, 0.f);
}

void RSNode::SetRotationY(float degree)
{
    SET_ANIMATABLE_MODIFIER(RotationY, float, degree, ROTATION_Y, 0.f);
}

void RSNode::SetTranslate(const Vector2f& translate)
{
    SET_ANIMATABLE_MODIFIER(Translate, Vector2f, translate, TRANSLATE, Vector2f(0.f, 0.f));
}

void RSNode::SetTranslate(float translateX, float translateY, float translateZ)
{
    SetTranslate({ translateX, translateY });
    SetTranslateZ(translateZ);
}
void RSNode::SetTranslateX(float translate)
{
    auto iter = propertyModifiers_.find(RSModifierType::TRANSLATE);
    if (iter == propertyModifiers_.end()) {
        return;
    }
    auto modifier = std::static_pointer_cast<RSAnimatableModifier<Vector2f>>(iter->second);
    if (!modifier) {
        return;
    }
    auto trans = modifier->property_->Get();
    trans.x_ = translate;
    modifier->Update(trans);
}

void RSNode::SetTranslateY(float translate)
{
    auto iter = propertyModifiers_.find(RSModifierType::TRANSLATE);
    if (iter == propertyModifiers_.end()) {
        return;
    }
    auto modifier = std::static_pointer_cast<RSAnimatableModifier<Vector2f>>(iter->second);
    if (!modifier) {
        return;
    }
    auto trans = modifier->property_->Get();
    trans.y_ = translate;
    modifier->Update(trans);
}

void RSNode::SetTranslateZ(float translate)
{
    SET_ANIMATABLE_MODIFIER(TranslateZ, float, translate, TRANSLATE_Z, 0.f);
}

void RSNode::SetScale(float scale)
{
    SetScale({ scale, scale });
}

void RSNode::SetScale(float scaleX, float scaleY)
{
    SetScale({ scaleX, scaleY });
}

void RSNode::SetScale(const Vector2f& scale)
{
    SET_ANIMATABLE_MODIFIER(Scale, Vector2f, scale, SCALE, Vector2f(1.f, 1.f));
}

void RSNode::SetScaleX(float scaleX)
{
    auto iter = propertyModifiers_.find(RSModifierType::SCALE);
    if (iter == propertyModifiers_.end()) {
        return;
    }
    auto modifier = std::static_pointer_cast<RSAnimatableModifier<Vector2f>>(iter->second);
    if (!modifier) {
        return;
    }
    auto scale = modifier->property_->Get();
    scale.x_ = scaleX;
    modifier->Update(scale);
}

void RSNode::SetScaleY(float scaleY)
{
    auto iter = propertyModifiers_.find(RSModifierType::SCALE);
    if (iter == propertyModifiers_.end()) {
        return;
    }
    auto modifier = std::static_pointer_cast<RSAnimatableModifier<Vector2f>>(iter->second);
    if (!modifier) {
        return;
    }
    auto scale = modifier->property_->Get();
    scale.y_ = scaleY;
    modifier->Update(scale);
}

// foreground
void RSNode::SetForegroundColor(uint32_t colorValue)
{
    auto color = Color::FromArgbInt(colorValue);
    SET_ANIMATABLE_MODIFIER(ForegroundColor, Color, color, FOREGROUND_COLOR, RgbPalette::Transparent());
}

void RSNode::SetBackgroundColor(uint32_t colorValue)
{
    auto color = Color::FromArgbInt(colorValue);
    SET_ANIMATABLE_MODIFIER(BackgroundColor, Color, color, BACKGROUND_COLOR, RgbPalette::Transparent());
}

void RSNode::SetSurfaceBgColor(uint32_t colorValue)
{
    auto color = Color::FromArgbInt(colorValue);
    SET_NONANIMATABLE_PROPERTY(SurfaceBgColor, color);
}

void RSNode::SetBackgroundShader(const std::shared_ptr<RSShader>& shader)
{
    SET_NONANIMATABLE_MODIFIER(BackgroundShader, std::shared_ptr<RSShader>, shader, BACKGROUND_SHADER, nullptr);
}

// background
void RSNode::SetBgImage(const std::shared_ptr<RSImage>& image)
{
    SET_NONANIMATABLE_MODIFIER(BgImage, std::shared_ptr<RSImage>, image, BG_IMAGE, nullptr);
}

void RSNode::SetBgImageSize(float width, float height)
{
    SetBgImageWidth(width);
    SetBgImageHeight(height);
}

void RSNode::SetBgImageWidth(float width)
{
    SET_ANIMATABLE_MODIFIER(BgImageWidth, float, width, BG_IMAGE_WIDTH, 0.f);
}

void RSNode::SetBgImageHeight(float height)
{
    SET_ANIMATABLE_MODIFIER(BgImageHeight, float, height, BG_IMAGE_HEIGHT, 0.f);
}

void RSNode::SetBgImagePosition(float positionX, float positionY)
{
    SetBgImagePositionX(positionX);
    SetBgImagePositionY(positionY);
}

void RSNode::SetBgImagePositionX(float positionX)
{
    SET_ANIMATABLE_MODIFIER(BgImagePositionX, float, positionX, BG_IMAGE_POSITION_X, 0.f);
}

void RSNode::SetBgImagePositionY(float positionY)
{
    SET_ANIMATABLE_MODIFIER(BgImagePositionY, float, positionY, BG_IMAGE_POSITION_Y, 0.f);
}

// border
void RSNode::SetBorderColor(uint32_t colorValue)
{
    SetBorderColor(colorValue, colorValue, colorValue, colorValue);
}

void RSNode::SetBorderColor(uint32_t left, uint32_t top, uint32_t right, uint32_t bottom)
{
    Vector4<Color> color(Color::FromArgbInt(left), Color::FromArgbInt(top),
                         Color::FromArgbInt(right), Color::FromArgbInt(bottom));
    SET_ANIMATABLE_MODIFIER(
        BorderColor, Vector4<Color>, color, BORDER_COLOR, Vector4<Color>(RgbPalette::Transparent()));
}

void RSNode::SetBorderColor(const Vector4<Color>& color)
{
    SET_ANIMATABLE_MODIFIER(
        BorderColor, Vector4<Color>, color, BORDER_COLOR, Vector4<Color>(RgbPalette::Transparent()));
}

void RSNode::SetBorderWidth(float width)
{
    SetBorderWidth(width, width, width, width);
}

void RSNode::SetBorderWidth(float left, float top, float right, float bottom)
{
    Vector4f width(left, top, right, bottom);
    SET_ANIMATABLE_MODIFIER(BorderWidth, Vector4f, width, BORDER_WIDTH, Vector4f(0.f));
}

void RSNode::SetBorderWidth(const Vector4f& width)
{
    SET_ANIMATABLE_MODIFIER(BorderWidth, Vector4f, width, BORDER_WIDTH, Vector4f(0.f));
}

void RSNode::SetBorderStyle(uint32_t styleValue)
{
    SetBorderStyle(styleValue, styleValue, styleValue, styleValue);
}

void RSNode::SetBorderStyle(uint32_t left, uint32_t top, uint32_t right, uint32_t bottom)
{
    Vector4<uint32_t> style(left, top, right, bottom);
    SET_NONANIMATABLE_MODIFIER(
        BorderStyle, Vector4<uint32_t>, style, BORDER_STYLE, Vector4<uint32_t>(BorderStyle::NONE));
}

void RSNode::SetBorderStyle(const Vector4<BorderStyle>& style)
{
    Vector4<uint32_t> styles(static_cast<uint32_t>(style.x_), static_cast<uint32_t>(style.y_),
                            static_cast<uint32_t>(style.z_), static_cast<uint32_t>(style.w_));
    SET_NONANIMATABLE_MODIFIER(
        BorderStyle, Vector4<uint32_t>, styles, BORDER_STYLE, Vector4<uint32_t>(BorderStyle::NONE));
}

void RSNode::SetBackgroundFilter(const std::shared_ptr<RSFilter>& backgroundFilter)
{
    SET_ANIMATABLE_MODIFIER(BackgroundFilter, std::shared_ptr<RSFilter>, backgroundFilter, BACKGROUND_FILTER, nullptr);
}

void RSNode::SetFilter(const std::shared_ptr<RSFilter>& filter)
{
    SET_ANIMATABLE_MODIFIER(Filter, std::shared_ptr<RSFilter>, filter, FILTER, nullptr);
}

void RSNode::SetCompositingFilter(const std::shared_ptr<RSFilter>& compositingFilter) {}

void RSNode::SetShadowColor(uint32_t colorValue)
{
    auto color = Color::FromArgbInt(colorValue);
    SET_ANIMATABLE_MODIFIER(ShadowColor, Color, color, SHADOW_COLOR, Color::FromArgbInt(DEFAULT_SPOT_COLOR));
}

void RSNode::SetShadowOffset(float offsetX, float offsetY)
{
    SetShadowOffsetX(offsetX);
    SetShadowOffsetY(offsetY);
}

void RSNode::SetShadowOffsetX(float offsetX)
{
    SET_ANIMATABLE_MODIFIER(ShadowOffsetX, float, offsetX, SHADOW_OFFSET_X, DEFAULT_SHADOW_OFFSET_X);
}

void RSNode::SetShadowOffsetY(float offsetY)
{
    SET_ANIMATABLE_MODIFIER(ShadowOffsetY, float, offsetY, SHADOW_OFFSET_Y, DEFAULT_SHADOW_OFFSET_Y);
}

void RSNode::SetShadowAlpha(float alpha)
{
    SET_ANIMATABLE_MODIFIER(ShadowAlpha, float, alpha, SHADOW_ALPHA, 0.f);
}

void RSNode::SetShadowElevation(float elevation)
{
    SET_ANIMATABLE_MODIFIER(ShadowElevation, float, elevation, SHADOW_ELEVATION, 0.f);
}

void RSNode::SetShadowRadius(float radius)
{
    SET_ANIMATABLE_MODIFIER(ShadowRadius, float, radius, SHADOW_RADIUS, 0.f);
}

void RSNode::SetShadowPath(const std::shared_ptr<RSPath>& shadowPath)
{
    SET_NONANIMATABLE_MODIFIER(ShadowPath, std::shared_ptr<RSPath>, shadowPath, SHADOW_PATH, nullptr);
}

void RSNode::SetFrameGravity(Gravity gravity)
{
    SET_NONANIMATABLE_MODIFIER(FrameGravity, Gravity, gravity, FRAME_GRAVITY, Gravity::DEFAULT);
}

void RSNode::SetClipBounds(const std::shared_ptr<RSPath>& path)
{
    SET_NONANIMATABLE_MODIFIER(ClipBounds, std::shared_ptr<RSPath>, path, CLIP_BOUNDS, nullptr);
}

void RSNode::SetClipToBounds(bool clipToBounds)
{
    SET_NONANIMATABLE_MODIFIER(ClipToBounds, bool, clipToBounds, CLIP_TO_BOUNDS, false);
}

void RSNode::SetClipToFrame(bool clipToFrame)
{
    SET_NONANIMATABLE_MODIFIER(ClipToFrame, bool, clipToFrame, CLIP_TO_FRAME, false);
}

void RSNode::SetVisible(bool visible)
{
    SET_NONANIMATABLE_MODIFIER(Visible, bool, visible, VISIBLE, true);
    if (transitionEffect_ != nullptr) {
        NotifyTransition(transitionEffect_, visible);
    }
}

void RSNode::SetMask(std::shared_ptr<RSMask> mask)
{
    SET_NONANIMATABLE_MODIFIER(Mask, std::shared_ptr<RSMask>, mask, MASK, nullptr);
}

void RSNode::NotifyTransition(const std::shared_ptr<const RSTransitionEffect>& effect, bool isTransitionIn)
{
    // temporary fix for multithread issue in implicit animator
    UpdateImplicitAnimator();
    if (implicitAnimator_ == nullptr) {
        ROSEN_LOGE("Failed to notify transition, implicit animator is null!");
        return;
    }

    if (!implicitAnimator_->NeedImplicitAnimation()) {
        return;
    }

    implicitAnimator_->BeginImplicitTransition(effect);
    implicitAnimator_->CreateImplicitTransition(*this, isTransitionIn);
    implicitAnimator_->EndImplicitTransition();
}

void RSNode::OnAddChildren()
{
    if (transitionEffect_ != nullptr) {
        NotifyTransition(transitionEffect_, true);
    }
}

void RSNode::OnRemoveChildren()
{
    if (transitionEffect_ != nullptr) {
        NotifyTransition(transitionEffect_, false);
    }
}

void RSNode::AnimationFinish(AnimationId animationId)
{
    auto animationItr = animations_.find(animationId);
    if (animationItr == animations_.end()) {
        ROSEN_LOGE("Failed to find animation[%llu]!", animationId);
        return;
    }

    auto animation = animationItr->second;
    if (animation == nullptr) {
        ROSEN_LOGE("Failed to finish animation[%llu], animation is null!", animationId);
        return;
    }

    animation->CallFinishCallback();
    RemoveAnimationInner(animation);
}

// This function will be optimized after the Modifier is committed
void RSNode::SetPropertyOnAllAnimationFinish(const RSAnimatableProperty& property)
{
    auto transactionProxy = RSTransactionProxy::GetInstance();
    if (transactionProxy == nullptr) {
        return;
    }
    std::unique_ptr<RSCommand> command;
    std::unique_ptr<RSCommand> commandForRemote;

    switch (property) {
        case RSAnimatableProperty::BOUNDS: {
            SET_NONANIMATABLE_PROPERTY_ON_REMOVE(Bounds);
            break;
        }
        case RSAnimatableProperty::BOUNDS_SIZE: {
            SET_NONANIMATABLE_PROPERTY_ON_REMOVE(BoundsSize);
            break;
        }
        case RSAnimatableProperty::BOUNDS_WIDTH: {
            SET_NONANIMATABLE_PROPERTY_ON_REMOVE(BoundsWidth);
            break;
        }
        case RSAnimatableProperty::BOUNDS_HEIGHT: {
            SET_NONANIMATABLE_PROPERTY_ON_REMOVE(BoundsHeight);
            break;
        }
        case RSAnimatableProperty::BOUNDS_POSITION: {
            SET_NONANIMATABLE_PROPERTY_ON_REMOVE(BoundsPosition);
            break;
        }
        case RSAnimatableProperty::BOUNDS_POSITION_X: {
            SET_NONANIMATABLE_PROPERTY_ON_REMOVE(BoundsPositionX);
            break;
        }
        case RSAnimatableProperty::BOUNDS_POSITION_Y: {
            SET_NONANIMATABLE_PROPERTY_ON_REMOVE(BoundsPositionY);
            break;
        }
        case RSAnimatableProperty::FRAME: {
            SET_NONANIMATABLE_PROPERTY_ON_REMOVE(Frame);
            break;
        }
        case RSAnimatableProperty::FRAME_SIZE: {
            SET_NONANIMATABLE_PROPERTY_ON_REMOVE(FrameSize);
            break;
        }
        case RSAnimatableProperty::FRAME_WIDTH: {
            SET_NONANIMATABLE_PROPERTY_ON_REMOVE(FrameWidth);
            break;
        }
        case RSAnimatableProperty::FRAME_HEIGHT: {
            SET_NONANIMATABLE_PROPERTY_ON_REMOVE(FrameHeight);
            break;
        }
        case RSAnimatableProperty::FRAME_POSITION: {
            SET_NONANIMATABLE_PROPERTY_ON_REMOVE(FramePosition);
            break;
        }
        case RSAnimatableProperty::FRAME_POSITION_X: {
            SET_NONANIMATABLE_PROPERTY_ON_REMOVE(FramePositionX);
            break;
        }
        case RSAnimatableProperty::FRAME_POSITION_Y: {
            SET_NONANIMATABLE_PROPERTY_ON_REMOVE(FramePositionY);
            break;
        }
        case RSAnimatableProperty::POSITION_Z: {
            SET_NONANIMATABLE_PROPERTY_ON_REMOVE(PositionZ);
            break;
        }
        case RSAnimatableProperty::PIVOT: {
            SET_NONANIMATABLE_PROPERTY_ON_REMOVE(Pivot);
            break;
        }
        case RSAnimatableProperty::PIVOT_X: {
            SET_NONANIMATABLE_PROPERTY_ON_REMOVE(PivotX);
            break;
        }
        case RSAnimatableProperty::PIVOT_Y: {
            SET_NONANIMATABLE_PROPERTY_ON_REMOVE(PivotY);
            break;
        }
        case RSAnimatableProperty::CORNER_RADIUS: {
            SET_NONANIMATABLE_PROPERTY_ON_REMOVE(CornerRadius);
            break;
        }
        case RSAnimatableProperty::ROTATION: {
            SET_NONANIMATABLE_PROPERTY_ON_REMOVE(Rotation);
            break;
        }
        case RSAnimatableProperty::ROTATION_X: {
            SET_NONANIMATABLE_PROPERTY_ON_REMOVE(RotationX);
            break;
        }
        case RSAnimatableProperty::ROTATION_Y: {
            SET_NONANIMATABLE_PROPERTY_ON_REMOVE(RotationY);
            break;
        }
        case RSAnimatableProperty::SCALE: {
            SET_NONANIMATABLE_PROPERTY_ON_REMOVE(Scale);
            break;
        }
        case RSAnimatableProperty::SCALE_X: {
            SET_NONANIMATABLE_PROPERTY_ON_REMOVE(ScaleX);
            break;
        }
        case RSAnimatableProperty::SCALE_Y: {
            SET_NONANIMATABLE_PROPERTY_ON_REMOVE(ScaleY);
            break;
        }
        case RSAnimatableProperty::TRANSLATE: {
            SET_NONANIMATABLE_PROPERTY_ON_REMOVE(Translate);
            break;
        }
        case RSAnimatableProperty::TRANSLATE_X: {
            SET_NONANIMATABLE_PROPERTY_ON_REMOVE(TranslateX);
            break;
        }
        case RSAnimatableProperty::TRANSLATE_Y: {
            SET_NONANIMATABLE_PROPERTY_ON_REMOVE(TranslateY);
            break;
        }
        case RSAnimatableProperty::TRANSLATE_Z: {
            SET_NONANIMATABLE_PROPERTY_ON_REMOVE(TranslateZ);
            break;
        }
        case RSAnimatableProperty::ALPHA: {
            SET_NONANIMATABLE_PROPERTY_ON_REMOVE(Alpha);
            break;
        }
        case RSAnimatableProperty::FOREGROUND_COLOR: {
            SET_NONANIMATABLE_PROPERTY_ON_REMOVE(ForegroundColor);
            break;
        }
        case RSAnimatableProperty::BACKGROUND_COLOR: {
            SET_NONANIMATABLE_PROPERTY_ON_REMOVE(BackgroundColor);
            break;
        }
        case RSAnimatableProperty::BGIMAGE_WIDTH: {
            SET_NONANIMATABLE_PROPERTY_ON_REMOVE(BgImageWidth);
            break;
        }
        case RSAnimatableProperty::BGIMAGE_HEIGHT: {
            SET_NONANIMATABLE_PROPERTY_ON_REMOVE(BgImageHeight);
            break;
        }
        case RSAnimatableProperty::BGIMAGE_POSITION_X: {
            SET_NONANIMATABLE_PROPERTY_ON_REMOVE(BgImagePositionX);
            break;
        }
        case RSAnimatableProperty::BGIMAGE_POSITION_Y: {
            SET_NONANIMATABLE_PROPERTY_ON_REMOVE(BgImagePositionY);
            break;
        }
        case RSAnimatableProperty::BORDER_COLOR: {
            SET_NONANIMATABLE_PROPERTY_ON_REMOVE(BorderColor);
            break;
        }
        case RSAnimatableProperty::BORDER_WIDTH: {
            SET_NONANIMATABLE_PROPERTY_ON_REMOVE(BorderWidth);
            break;
        }
        case RSAnimatableProperty::SUB_LAYER_TRANSFORM: {
            SET_NONANIMATABLE_PROPERTY_ON_REMOVE(SublayerTransform);
            break;
        }
        case RSAnimatableProperty::BACKGROUND_FILTER: {
            SET_NONANIMATABLE_PROPERTY_ON_REMOVE(BackgroundFilter);
            break;
        }
        case RSAnimatableProperty::FILTER: {
            SET_NONANIMATABLE_PROPERTY_ON_REMOVE(Filter);
            break;
        }
        case RSAnimatableProperty::SHADOW_COLOR: {
            SET_NONANIMATABLE_PROPERTY_ON_REMOVE(ShadowColor);
            break;
        }
        case RSAnimatableProperty::SHADOW_OFFSET_X: {
            SET_NONANIMATABLE_PROPERTY_ON_REMOVE(ShadowOffsetX);
            break;
        }
        case RSAnimatableProperty::SHADOW_OFFSET_Y: {
            SET_NONANIMATABLE_PROPERTY_ON_REMOVE(ShadowOffsetY);
            break;
        }
        case RSAnimatableProperty::SHADOW_ALPHA: {
            SET_NONANIMATABLE_PROPERTY_ON_REMOVE(ShadowAlpha);
            break;
        }
        case RSAnimatableProperty::SHADOW_ELEVATION: {
            SET_NONANIMATABLE_PROPERTY_ON_REMOVE(ShadowElevation);
            break;
        }
        case RSAnimatableProperty::SHADOW_RADIUS: {
            SET_NONANIMATABLE_PROPERTY_ON_REMOVE(ShadowRadius);
            break;
        }
        default:
            return;
    }
    transactionProxy->Begin();
    transactionProxy->AddCommand(command, IsRenderServiceNode(), GetFollowType(), GetId());
    transactionProxy->AddCommand(commandForRemote, true, GetFollowType(), GetId());
    transactionProxy->Commit();
}

void RSNode::SetPaintOrder(bool drawContentLast)
{
    drawContentLast_ = drawContentLast;
}

void RSNode::ClearModifiers()
{
    for (auto& [id, modifier] : modifiers_) {
        modifier->MarkRemoveFromNode();
        std::unique_ptr<RSCommand> command = std::make_unique<RSRemoveModifier>(GetId(), modifier->GetPropertyId());
        auto transactionProxy = RSTransactionProxy::GetInstance();
        if (transactionProxy != nullptr) {
            transactionProxy->AddCommand(command, IsRenderServiceNode());
        }
    }
    modifiers_.clear();
}

void RSNode::ClearAllModifiers()
{
    if (animationManager_ == nullptr) {
        animationManager_ = RSAnimationManagerMap::Instance().GetAnimationManager(gettid());
    }
    for (auto& [id, modifier] : modifiers_) {
        modifier->MarkRemoveFromNode();
        animationManager_->RemoveProperty(id);
    }
    modifiers_.clear();
    std::unique_ptr<RSCommand> command = std::make_unique<RSClearModifiers>(GetId());
    auto transactionProxy = RSTransactionProxy::GetInstance();
    if (transactionProxy != nullptr) {
        transactionProxy->AddCommand(command, IsRenderServiceNode());
    }
}

void RSNode::AddModifier(const std::shared_ptr<RSModifier>& modifier)
{
    if (!modifier) {
        return;
    }
    auto iter = propertyModifiers_.find(modifier->GetModifierType());
    if (iter != propertyModifiers_.end()) {
        modifier->SetIsAdditive(true);
    }
    if (motionPathOption_ != nullptr && IsPathAnimatableModifier(modifier->GetModifierType())) {
        modifier->SetMotionPathOption(motionPathOption_);
    }
    modifiers_.insert({ modifier->GetPropertyId(), modifier });
    modifier->MarkAddToNode(GetId());
    std::unique_ptr<RSCommand> command = std::make_unique<RSAddModifier>(GetId(), modifier->CreateRenderModifier());
    auto transactionProxy = RSTransactionProxy::GetInstance();
    if (transactionProxy != nullptr) {
        transactionProxy->AddCommand(command, IsRenderServiceNode());
    }
}

void RSNode::RemoveModifier(const std::shared_ptr<RSModifier>& modifier)
{
    if (!modifier) {
        return;
    }
    auto iter = modifiers_.find(modifier->GetPropertyId());
    if (iter == modifiers_.end()) {
        return;
    }

    modifiers_.erase(iter);
    modifier->MarkRemoveFromNode();
    if (animationManager_ == nullptr) {
        animationManager_ = RSAnimationManagerMap::Instance().GetAnimationManager(gettid());
    }
    animationManager_->RemoveProperty(modifier->GetPropertyId());
    std::unique_ptr<RSCommand> command = std::make_unique<RSRemoveModifier>(GetId(), modifier->GetPropertyId());
    auto transactionProxy = RSTransactionProxy::GetInstance();
    if (transactionProxy != nullptr) {
        transactionProxy->AddCommand(command, IsRenderServiceNode());
    }
}

const std::shared_ptr<RSModifier> RSNode::GetModifier(const PropertyId& propertyId)
{
    auto iter = modifiers_.find(propertyId);
    if (iter != modifiers_.end()) {
        return iter->second;
    }

    return {};
}

void RSNode::UpdateModifierMotionPathOption()
{
    for (auto& [type, modifier] : propertyModifiers_) {
        if (IsPathAnimatableModifier(type)) {
            modifier->SetMotionPathOption(motionPathOption_);
        }
    }
    for (auto& [id, modifier] : modifiers_) {
        if (IsPathAnimatableModifier(modifier->GetModifierType())) {
            modifier->SetMotionPathOption(motionPathOption_);
        }
    }
}

std::string RSNode::DumpNode(int depth) const
{
    std::stringstream ss;
    ss << RSBaseNode::DumpNode(depth);
    if (!animations_.empty()) {
        ss << " animation:" << std::to_string(animations_.size());
    }
    ss << " " << GetStagingProperties().Dump();
    return ss.str();
}

<<<<<<< HEAD
void RSNode::SetMask(const std::shared_ptr<RSMask>& mask)
{
    SET_NONANIMATABLE_PROPERTY(Mask, mask);
}

=======
>>>>>>> 9e2ab37e... add modifier and apply
void RSNode::UpdateImplicitAnimator()
{
    auto tid = gettid();
    if (tid == implicitAnimatorTid_) {
        return;
    }
    implicitAnimatorTid_ = tid;
    implicitAnimator_ = RSImplicitAnimatorMap::Instance().GetAnimator(tid);
}
} // namespace Rosen
} // namespace OHOS
