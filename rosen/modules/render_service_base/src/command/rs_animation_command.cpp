/*
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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

#include "command/rs_animation_command.h"

#include <memory>

#include "animation/rs_render_interactive_implict_animator_map.h"
#include "animation/rs_render_interactive_implict_animator.h"
#include "animation/rs_render_particle.h"
#include "common/rs_common_def.h"
#include "common/rs_common_hook.h"
#include "modifier/rs_render_modifier.h"
#include "modifier/rs_render_property.h"
#include "platform/common/rs_log.h"

namespace OHOS {
namespace Rosen {

namespace {
static AnimationCommandHelper::AnimationCallbackProcessor animationCallbackProcessor = nullptr;
}

void AnimationCommandHelper::AnimationCallback(
    RSContext& context, NodeId targetId, AnimationId animId, AnimationCallbackEvent event)
{
    if (animationCallbackProcessor != nullptr) {
        animationCallbackProcessor(targetId, animId, event);
    }
}

void AnimationCommandHelper::SetAnimationCallbackProcessor(AnimationCallbackProcessor processor)
{
    animationCallbackProcessor = processor;
}

void AnimationCommandHelper::CreateAnimation(
    RSContext& context, NodeId targetId, const std::shared_ptr<RSRenderAnimation>& animation)
{
    if (animation == nullptr) {
        RS_LOGE("AnimationCommandHelper::CreateAnimation, animation is nullptr");
        return;
    }
    auto node = context.GetNodeMap().GetRenderNode<RSRenderNode>(targetId);
    if (node == nullptr) {
        RS_LOGE("AnimationCommandHelper::CreateAnimation, node[%{public}" PRIu64 "] is nullptr", targetId);
        return;
    }
    RsCommonHook::Instance().OnStartNewAnimation(animation->GetFrameRateRange().GetComponentName());
    node->GetAnimationManager().AddAnimation(animation);
    auto modifier = node->GetModifier(animation->GetPropertyId());
    if (modifier != nullptr) {
        animation->AttachRenderProperty(modifier->GetProperty());
    }
    auto currentTime = context.GetCurrentTimestamp();
    animation->SetStartTime(currentTime);
    animation->Attach(node.get());
    // register node as animating node
    context.RegisterAnimatingRenderNode(node);
}

void AnimationCommandHelper::CreateParticleAnimation(
    RSContext& context, NodeId targetId, const std::shared_ptr<RSRenderParticleAnimation>& animation)
{
    if (animation == nullptr) {
        RS_LOGE("AnimationCommandHelper::CreateParticleAnimation, animation is nullptr");
        return;
    }
    auto node = context.GetNodeMap().GetRenderNode<RSRenderNode>(targetId);
    if (node == nullptr) {
        return;
    }
    RsCommonHook::Instance().OnStartNewAnimation(animation->GetFrameRateRange().GetComponentName());
    auto propertyId = animation->GetPropertyId();
    node->GetAnimationManager().AddAnimation(animation);
    auto property = std::make_shared<RSRenderProperty<RSRenderParticleVector>>(
        animation->GetRenderParticle(), propertyId);
    auto modifier = std::make_shared<RSParticlesRenderModifier>(property);
    node->AddModifier(modifier);
    animation->AttachRenderProperty(property);
    auto currentTime = context.GetCurrentTimestamp();
    animation->SetStartTime(currentTime);
    animation->Attach(node.get());
    // register node as animating node
    context.RegisterAnimatingRenderNode(node);
}

void AnimationCommandHelper::CancelAnimation(RSContext& context, NodeId targetId, PropertyId propertyId)
{
    auto node = context.GetNodeMap().GetRenderNode<RSRenderNode>(targetId);
    if (node == nullptr) {
        return;
    }

    auto& animationManager = node->GetAnimationManager();
    animationManager.CancelAnimationByPropertyId(propertyId);
}

void AnimationCommandHelper::CreateInteractiveAnimator(RSContext& context,
    InteractiveImplictAnimatorId targetId, std::vector<std::pair<NodeId, AnimationId>> animations,
    bool startImmediately)
{
    auto animator = context.GetInteractiveImplictAnimatorMap().GetInteractiveImplictAnimator(targetId);
    if (animator == nullptr) {
        animator = std::make_shared<RSRenderInteractiveImplictAnimator>(targetId, context.weak_from_this());
        context.GetInteractiveImplictAnimatorMap().RegisterInteractiveImplictAnimator(animator);
    }
    animator->AddAnimations(animations);
    if (startImmediately) {
        animator->ContinueAnimator();
    }
}

void AnimationCommandHelper::DestoryInteractiveAnimator(RSContext& context, InteractiveImplictAnimatorId targetId)
{
    auto animator = context.GetInteractiveImplictAnimatorMap().GetInteractiveImplictAnimator(targetId);
    if (animator == nullptr) {
        return;
    }
    context.GetInteractiveImplictAnimatorMap().UnregisterInteractiveImplictAnimator(targetId);
}

void AnimationCommandHelper::InteractiveAnimatorAddAnimations(RSContext& context,
    InteractiveImplictAnimatorId targetId, std::vector<std::pair<NodeId, AnimationId>> animations)
{
    auto animator = context.GetInteractiveImplictAnimatorMap().GetInteractiveImplictAnimator(targetId);
    if (animator == nullptr) {
        return;
    }
    animator->AddAnimations(animations);
}

void AnimationCommandHelper::PauseInteractiveAnimator(RSContext& context, InteractiveImplictAnimatorId targetId)
{
    auto animator = context.GetInteractiveImplictAnimatorMap().GetInteractiveImplictAnimator(targetId);
    if (animator == nullptr) {
        return;
    }
    animator->PauseAnimator();
}

void AnimationCommandHelper::ContinueInteractiveAnimator(RSContext& context, InteractiveImplictAnimatorId targetId)
{
    auto animator = context.GetInteractiveImplictAnimatorMap().GetInteractiveImplictAnimator(targetId);
    if (animator == nullptr) {
        return;
    }
    animator->ContinueAnimator();
}

void AnimationCommandHelper::FinishInteractiveAnimator(RSContext& context,
    InteractiveImplictAnimatorId targetId, RSInteractiveAnimationPosition finishPos)
{
    auto animator = context.GetInteractiveImplictAnimatorMap().GetInteractiveImplictAnimator(targetId);
    if (animator == nullptr) {
        return;
    }
    animator->FinishAnimator(finishPos);
}

void AnimationCommandHelper::ReverseInteractiveAnimator(RSContext& context, InteractiveImplictAnimatorId targetId)
{
    auto animator = context.GetInteractiveImplictAnimatorMap().GetInteractiveImplictAnimator(targetId);
    if (animator == nullptr) {
        return;
    }
    animator->ReverseAnimator();
}

void AnimationCommandHelper::SetFractionInteractiveAnimator(RSContext& context,
    InteractiveImplictAnimatorId targetId, float fraction)
{
    auto animator = context.GetInteractiveImplictAnimatorMap().GetInteractiveImplictAnimator(targetId);
    if (animator == nullptr) {
        return;
    }
    animator->SetFractionAnimator(fraction);
}
} // namespace Rosen
} // namespace OHOS
