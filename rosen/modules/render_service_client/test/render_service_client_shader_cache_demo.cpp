/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

// Shader frame cache demo: verifies container/per-effect cache behavior with
// repeating animations on COLOR_GRADIENT_EFFECT shaders.
//
// Usage:
//   shader_cache_demo <case>
//
// Cases:
//   1 — CONTAINER + ON_PARAM_SAME, single effect, animated A<->B
//       Expects: first frame miss+update, animation frames miss (params change),
//       stable frames hit.
//   2 — PER_EFFECT + ON_PARAM_SAME, single effect, animated A<->B
//       Expects: same as case 1 but per-effect trace (idx=0).
//   3 — CONTAINER + ON_PARAM_SAME, 2-effect chain, animated ChainA<->ChainB
//       Expects: any effect change triggers container miss+update.
//   4 — PER_EFFECT + ON_PARAM_SAME, 2-effect chain, animated ChainA<->ChainB
//       Expects: per-effect independent hit/miss (idx=0 and idx=1).
//   5 — NONE (no cache), single effect, animated A<->B
//       Expects: DrawShaderEffect every frame, no cache trace.
//   6 — PER_EFFECT + ON_PARAM_SAME, 2-effect chain, A stable / B animated
//       Effect A params fixed, effect B changes via animation.
//       Expects: idx=0 hit (A stable), idx=1 miss (B changes).
//   7 — CONTAINER + ON_PARAM_SAME, shader fixed, background color animated
//       Shader params never change; only SetBackgroundColor animates.
//       Expects: first frame miss+update, subsequent frames cache hit
//       (background color change must not invalidate shader cache).
//   8 — CONTAINER + FIXED_INTERVAL(skip=3), shader fixed, node position animated
//       Shader params unchanged but canvasHash changes every frame (position),
//       so condHash is false and FIXED_INTERVAL skip logic is exercised:
//       miss+update → 3 hits (skip) → miss+update → ...
//   9 — CONTAINER + FIXED_INTERVAL(skip=3), shader animated A<->B
//       Params change every frame, but FIXED_INTERVAL still skips N frames
//       between re-renders (unlike ON_PARAM_SAME which would miss every frame).
//   10 — CONTAINER + FIXED_INTERVAL(skip=3), shader fixed, no animation
//       Params and canvas both stable → condHash always true → every frame
//       hits after initial miss+update (FIXED_INTERVAL must not break normal
//       content-hit path).
//   no arg — prints usage.
//
// Prerequisites:
//   - System property: persist.sys.graphic.shaderFrameCacheEnabled=1 (default on)
//   - Trace filter: look for "GE#ShaderCache: container hit/miss" or
//     "GE#ShaderCache: perEffect hit/miss" in hitrace output.

#include <algorithm>
#include <iostream>
#include <unistd.h>

#include "transaction/rs_interfaces.h"
#include "transaction/rs_transaction.h"
#include "ui/rs_canvas_node.h"
#include "ui/rs_root_node.h"
#include "ui/rs_ui_context.h"
#include "ui/rs_ui_director.h"
#include "ui_effect/property/include/rs_ui_shader_base.h"
#include "ui/rs_surface_node.h"

using namespace OHOS;
using namespace OHOS::Rosen;
constexpr uint64_t SCREEN_ID = 0;

namespace {
constexpr int WINDOW_WIDTH = 1500;
constexpr int WINDOW_HEIGHT = 2000;
constexpr unsigned int ANIMATION_DURATION_MS = 5000;
constexpr size_t GRADIENT_EFFECT_MAX_SIZE = 12;
// Demo case numbers, keep in sync with the usage help at the top of the file.
constexpr int CASE_CONTAINER_ON_PARAM_SINGLE = 1;
constexpr int CASE_PER_EFFECT_ON_PARAM_SINGLE = 2;
constexpr int CASE_CONTAINER_ON_PARAM_CHAIN = 3;
constexpr int CASE_PER_EFFECT_ON_PARAM_CHAIN = 4;
constexpr int CASE_NONE_CACHE = 5;
constexpr int CASE_PER_EFFECT_CHAIN_B_ONLY = 6;
constexpr int CASE_CONTAINER_BG_ANIM = 7;
constexpr int CASE_FIXED_INTERVAL_POS_ANIM = 8;
constexpr int CASE_FIXED_INTERVAL_SHADER_ANIM = 9;
constexpr int CASE_FIXED_INTERVAL_NO_ANIM = 10;
// Fixed-interval cases skip this many frames between cache re-renders.
constexpr uint32_t DEMO_SKIP_INTERVAL = 3;
// Sleep long enough to observe two full animation cycles per test phase.
constexpr unsigned int MS_PER_SECOND = 1000;
constexpr unsigned int OBSERVE_ANIMATION_CYCLES = 2;
// Position offset for the position-animation case; moving the node changes
// canvasHash every frame without touching shader params.
constexpr int ANIMATED_NODE_OFFSET = 50;

using ColorSetter = void(RSNGColorGradientEffect::*)(const Vector4f&);
constexpr ColorSetter COLOR_SETTERS[] = {
    &RSNGColorGradientEffect::Setter<ColorGradientEffectColor0Tag>,
    &RSNGColorGradientEffect::Setter<ColorGradientEffectColor1Tag>,
    &RSNGColorGradientEffect::Setter<ColorGradientEffectColor2Tag>,
    &RSNGColorGradientEffect::Setter<ColorGradientEffectColor3Tag>,
    &RSNGColorGradientEffect::Setter<ColorGradientEffectColor4Tag>,
    &RSNGColorGradientEffect::Setter<ColorGradientEffectColor5Tag>,
    &RSNGColorGradientEffect::Setter<ColorGradientEffectColor6Tag>,
    &RSNGColorGradientEffect::Setter<ColorGradientEffectColor7Tag>,
    &RSNGColorGradientEffect::Setter<ColorGradientEffectColor8Tag>,
    &RSNGColorGradientEffect::Setter<ColorGradientEffectColor9Tag>,
    &RSNGColorGradientEffect::Setter<ColorGradientEffectColor10Tag>,
    &RSNGColorGradientEffect::Setter<ColorGradientEffectColor11Tag>
};

using PositionSetter = void(RSNGColorGradientEffect::*)(const Vector2f&);
constexpr PositionSetter POSITION_SETTERS[] = {
    &RSNGColorGradientEffect::Setter<ColorGradientEffectPosition0Tag>,
    &RSNGColorGradientEffect::Setter<ColorGradientEffectPosition1Tag>,
    &RSNGColorGradientEffect::Setter<ColorGradientEffectPosition2Tag>,
    &RSNGColorGradientEffect::Setter<ColorGradientEffectPosition3Tag>,
    &RSNGColorGradientEffect::Setter<ColorGradientEffectPosition4Tag>,
    &RSNGColorGradientEffect::Setter<ColorGradientEffectPosition5Tag>,
    &RSNGColorGradientEffect::Setter<ColorGradientEffectPosition6Tag>,
    &RSNGColorGradientEffect::Setter<ColorGradientEffectPosition7Tag>,
    &RSNGColorGradientEffect::Setter<ColorGradientEffectPosition8Tag>,
    &RSNGColorGradientEffect::Setter<ColorGradientEffectPosition9Tag>,
    &RSNGColorGradientEffect::Setter<ColorGradientEffectPosition10Tag>,
    &RSNGColorGradientEffect::Setter<ColorGradientEffectPosition11Tag>
};

using StrengthSetter = void(RSNGColorGradientEffect::*)(const float&);
constexpr StrengthSetter STRENGTH_SETTERS[] = {
    &RSNGColorGradientEffect::Setter<ColorGradientEffectStrength0Tag>,
    &RSNGColorGradientEffect::Setter<ColorGradientEffectStrength1Tag>,
    &RSNGColorGradientEffect::Setter<ColorGradientEffectStrength2Tag>,
    &RSNGColorGradientEffect::Setter<ColorGradientEffectStrength3Tag>,
    &RSNGColorGradientEffect::Setter<ColorGradientEffectStrength4Tag>,
    &RSNGColorGradientEffect::Setter<ColorGradientEffectStrength5Tag>,
    &RSNGColorGradientEffect::Setter<ColorGradientEffectStrength6Tag>,
    &RSNGColorGradientEffect::Setter<ColorGradientEffectStrength7Tag>,
    &RSNGColorGradientEffect::Setter<ColorGradientEffectStrength8Tag>,
    &RSNGColorGradientEffect::Setter<ColorGradientEffectStrength9Tag>,
    &RSNGColorGradientEffect::Setter<ColorGradientEffectStrength10Tag>,
    &RSNGColorGradientEffect::Setter<ColorGradientEffectStrength11Tag>
};

// Create shader directly via RSNGColorGradientEffect + Setter<Tag>, avoiding
// the VisualEffectPara / RSNGShaderBase::Create(para) indirection.
std::shared_ptr<RSNGShaderBase> CreateGradientShader(
    const std::vector<Vector4f>& colors, const std::vector<Vector2f>& positions,
    const std::vector<float>& strengths)
{
    auto shader = std::make_shared<RSNGColorGradientEffect>();
    for (size_t i = 0; i < colors.size() && i < GRADIENT_EFFECT_MAX_SIZE; i++) {
        (shader.get()->*COLOR_SETTERS[i])(colors[i]);
    }
    for (size_t i = 0; i < positions.size() && i < GRADIENT_EFFECT_MAX_SIZE; i++) {
        (shader.get()->*POSITION_SETTERS[i])(positions[i]);
    }
    for (size_t i = 0; i < strengths.size() && i < GRADIENT_EFFECT_MAX_SIZE; i++) {
        (shader.get()->*STRENGTH_SETTERS[i])(strengths[i]);
    }
    shader->Setter<ColorGradientEffectColorNumberTag>(static_cast<float>(colors.size()));
    return shader;
}

std::shared_ptr<RSNGShaderBase> CreateGradientShader(
    const Vector4f& color0, const Vector4f& color1)
{
    return CreateGradientShader(
        {color0, color1},
        {Vector2f(0.0f, 0.0f), Vector2f(1.0f, 1.0f)},
        {1.0f, 1.0f});
}

std::shared_ptr<RSNGShaderBase> CreateGradientChain(
    const Vector4f& a0, const Vector4f& a1, const Vector4f& b0, const Vector4f& b1)
{
    auto shaderA = CreateGradientShader(a0, a1);
    if (!shaderA) {
        return nullptr;
    }
    auto shaderB = CreateGradientShader(b0, b1);
    if (!shaderB) {
        return shaderA;
    }
    shaderA->Append(shaderB);
    return shaderA;
}

class ShaderCacheDemo {
public:
    ShaderCacheDemo()
    {
        if (!InitDirector() || !InitSurfaceNode() || !InitRootNode()) {
            return;
        }
        canvasNode_ = RSCanvasNode::Create(false, false, uiContext_);
        if (!canvasNode_) {
            return;
        }
        canvasNode_->SetBounds(0, 0, WINDOW_WIDTH, WINDOW_HEIGHT);
        canvasNode_->SetFrame(0, 0, WINDOW_WIDTH, WINDOW_HEIGHT);
        canvasNode_->SetBackgroundColor(SK_ColorBLACK);
        rootNode_->AddChild(canvasNode_, -1);
        transaction_ = uiContext_->GetRSTransaction();
        if (!transaction_) {
            return;
        }
        transaction_->FlushImplicitTransaction();
        rsUiDirector_->SendMessages();
        rsUiDirector_->FlushModifier();
        initSuccess_ = true;
        std::cout << "ShaderCache demo init success" << std::endl;
    }

    ~ShaderCacheDemo() noexcept
    {
        if (initSuccess_ && surfaceNode_) {
            surfaceNode_->DetachToDisplay(SCREEN_ID);
        }
        if (initSuccess_ && transaction_) {
            transaction_->FlushImplicitTransaction();
            rsUiDirector_->SendMessages();
            rsUiDirector_->FlushModifier();
        }
    }

    void Run(int testCase)
    {
        if (!initSuccess_) {
            std::cout << "Demo init failed" << std::endl;
            return;
        }

        if (testCase >= CASE_FIXED_INTERVAL_POS_ANIM) {
            DispatchFixedIntervalCase(testCase);
        } else {
            DispatchCachePolicyCase(testCase);
        }
        std::cout << "\n=== ShaderCache Demo End ===" << std::endl;
    }

private:
    // Cases 1-7: cache level / skip mode policy scenarios.
    void DispatchCachePolicyCase(int testCase)
    {
        switch (testCase) {
            case CASE_CONTAINER_ON_PARAM_SINGLE:
                TestPhase("CONTAINER + ON_PARAM_SAME (single, animated)",
                    RSFrameCacheLevel::CONTAINER, RSFrameSkipMode::ON_PARAM_SAME, 0,
                    ShaderStateA(), ShaderStateB());
                break;
            case CASE_PER_EFFECT_ON_PARAM_SINGLE:
                TestPhase("PER_EFFECT + ON_PARAM_SAME (single, animated)",
                    RSFrameCacheLevel::PER_EFFECT, RSFrameSkipMode::ON_PARAM_SAME, 0,
                    ShaderStateA(), ShaderStateB());
                break;
            case CASE_CONTAINER_ON_PARAM_CHAIN:
                TestPhase("CONTAINER + ON_PARAM_SAME (chain, animated)",
                    RSFrameCacheLevel::CONTAINER, RSFrameSkipMode::ON_PARAM_SAME, 0,
                    ChainStateA(), ChainStateB());
                break;
            case CASE_PER_EFFECT_ON_PARAM_CHAIN:
                TestPhase("PER_EFFECT + ON_PARAM_SAME (chain, animated)",
                    RSFrameCacheLevel::PER_EFFECT, RSFrameSkipMode::ON_PARAM_SAME, 0,
                    ChainStateA(), ChainStateB());
                break;
            case CASE_NONE_CACHE:
                TestPhaseNoCache("NONE (no cache, animated)",
                    ShaderStateA(), ShaderStateB());
                break;
            case CASE_PER_EFFECT_CHAIN_B_ONLY:
                TestPhase("PER_EFFECT + ON_PARAM_SAME (chain, A stable / B animated)",
                    RSFrameCacheLevel::PER_EFFECT, RSFrameSkipMode::ON_PARAM_SAME, 0,
                    ChainOnlyBChangeA(), ChainOnlyBChangeB());
                break;
            case CASE_CONTAINER_BG_ANIM:
                TestBgColorAnimation("CONTAINER + ON_PARAM_SAME (shader fixed, bg color animated)",
                    RSFrameCacheLevel::CONTAINER, RSFrameSkipMode::ON_PARAM_SAME, 0,
                    ShaderStateA(), SK_ColorRED, SK_ColorBLUE);
                break;
            default:
                PrintUsage();
                break;
        }
    }

    // Cases 8-10: fixed-interval skip scenarios.
    void DispatchFixedIntervalCase(int testCase)
    {
        switch (testCase) {
            case CASE_FIXED_INTERVAL_POS_ANIM:
                TestSkipFrameFixed("CONTAINER + FIXED_INTERVAL(skip=3), shader fixed, pos animated",
                    RSFrameCacheLevel::CONTAINER, RSFrameSkipMode::FIXED_INTERVAL, DEMO_SKIP_INTERVAL, ShaderStateA());
                break;
            case CASE_FIXED_INTERVAL_SHADER_ANIM:
                TestPhase("CONTAINER + FIXED_INTERVAL(skip=3), shader animated", RSFrameCacheLevel::CONTAINER,
                    RSFrameSkipMode::FIXED_INTERVAL, DEMO_SKIP_INTERVAL, ShaderStateA(), ShaderStateB());
                break;
            case CASE_FIXED_INTERVAL_NO_ANIM:
                TestSkipFrameNoAnim("CONTAINER + FIXED_INTERVAL(skip=3), shader fixed, no anim",
                    RSFrameCacheLevel::CONTAINER, RSFrameSkipMode::FIXED_INTERVAL, DEMO_SKIP_INTERVAL, ShaderStateA());
                break;
            default:
                PrintUsage();
                break;
        }
    }

    void PrintUsage()
    {
        std::cout << "Usage: shader_cache_demo <case>" << std::endl;
        std::cout << "  1: CONTAINER + ON_PARAM_SAME (single)" << std::endl;
        std::cout << "  2: PER_EFFECT + ON_PARAM_SAME (single)" << std::endl;
        std::cout << "  3: CONTAINER + ON_PARAM_SAME (chain, both change)" << std::endl;
        std::cout << "  4: PER_EFFECT + ON_PARAM_SAME (chain, both change)" << std::endl;
        std::cout << "  5: NONE (no cache)" << std::endl;
        std::cout << "  6: PER_EFFECT + ON_PARAM_SAME (chain, A stable / B change)" << std::endl;
        std::cout << "  7: CONTAINER + ON_PARAM_SAME (shader fixed, bg animated)" << std::endl;
        std::cout << "  8: CONTAINER + FIXED_INTERVAL(skip=3), shader fixed, pos animated" << std::endl;
        std::cout << "  9: CONTAINER + FIXED_INTERVAL(skip=3), shader animated" << std::endl;
        std::cout << "  10: CONTAINER + FIXED_INTERVAL(skip=3), shader fixed, no anim" << std::endl;
    }
    // Set shader A with cache, then start repeating animation to shader B.
    // Server-side interpolation drives param changes; client just sends commands.
    void TestPhase(const char* label, RSFrameCacheLevel level,
        RSFrameSkipMode mode, uint32_t skipInterval,
        std::shared_ptr<RSNGShaderBase> shaderA, std::shared_ptr<RSNGShaderBase> shaderB)
    {
        std::cout << "\n=== " << label << " ===" << std::endl;

        if (shaderA) {
            shaderA->EnableCache(level, {mode, skipInterval});
        }
        canvasNode_->SetBackgroundNGShader(shaderA);
        rsUiDirector_->SendMessages();
        rsUiDirector_->FlushModifier();
        std::cout << "  state A set (expect miss+update)" << std::endl;

        RSAnimationTimingProtocol protocol;
        protocol.SetDuration(ANIMATION_DURATION_MS);
        protocol.SetRepeatCount(-1);

        RSNode::Animate(uiContext_, protocol, RSAnimationTimingCurve::EASE_IN_OUT, [&]() {
            if (shaderB) {
                shaderB->EnableCache(level, {mode, skipInterval});
            }
            canvasNode_->SetBackgroundNGShader(shaderB);
        });

        rsUiDirector_->SendMessages();
        rsUiDirector_->FlushModifier();
        std::cout << "  animation A<->B started (repeat=-1, "
                  << ANIMATION_DURATION_MS << "ms)" << std::endl;

        sleep(ANIMATION_DURATION_MS / MS_PER_SECOND * OBSERVE_ANIMATION_CYCLES);

        RSNode::CloseImplicitAnimation(uiContext_);
        std::cout << "  animation stopped" << std::endl;
    }

    void TestPhaseNoCache(const char* label,
        std::shared_ptr<RSNGShaderBase> shaderA, std::shared_ptr<RSNGShaderBase> shaderB)
    {
        std::cout << "\n=== " << label << " ===" << std::endl;
        canvasNode_->SetBackgroundNGShader(shaderA);
        rsUiDirector_->SendMessages();
        rsUiDirector_->FlushModifier();

        RSAnimationTimingProtocol protocol;
        protocol.SetDuration(ANIMATION_DURATION_MS);
        protocol.SetRepeatCount(-1);

        RSNode::Animate(uiContext_, protocol, RSAnimationTimingCurve::EASE_IN_OUT, [&]() {
            canvasNode_->SetBackgroundNGShader(shaderB);
        });

        rsUiDirector_->SendMessages();
        rsUiDirector_->FlushModifier();
        std::cout << "  animation started, no cache" << std::endl;
        sleep(ANIMATION_DURATION_MS / MS_PER_SECOND * OBSERVE_ANIMATION_CYCLES);
        RSNode::CloseImplicitAnimation(uiContext_);
        canvasNode_->SetBackgroundNGShader(nullptr);
        rsUiDirector_->SendMessages();
        rsUiDirector_->FlushModifier();
    }

    // Shader params are fixed (never change); only background color animates.
    // Verifies that background color changes do not invalidate shader cache:
    // contentHash is derived from shader params only, so cache should hit
    // every frame after the initial miss+update.
    void TestBgColorAnimation(const char* label, RSFrameCacheLevel level,
        RSFrameSkipMode mode, uint32_t skipInterval,
        std::shared_ptr<RSNGShaderBase> shader,
        uint32_t bgColorA, uint32_t bgColorB)
    {
        std::cout << "\n=== " << label << " ===" << std::endl;

        if (shader) {
            shader->EnableCache(level, {mode, skipInterval});
        }
        canvasNode_->SetBackgroundNGShader(shader);
        canvasNode_->SetBackgroundColor(bgColorA);
        rsUiDirector_->SendMessages();
        rsUiDirector_->FlushModifier();
        std::cout << "  shader set (fixed), bg color A (expect miss+update)" << std::endl;

        RSAnimationTimingProtocol protocol;
        protocol.SetDuration(ANIMATION_DURATION_MS);
        protocol.SetRepeatCount(-1);

        RSNode::Animate(uiContext_, protocol, RSAnimationTimingCurve::EASE_IN_OUT, [&]() {
            canvasNode_->SetBackgroundColor(bgColorB);
        });

        rsUiDirector_->SendMessages();
        rsUiDirector_->FlushModifier();
        std::cout << "  bg color A<->B started (shader fixed, expect cache hit)" << std::endl;

        sleep(ANIMATION_DURATION_MS / MS_PER_SECOND * OBSERVE_ANIMATION_CYCLES);

        RSNode::CloseImplicitAnimation(uiContext_);
        std::cout << "  animation stopped" << std::endl;
    }

    // Shader params are fixed but node position animates, causing canvasHash to
    // change every frame. This makes condHash false, so FIXED_INTERVAL skip logic
    // is exercised: miss+update → skipInterval hits → miss+update → ...
    void TestSkipFrameFixed(const char* label, RSFrameCacheLevel level,
        RSFrameSkipMode mode, uint32_t skipInterval,
        std::shared_ptr<RSNGShaderBase> shader)
    {
        std::cout << "\n=== " << label << " ===" << std::endl;

        if (shader) {
            shader->EnableCache(level, {mode, skipInterval});
        }
        canvasNode_->SetBackgroundNGShader(shader);
        canvasNode_->SetBounds(0, 0, WINDOW_WIDTH, WINDOW_HEIGHT);
        rsUiDirector_->SendMessages();
        rsUiDirector_->FlushModifier();
        std::cout << "  shader set (fixed), skipInterval=" << skipInterval
                  << " (expect miss+update every " << (skipInterval + 1) << " frames)" << std::endl;

        RSAnimationTimingProtocol protocol;
        protocol.SetDuration(ANIMATION_DURATION_MS);
        protocol.SetRepeatCount(-1);

        RSNode::Animate(uiContext_, protocol, RSAnimationTimingCurve::EASE_IN_OUT,
            [&]() { canvasNode_->SetBounds(ANIMATED_NODE_OFFSET, ANIMATED_NODE_OFFSET, WINDOW_WIDTH, WINDOW_HEIGHT); });

        rsUiDirector_->SendMessages();
        rsUiDirector_->FlushModifier();
        std::cout << "  position animation started (shader fixed, canvasHash changes)" << std::endl;

        sleep(ANIMATION_DURATION_MS / MS_PER_SECOND * OBSERVE_ANIMATION_CYCLES);

        RSNode::CloseImplicitAnimation(uiContext_);
        canvasNode_->SetBackgroundNGShader(nullptr);
        rsUiDirector_->SendMessages();
        rsUiDirector_->FlushModifier();
        std::cout << "  test done" << std::endl;
    }

    // FIXED_INTERVAL with shader and canvas both stable. condHash is always
    // true, so every frame hits after the initial miss+update. This verifies
    // that FIXED_INTERVAL mode does not break the normal content-hit path.
    void TestSkipFrameNoAnim(const char* label, RSFrameCacheLevel level,
        RSFrameSkipMode mode, uint32_t skipInterval,
        std::shared_ptr<RSNGShaderBase> shader)
    {
        std::cout << "\n=== " << label << " ===" << std::endl;

        if (shader) {
            shader->EnableCache(level, {mode, skipInterval});
        }
        canvasNode_->SetBackgroundNGShader(shader);
        rsUiDirector_->SendMessages();
        rsUiDirector_->FlushModifier();
        std::cout << "  shader set (fixed, no animation), skipInterval=" << skipInterval
                  << " (expect first miss+update, then all hits)" << std::endl;

        sleep(ANIMATION_DURATION_MS / MS_PER_SECOND * OBSERVE_ANIMATION_CYCLES);

        canvasNode_->SetBackgroundNGShader(nullptr);
        rsUiDirector_->SendMessages();
        rsUiDirector_->FlushModifier();
        std::cout << "  test done" << std::endl;
    }

    // Shader states
    std::shared_ptr<RSNGShaderBase> ShaderStateA()
    {
        return CreateGradientShader(
            Vector4f(1.0f, 0.0f, 0.0f, 1.0f), Vector4f(0.0f, 0.0f, 1.0f, 1.0f));
    }
    std::shared_ptr<RSNGShaderBase> ShaderStateB()
    {
        return CreateGradientShader(
            Vector4f(0.0f, 1.0f, 0.0f, 1.0f), Vector4f(1.0f, 1.0f, 0.0f, 1.0f));
    }
    std::shared_ptr<RSNGShaderBase> ChainStateA()
    {
        return CreateGradientChain(
            Vector4f(1.0f, 0.0f, 0.0f, 1.0f), Vector4f(0.0f, 0.0f, 1.0f, 1.0f),
            Vector4f(0.5f, 0.0f, 1.0f, 1.0f), Vector4f(1.0f, 0.5f, 0.0f, 1.0f));
    }
    std::shared_ptr<RSNGShaderBase> ChainStateB()
    {
        return CreateGradientChain(
            Vector4f(0.0f, 1.0f, 0.0f, 1.0f), Vector4f(1.0f, 1.0f, 0.0f, 1.0f),
            Vector4f(0.0f, 0.5f, 1.0f, 1.0f), Vector4f(1.0f, 0.0f, 0.5f, 1.0f));
    }
    // Chain where effect A is always red→blue (fixed), only effect B changes
    std::shared_ptr<RSNGShaderBase> ChainOnlyBChangeA()
    {
        return CreateGradientChain(
            Vector4f(1.0f, 0.0f, 0.0f, 1.0f), Vector4f(0.0f, 0.0f, 1.0f, 1.0f),
            Vector4f(0.0f, 1.0f, 0.0f, 1.0f), Vector4f(1.0f, 1.0f, 0.0f, 1.0f));
    }
    std::shared_ptr<RSNGShaderBase> ChainOnlyBChangeB()
    {
        return CreateGradientChain(
            Vector4f(1.0f, 0.0f, 0.0f, 1.0f), Vector4f(0.0f, 0.0f, 1.0f, 1.0f),
            Vector4f(1.0f, 0.0f, 1.0f, 1.0f), Vector4f(0.0f, 1.0f, 1.0f, 1.0f));
    }

    bool InitDirector()
    {
        auto screenId = RSInterfaces::GetInstance().GetDefaultScreenId();
        connectToRender_ = RSInterfaces::GetInstance().GetConnectToRenderToken(screenId);
        rsUiDirector_ = RSUIDirector::Create(connectToRender_);
        if (!rsUiDirector_) {
            return false;
        }
        uiContext_ = rsUiDirector_->GetRSUIContext();
        return uiContext_ != nullptr;
    }

    bool InitSurfaceNode()
    {
        RSSurfaceNodeConfig surfaceNodeConfig;
        surfaceNodeConfig.SurfaceNodeName = "shader_cache_demo";
        surfaceNode_ = RSSurfaceNode::Create(surfaceNodeConfig,
            RSSurfaceNodeType::APP_WINDOW_NODE, true, false, uiContext_);
        if (!surfaceNode_) {
            return false;
        }
        surfaceNode_->SetFrameGravity(Gravity::RESIZE_ASPECT_FILL);
        surfaceNode_->SetBounds(0, 0, WINDOW_WIDTH, WINDOW_HEIGHT);
        surfaceNode_->SetFrame(0, 0, WINDOW_WIDTH, WINDOW_HEIGHT);
        surfaceNode_->SetPositionZ(RSSurfaceNode::POINTER_WINDOW_POSITION_Z);
        surfaceNode_->SetBackgroundColor(SK_ColorWHITE);
        surfaceNode_->AttachToDisplay(SCREEN_ID);
        rsUiDirector_->SetRSSurfaceNode(surfaceNode_);
        return true;
    }

    bool InitRootNode()
    {
        rootNode_ = RSRootNode::Create(false, false, uiContext_);
        if (!rootNode_) {
            return false;
        }
        rootNode_->SetBounds(0, 0, WINDOW_WIDTH, WINDOW_HEIGHT);
        rootNode_->SetFrame(0, 0, WINDOW_WIDTH, WINDOW_HEIGHT);
        rsUiDirector_->SetRSRootNode(rootNode_->ReinterpretCastTo<RSRootNode>());
        return true;
    }

    sptr<IRemoteObject> connectToRender_;
    std::shared_ptr<RSUIDirector> rsUiDirector_;
    std::shared_ptr<RSUIContext> uiContext_;
    std::shared_ptr<RSTransactionHandler> transaction_;
    std::shared_ptr<RSSurfaceNode> surfaceNode_;
    std::shared_ptr<RSNode> rootNode_;
    RSCanvasNode::SharedPtr canvasNode_;
    bool initSuccess_ = false;
};
} // namespace

int main(int argc, char* argv[])
{
    int testCase = 0;
    if (argc > 1) {
        testCase = std::atoi(argv[1]);
    }
    {
        ShaderCacheDemo demo;
        demo.Run(testCase);
    }
    return 0;
}
