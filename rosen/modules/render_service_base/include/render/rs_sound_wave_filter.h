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
#ifndef RENDER_SERVICE_BASE_RENDER_RS_SOUND_WAVE_FILTER_H
#define RENDER_SERVICE_BASE_RENDER_RS_SOUND_WAVE_FILTER_H

#include <memory>
#include "common/rs_color_palette.h"
#include "render/rs_shader_filter.h"

namespace OHOS {
namespace Rosen {
class RSB_EXPORT RSSoundWaveFilter : public RSShaderFilter {
public:
    RSSoundWaveFilter(Vector4f colorA, Vector4f colorB, Vector4f colorC,
                      float colorProgress, float soundIntensity,
                      float shockWaveAlphaA, float shockWaveAlphaB,
                      float shockWaveProgressA, float shockWaveProgressB, float shockWaveTotalAlpha);
    RSSoundWaveFilter(const RSSoundWaveFilter&) = delete;
    RSSoundWaveFilter operator=(const RSSoundWaveFilter&) = delete;
    ~RSSoundWaveFilter() override;

    float GetColorProgress() const;
    float GetSoundIntensity() const;
    float GetShockWaveAlphaA() const;
    float GetShockWaveAlphaB() const;
    float GetShockWaveProgressA() const;
    float GetShockWaveProgressB() const;
    float GetShockWaveTotalAlpha() const;

    void GenerateGEVisualEffect(std::shared_ptr<Drawing::GEVisualEffectContainer> visualEffectContainer) override;

private:
    static constexpr char GE_FILTER_SOUND_WAVE_COLOR_A[] = "COLORA";
    static constexpr char GE_FILTER_SOUND_WAVE_COLOR_B[] = "COLORB";
    static constexpr char GE_FILTER_SOUND_WAVE_COLOR_C[] = "COLORC";
    static constexpr char GE_FILTER_SOUND_WAVE_COLORPROGRESS[] = "COLORPROGRESS";
    static constexpr char GE_FILTER_SOUND_WAVE_SOUNDINTENSITY[] = "SOUNDINTENSITY";
    static constexpr char GE_FILTER_SOUND_WAVE_SHOCKWAVEALPHA_A[] = "SHOCKWAVEALPHAA";
    static constexpr char GE_FILTER_SOUND_WAVE_SHOCKWAVEALPHA_B[] = "SHOCKWAVEALPHAB";
    static constexpr char GE_FILTER_SOUND_WAVE_SHOCKWAVEPROGRESS_A[] = "SHOCKWAVEPROGRESSA";
    static constexpr char GE_FILTER_SOUND_WAVE_SHOCKWAVEPROGRESS_B[] = "SHOCKWAVEPROGRESSB";
    static constexpr char GE_FILTER_SOUND_WAVE_TOTAL_ALPHA[] = "SHOCKWAVETOTALALPHA";

    // sound wave
    Drawing::Color4f colorA_ = { 1.0f, 1.0f, 1.0f, 1.0f };
    Drawing::Color4f colorB_ = { 1.0f, 1.0f, 1.0f, 1.0f };
    Drawing::Color4f colorC_ = { 1.0f, 1.0f, 1.0f, 1.0f };
    float colorProgress_ = 0.0f;
    float soundIntensity_ = 0.0f;

    // shock wave
    float shockWaveAlphaA_ = 1.0f;
    float shockWaveAlphaB_ = 1.0f;
    float shockWaveProgressA_ = 0.0f;
    float shockWaveProgressB_ = 0.0f;
    float shockWaveTotalAlpha_ = 0.0f;
};
} // namespace Rosen
} // namespace OHOS

#endif // RENDER_SERVICE_BASE_RENDER_RS_SOUND_WAVE_FILTER_H