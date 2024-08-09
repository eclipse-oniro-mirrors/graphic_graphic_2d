/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include "draw/brush.h"

#include "static_factory.h"

namespace OHOS {
namespace Rosen {
namespace Drawing {
Brush::Brush() noexcept
    : color_(),
      blendMode_(BlendMode::SRC_OVER),
      filter_(),
      colorSpace_(nullptr),
      shaderEffect_(nullptr),
      blender_(nullptr),
      blurDrawLooper_(nullptr),
      antiAlias_(false)
{}

Brush::Brush(const Color& c) noexcept
    : color_(c),
      blendMode_(BlendMode::SRC_OVER),
      filter_(),
      colorSpace_(nullptr),
      shaderEffect_(nullptr),
      blender_(nullptr),
      blurDrawLooper_(nullptr),
      antiAlias_(false)
{}

Brush::Brush(int rgba) noexcept
    : color_(rgba),
      blendMode_(BlendMode::SRC_OVER),
      filter_(),
      colorSpace_(nullptr),
      shaderEffect_(nullptr),
      blender_(nullptr),
      blurDrawLooper_(nullptr),
      antiAlias_(false)
{}

Brush::Brush(std::shared_ptr<ShaderEffect> e) noexcept
    : color_(), blendMode_(BlendMode::SRC_OVER), filter_(), colorSpace_(nullptr), shaderEffect_(e), blender_(nullptr),
    blurDrawLooper_(nullptr), antiAlias_(false)
{}

const Color& Brush::GetColor() const
{
    return color_;
}

void Brush::SetColor(const Color& c)
{
    color_ = c;
}

void Brush::SetColor(uint32_t c)
{
    color_.SetColorQuad(c);
}

void Brush::SetARGB(int a, int r, int g, int b)
{
    color_.SetRgb(r, g, b, a);
}

const Color4f& Brush::GetColor4f()
{
    return color_.GetColor4f();
}

void Brush::SetColor(const Color4f& cf, std::shared_ptr<ColorSpace> s)
{
    color_.SetRgbF(cf.redF_, cf.greenF_, cf.blueF_, cf.alphaF_);
    colorSpace_ = s;
}

void Brush::SetAlpha(uint32_t a)
{
    color_.SetAlpha(a);
}

void Brush::SetAlphaF(scalar a)
{
    color_.SetAlphaF(a);
}

void Brush::SetBlendMode(const BlendMode& mode)
{
    blendMode_ = mode;
}

void Brush::SetFilter(const Filter& filter)
{
    filter_ = filter;
    hasFilter_ = true;
}

const Filter& Brush::GetFilter() const
{
    return filter_;
}

void Brush::SetShaderEffect(std::shared_ptr<ShaderEffect> e)
{
    shaderEffect_ = e;
}

void Brush::SetLooper(std::shared_ptr<BlurDrawLooper> blurDrawLooper)
{
    blurDrawLooper_ = blurDrawLooper;
}

std::shared_ptr<BlurDrawLooper> Brush::GetLooper() const
{
    return blurDrawLooper_;
}

void Brush::SetBlender(std::shared_ptr<Blender> blender)
{
    blender_ = blender;
}

void Brush::SetBlenderEnabled(bool blenderEnabled)
{
    blenderEnabled_ = blenderEnabled;
}

bool Brush::IsAntiAlias() const
{
    return antiAlias_;
}

void Brush::SetAntiAlias(bool aa)
{
    antiAlias_ = aa;
}

bool Brush::CanComputeFastBounds()
{
    return StaticFactory::CanComputeFastBounds(*this);
}

const Rect& Brush::ComputeFastBounds(const Rect& orig, Rect* storage)
{
    return StaticFactory::ComputeFastBounds(*this, orig, storage);
}

void Brush::Reset()
{
    *this = Brush();
}

bool Brush::AsBlendMode()
{
    return StaticFactory::AsBlendMode(*this);
}

/**
 * In these cases, disable HDR paintfilter by setting forceBrightnessDisable_ as true:
 * 1. Filter(effect): HDR paintfilter is already applied when take snapshot.
 * 2. UIFirst: Disable main thread since sub thread is already applied.
*/
void Brush::SetForceBrightnessDisable(bool forceBrightnessDisable)
{
    forceBrightnessDisable_ = forceBrightnessDisable;
}

bool Brush::IsHdr() const
{
    return isHdr_;
}

void Brush::SetHdr(bool isHdr)
{
    isHdr_ = isHdr;
}

bool operator==(const Brush& b1, const Brush& b2)
{
    return b1.color_ == b2.color_ && b1.blendMode_ == b2.blendMode_ && b1.shaderEffect_ == b2.shaderEffect_ &&
        b1.blender_ == b2.blender_ && b1.blenderEnabled_ == b2.blenderEnabled_ && b1.colorSpace_ == b2.colorSpace_ &&
        b1.filter_ == b2.filter_ && b1.antiAlias_ == b2.antiAlias_ && b1.blurDrawLooper_ == b2.blurDrawLooper_ &&
        b1.isHdr_ == b2.isHdr_;
}

bool operator!=(const Brush& b1, const Brush& b2)
{
    return !(b1 == b2);
}

void Brush::Dump(std::string& out)
{
    out += "color[";
    color_.Dump(out);
    out += "]";
    out += " blendMode:" + std::to_string(static_cast<int>(blendMode_));
    out += " filter[";
    filter_.Dump(out);
    out += "]";
    if (colorSpace_ != nullptr) {
        out += " colorSpaceType:" + std::to_string(static_cast<int>(colorSpace_->GetType()));
    }
    if (shaderEffect_ != nullptr) {
        out += " shaderEffectType:" + std::to_string(static_cast<int>(shaderEffect_->GetType()));
    }
    out += " isAntiAlias:" + std::to_string(antiAlias_);
    out += " blenderEnabled:" + std::to_string(blenderEnabled_);
    out += " hasFilter:" + std::to_string(hasFilter_);
    out += " forceBrightnessDisable:" + std::to_string(forceBrightnessDisable_);
    out += " isHDR:" + std::to_string(isHdr_);
}

} // namespace Drawing
} // namespace Rosen
} // namespace OHOS
