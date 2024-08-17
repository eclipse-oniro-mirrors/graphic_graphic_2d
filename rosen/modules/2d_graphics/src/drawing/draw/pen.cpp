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

#include "draw/pen.h"

#include "static_factory.h"

namespace OHOS {
namespace Rosen {
namespace Drawing {
Pen::Pen() noexcept
    : width_(0),
      miterLimit_(-1),
      join_(Pen::JoinStyle::MITER_JOIN),
      cap_(Pen::CapStyle::FLAT_CAP),
      pathEffect_(nullptr),
      brush_()
{}

Pen::Pen(const Color& c) noexcept : Pen()
{
    brush_.SetColor(c);
}

Pen::Pen(int rgba) noexcept : Pen()
{
    brush_.SetColor(rgba);
}

Color Pen::GetColor() const
{
    return brush_.GetColor();
}

void Pen::SetColor(const Color& c)
{
    brush_.SetColor(c);
}

void Pen::SetColor(uint32_t c)
{
    brush_.SetColor(c);
}

void Pen::SetARGB(int a, int r, int g, int b)
{
    return brush_.SetARGB(a, r, g, b);
}

const Color4f& Pen::GetColor4f()
{
    return brush_.GetColor4f();
}

const std::shared_ptr<ColorSpace> Pen::GetColorSpace() const
{
    return brush_.GetColorSpace();
}

const ColorSpace* Pen::GetColorSpacePtr() const
{
    return brush_.GetColorSpacePtr();
}

void Pen::SetColor(const Color4f& cf, std::shared_ptr<ColorSpace> s)
{
    brush_.SetColor(cf, s);
}

uint32_t Pen::GetAlpha() const
{
    return brush_.GetAlpha();
}

scalar Pen::GetAlphaF() const
{
    return brush_.GetAlphaF();
}

void Pen::SetAlpha(uint32_t a)
{
    return brush_.SetAlpha(a);
}

void Pen::SetAlphaF(scalar a)
{
    return brush_.SetAlphaF(a);
}

scalar Pen::GetWidth() const
{
    return width_;
}

void Pen::SetWidth(scalar width)
{
    width_ = width;
}

scalar Pen::GetMiterLimit() const
{
    return miterLimit_;
}

void Pen::SetMiterLimit(scalar limit)
{
    miterLimit_ = limit;
}

Pen::CapStyle Pen::GetCapStyle() const
{
    return cap_;
}

void Pen::SetCapStyle(CapStyle cs)
{
    cap_ = cs;
}

Pen::JoinStyle Pen::GetJoinStyle() const
{
    return join_;
}

void Pen::SetJoinStyle(JoinStyle js)
{
    join_ = js;
}

BlendMode Pen::GetBlendMode() const
{
    return brush_.GetBlendMode();
}

void Pen::SetBlendMode(BlendMode mode)
{
    return brush_.SetBlendMode(mode);
}

void Pen::SetBlender(std::shared_ptr<Blender> blender)
{
    brush_.SetBlender(blender);
}

void Pen::SetBlenderEnabled(bool blenderEnabled)
{
    blenderEnabled_ = blenderEnabled;
}

std::shared_ptr<Blender> Pen::GetBlender() const
{
    return brush_.GetBlender();
}

const Blender* Pen::GetBlenderPtr() const
{
    return brush_.GetBlenderPtr();
}

bool Pen::IsAntiAlias() const
{
    return brush_.IsAntiAlias();
}

void Pen::SetAntiAlias(bool aa)
{
    brush_.SetAntiAlias(aa);
}

void Pen::SetPathEffect(std::shared_ptr<PathEffect> e)
{
    pathEffect_ = e;
}

std::shared_ptr<PathEffect> Pen::GetPathEffect() const
{
    return pathEffect_;
}

const PathEffect* Pen::GetPathEffectPtr() const
{
    return pathEffect_.get();
}

void Pen::SetFilter(const Filter& filter)
{
    brush_.SetFilter(filter);
}

const Filter& Pen::GetFilter() const
{
    return brush_.GetFilter();
}

bool Pen::HasFilter() const
{
    return brush_.HasFilter();
}

void Pen::SetShaderEffect(std::shared_ptr<ShaderEffect> e)
{
    brush_.SetShaderEffect(e);
}

std::shared_ptr<ShaderEffect> Pen::GetShaderEffect() const
{
    return brush_.GetShaderEffect();
}

const ShaderEffect* Pen::GetShaderEffectPtr() const
{
    return brush_.GetShaderEffectPtr();
}

void Pen::Reset()
{
    *this = Pen();
}

void Pen::SetLooper(std::shared_ptr<BlurDrawLooper> blurDrawLooper)
{
    brush_.SetLooper(blurDrawLooper);
}

std::shared_ptr<BlurDrawLooper> Pen::GetLooper() const
{
    return brush_.GetLooper();
}

bool Pen::GetFillPath(const Path& src, Path& dst, const Rect* rect, const Matrix& matrix)
{
    return StaticFactory::GetFillPath(*this, src, dst, rect, matrix);
}

bool operator==(const Pen& p1, const Pen& p2)
{
    return p1.width_ == p2.width_ && p1.miterLimit_ == p2.miterLimit_ && p1.join_ == p2.join_ && p1.cap_ == p2.cap_ &&
        p1.pathEffect_ == p2.pathEffect_ && p1.brush_ == p2.brush_;
}

bool operator!=(const Pen& p1, const Pen& p2)
{
    return !(p1 == p2);
}
} // namespace Drawing
} // namespace Rosen
} // namespace OHOS
