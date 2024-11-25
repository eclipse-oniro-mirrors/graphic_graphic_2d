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

#include "image/bitmap.h"

#include "impl_factory.h"

namespace OHOS {
namespace Rosen {
namespace Drawing {
Bitmap::Bitmap()
    : bmpImplPtr(ImplFactory::CreateBitmapImpl())
{}

Bitmap::~Bitmap() {}

bool Bitmap::Build(int32_t width, int32_t height, const BitmapFormat& format,
    int32_t stride, std::shared_ptr<Drawing::ColorSpace> colorSpace)
{
    return bmpImplPtr->Build(width, height, format, stride, colorSpace);
}

bool Bitmap::Build(const ImageInfo& imageInfo, int32_t stride)
{
    return bmpImplPtr->Build(imageInfo, stride);
}

int Bitmap::GetWidth() const
{
    return bmpImplPtr->GetWidth();
}

int Bitmap::GetHeight() const
{
    return bmpImplPtr->GetHeight();
}

int Bitmap::GetRowBytes() const
{
    return bmpImplPtr->GetRowBytes();
}

ColorType Bitmap::GetColorType() const
{
    return bmpImplPtr->GetColorType();
}

AlphaType Bitmap::GetAlphaType() const
{
    return bmpImplPtr->GetAlphaType();
}

bool Bitmap::PeekPixels(Pixmap& pixmap) const
{
    return bmpImplPtr->PeekPixels(pixmap);
}

size_t Bitmap::ComputeByteSize() const
{
    return bmpImplPtr->ComputeByteSize();
}

void Bitmap::SetPixels(void* pixel)
{
    bmpImplPtr->SetPixels(pixel);
}

bool Bitmap::ExtractSubset(Bitmap& dst, const Rect& subset) const
{
    return bmpImplPtr->ExtractSubset(dst, subset);
}

bool Bitmap::ReadPixels(const ImageInfo& dstInfo, void* dstPixels, size_t dstRowBytes,
    int32_t srcX, int32_t srcY) const
{
    return bmpImplPtr->ReadPixels(dstInfo, dstPixels, dstRowBytes, srcX, srcY);
}

void* Bitmap::GetPixels() const
{
    return bmpImplPtr->GetPixels();
}

void Bitmap::CopyPixels(Bitmap& dst, int srcLeft, int srcTop) const
{
    bmpImplPtr->CopyPixels(dst, srcLeft, srcTop);
}

bool Bitmap::InstallPixels(const ImageInfo& info, void* pixels, size_t rowBytes,
    ReleaseProc releaseProc, void* context)
{
    return bmpImplPtr->InstallPixels(info, pixels, rowBytes, releaseProc, context);
}

bool Bitmap::IsImmutable()
{
    return bmpImplPtr->IsImmutable();
}

void Bitmap::SetImmutable()
{
    bmpImplPtr->SetImmutable();
}

void Bitmap::ClearWithColor(const ColorQuad& color) const
{
    bmpImplPtr->ClearWithColor(color);
}

bool Bitmap::IsValid() const
{
    return bmpImplPtr->IsValid();
}

bool Bitmap::IsEmpty() const
{
    return bmpImplPtr->IsEmpty();
}

ColorQuad Bitmap::GetColor(int x, int y) const
{
    return bmpImplPtr->GetColor(x, y);
}

void Bitmap::Free()
{
    bmpImplPtr->Free();
}

BitmapFormat Bitmap::GetFormat() const
{
    ImageInfo imageInfo = GetImageInfo();
    return {imageInfo.GetColorType(), imageInfo.GetAlphaType()};
}

void Bitmap::SetFormat(const BitmapFormat& format)
{
    ImageInfo imageinfo = GetImageInfo();
    imageinfo.SetColorType(format.colorType);
    imageinfo.SetAlphaType(format.alphaType);
    SetInfo(imageinfo);
}

void Bitmap::SetInfo(const ImageInfo& info)
{
    bmpImplPtr->SetInfo(info);
}

ImageInfo Bitmap::GetImageInfo() const
{
    return bmpImplPtr->GetImageInfo();
}

Pixmap Bitmap::GetPixmap() const
{
    return bmpImplPtr->GetPixmap();
}

std::shared_ptr<Image> Bitmap::MakeImage() const
{
    return bmpImplPtr->MakeImage();
}

bool Bitmap::TryAllocPixels(const ImageInfo& info)
{
    return bmpImplPtr->TryAllocPixels(info);
}

std::shared_ptr<Data> Bitmap::Serialize() const
{
    return bmpImplPtr->Serialize();
}

bool Bitmap::Deserialize(std::shared_ptr<Data> data)
{
    return bmpImplPtr->Deserialize(data);
}

} // namespace Drawing
} // namespace Rosen
} // namespace OHOS
