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

#include "skia_color_space.h"

#include "skia_image.h"

#include "image/image.h"

namespace OHOS {
namespace Rosen {
namespace Drawing {
SkiaColorSpace::SkiaColorSpace() noexcept : colorSpace_(nullptr) {}

void SkiaColorSpace::InitWithSRGB()
{
    colorSpace_ = SkColorSpace::MakeSRGB();
}

void SkiaColorSpace::InitWithSRGBLinear()
{
    colorSpace_ = SkColorSpace::MakeSRGBLinear();
}

void SkiaColorSpace::InitWithImage(const Image& image)
{
    auto i = image.GetImpl<SkiaImage>();
    if (i != nullptr) {
        const sk_sp<SkImage> skiaImage = i->GetImage();
        colorSpace_ = skiaImage->refColorSpace();
    }
}

static inline skcms_TransferFunction ConvertToSkCMSTransferFunction(const CMSTransferFuncType& func)
{
    switch (func) {
        case CMSTransferFuncType::SRGB:
            return SkNamedTransferFn::kSRGB;
        case CMSTransferFuncType::DOT2:
            return SkNamedTransferFn::k2Dot2;
        case CMSTransferFuncType::LINEAR:
            return SkNamedTransferFn::kLinear;
        case CMSTransferFuncType::REC2020:
            return SkNamedTransferFn::kRec2020;
        default:
            return SkNamedTransferFn::kSRGB;
    }
}

static inline skcms_Matrix3x3 ConvertToSkCMSMatrix3x3(const CMSMatrixType& matrix)
{
    switch (matrix) {
        case CMSMatrixType::SRGB:
            return SkNamedGamut::kSRGB;
        case CMSMatrixType::ADOBE_RGB:
            return SkNamedGamut::kAdobeRGB;
        case CMSMatrixType::DCIP3:
            return SkNamedGamut::kDCIP3;
        case CMSMatrixType::REC2020:
            return SkNamedGamut::kRec2020;
        case CMSMatrixType::XYZ:
            return SkNamedGamut::kXYZ;
        default:
            return SkNamedGamut::kSRGB;
    }
}

void SkiaColorSpace::InitWithRGB(const CMSTransferFuncType& func, const CMSMatrixType& matrix)
{
    colorSpace_ = SkColorSpace::MakeRGB(ConvertToSkCMSTransferFunction(func), ConvertToSkCMSMatrix3x3(matrix));
}

sk_sp<SkColorSpace> SkiaColorSpace::GetColorSpace() const
{
    return colorSpace_;
}
} // namespace Drawing
} // namespace Rosen
} // namespace OHOS