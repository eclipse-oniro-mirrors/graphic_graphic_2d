/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "color_picker.h"
#include "hilog/log.h"
#include "effect_errors.h"
#include "effect_utils.h"
#include "color.h"
#include "pixel_map.h"
#include "include/core/SkBitmap.h"
#include "include/core/SkRect.h"
#include "include/core/SkImageFilter.h"
#include "include/effects/SkImageFilters.h"
#include "include/core/SkCanvas.h"
#include "include/core/SkColor.h"
#include "include/core/SkColorFilter.h"
#include "include/core/SkColorSpace.h"
#include "include/core/SkImageInfo.h"
#include "include/core/SkPaint.h"
#include "include/core/SkPixmap.h"
#include "include/core/SkFont.h"
#include "include/core/SkTypeface.h"
#include <math.h>
#include <utility>

#ifdef __cplusplus
extern "C" {
#endif

namespace OHOS {
namespace Rosen {
using OHOS::HiviewDFX::HiLog;

std::shared_ptr<ColorPicker> ColorPicker::CreateColorPicker(const std::shared_ptr<Media::PixelMap>& pixmap,
    uint32_t &errorCode)
{
    if (pixmap == nullptr) {
        HiLog::Info(LABEL, "[ColorPicker]failed to create ColorPicker with null pixmap.");
        errorCode = ERR_EFFECT_INVALID_VALUE;
        return nullptr;
    }
    ColorPicker *colorPicker = new (std::nothrow) ColorPicker(pixmap);
    if (colorPicker == nullptr) {
        HiLog::Info(LABEL, "[ColorPicker]failed to create ColorPicker with pixmap.");
        errorCode = ERR_EFFECT_INVALID_VALUE;
        return nullptr;
    }

    errorCode = SUCCESS;
    return std::shared_ptr<ColorPicker>(colorPicker);
}

std::shared_ptr<Media::PixelMap> ColorPicker::GetScaledPixelMap()
{
    // Create scaled pixelmap
    OHOS::Media::InitializationOptions options;
    options.alphaType = pixelmap_->GetAlphaType();
    options.pixelFormat = pixelmap_->GetPixelFormat();
    options.scaleMode = OHOS::Media::ScaleMode::FIT_TARGET_SIZE;
    options.size.width = 1;
    options.size.height = 1;
    options.editable = true;
    std::unique_ptr<Media::PixelMap> newPixelMap = Media::PixelMap::Create(*pixelmap_.get(), options);
    return std::move(newPixelMap);
}

uint32_t ColorPicker::GetMainColor(ColorManager::Color &color)
{
    if (pixelmap_ == nullptr) {
        return ERR_EFFECT_INVALID_VALUE;
    }
    std::shared_ptr<Media::PixelMap> pixelMap = GetScaledPixelMap();

    // get color
    uint32_t colorVal = 0;
    int x = 0;
    int y = 0;
    bool bSucc = pixelMap->GetARGB32Color(x, y, colorVal);
    HiLog::Info(LABEL, "[newpix].argb.ret=%{public}d, %{public}x", bSucc, colorVal);
    color = ColorManager::Color(colorVal);
    return SUCCESS;
}

ColorPicker::ColorPicker(std::shared_ptr<Media::PixelMap> pixmap):ColorExtract(pixmap) {}



// 选取数量占比最多的颜色
uint32_t ColorPicker::GetLargestProportionColor(ColorManager::Color &color) const
{
    if (featureColors.empty()) {
        return ERR_EFFECT_INVALID_VALUE;
    }
    color = ColorManager::Color(featureColors[0].first | 0xFF000000); // alpha = oxFF
    return SUCCESS;
}

// 选取饱和度最高的颜色
uint32_t ColorPicker::GetHighestSaturationColor(ColorManager::Color &color) const
{
    if (featureColors.empty()) {
        return ERR_EFFECT_INVALID_VALUE;
    }
    uint32_t colorPicked = 0;
    HSV hsv = {0};
    double maxSaturation = 0.0;
    for (int i = 0; i < featureColors.size(); i++) {
        hsv = RGB2HSV(featureColors[i].first);
        if (hsv.s > maxSaturation) {
            maxSaturation = hsv.s;
            colorPicked = featureColors[i].first;
        }
    }
    color = ColorManager::Color(colorPicked | 0xFF000000);
    return SUCCESS;
}


// 计算图片的平均颜色
uint32_t ColorPicker::GetAverageColor(ColorManager::Color &color) const
{
    uint32_t colorPicked = 0;
    uint32_t redSum = 0;
    uint32_t greenSum = 0;
    uint32_t blueSum = 0;
    int totalPixelNum = 0;
    if (featureColors.empty()) {
        return ERR_EFFECT_INVALID_VALUE;
    }
    for (int i = 0; i < featureColors.size(); i++) {
        totalPixelNum += featureColors[i].second;
        redSum += featureColors[i].second * ((featureColors[i].first >> ARGB_R_SHIFT) & ARGB_MASK);
        greenSum += featureColors[i].second * ((featureColors[i].first >> ARGB_G_SHIFT) & ARGB_MASK);
        blueSum += featureColors[i].second * ((featureColors[i].first >> ARGB_B_SHIFT) & ARGB_MASK);
    }
    uint32_t redMean = round(redSum / (float)totalPixelNum);
    uint32_t greenMean = round(greenSum / (float)totalPixelNum);
    uint32_t blueMean = round(blueSum / (float)totalPixelNum);
    colorPicked = redMean << ARGB_R_SHIFT | greenMean << ARGB_G_SHIFT | blueMean << ARGB_B_SHIFT;
    color = ColorManager::Color(colorPicked | 0xFF000000);
    return SUCCESS;

}

// 判别黑白灰颜色
bool ColorPicker::IsBlackOrWhiteOrGrayColor(uint32_t color) const
{
    HSV hsv = RGB2HSV(color);
    if ((hsv.v > 30 && hsv.s <= 5) || (hsv.v > 15 && hsv.v <= 30 && hsv.s <= 15) || (hsv.v <= 15)) {
        return true;
    }
    return false;
}

// 壁纸颜色深浅模式判别
// rgb值转化为明度
uint32_t ColorPicker::RGB2GRAY(uint32_t color) const
{
    uint32_t r = GetARGB32ColorR(color);
    uint32_t g = GetARGB32ColorG(color);
    uint32_t b = GetARGB32ColorB(color);
    return static_cast<uint32_t>(r * GRAY_RATIO_RED + g * GRAY_RATIO_GREEN + b * GRAY_RATIO_BLUE);

}
// 计算明度方差
uint32_t ColorPicker::CalcGrayVariance() const
{
    long long int grayVariance = 0;

    ColorManager::Color color;
    bool rst = GetAverageColor(color);
    if (rst != SUCCESS) {
        return ERR_EFFECT_INVALID_VALUE;
    }
    uint32_t averageColor = ((color.PackValue() >> 32) & 0xFFFFFFFF);
    uint32_t averageGray = RGB2GRAY(averageColor);
    for (int i = 0; i < featureColors.size(); i++) {
        grayVariance += pow(static_cast<long long int>(RGB2GRAY(featureColors[i].first)) - averageGray, 2) * featureColors[i].second;
    }
    grayVariance /= colorValLen_;
    return static_cast<uint32_t>(grayVariance);
}

// 相对亮度计算，归一化为 0-1
double ColorPicker::CalcRelaticeLuminance(uint32_t color) const
{
    uint32_t r = GetARGB32ColorR(color);
    uint32_t g = GetARGB32ColorG(color);
    uint32_t b = GetARGB32ColorB(color);
    return (r * LUMINANCE_RATIO_RED + g * LUMINANCE_RATIO_GREEN + b * LUMINANCE_RATIO_BLUE) / 255;

}
double ColorPicker::CalcContrastRatioWithWhite() const
{
    double lightColorDegree = 0;
    for (int i = 0; i < featureColors.size(); i++) {
        lightColorDegree += ((1 + 0.05) / (CalcRelaticeLuminance(featureColors[i].first) + 0.05)) * featureColors[i].second;
    }
    lightColorDegree /= colorValLen_;
    return lightColorDegree;
}

uint32_t ColorPicker::DiscriminatePitureLightDegree(PictureLightColorDegree &degree) const
{
    if (featureColors.empty()) {
        return ERR_EFFECT_INVALID_VALUE;
    }
    uint32_t grayVariance = CalcGrayVariance();
    if (grayVariance < 6000) {
        double lightColorDegree = CalcContrastRatioWithWhite();
        if (lightColorDegree < 1.5) {
            degree = EXTREMELY_LIGHT_COLOR_PICTURE;
        } else if (lightColorDegree >= 1.5 && lightColorDegree < 1.9) {
            degree = LIGHT_COLOR_PICTURE;
        } else if (lightColorDegree >= 1.9 && lightColorDegree <= 7) {
            degree = FLOWERY_PICTURE;
        } else {
            if (grayVariance >= 3000) {
                degree = DARK_COLOR_PICTURE;
            } else {
                degree = EXTREMELY_DARK_COLOR_PICTURE;
            }
        }
    } else {
        degree = EXTREMELY_FLOWERY_PICTURE;
    }
    return SUCCESS;
}

// 深浅图片反色
uint32_t ColorPicker::GetReverseColor(ColorManager::Color &color) const
{
    PictureLightColorDegree lightColorDegree;
    bool rst = DiscriminatePitureLightDegree(lightColorDegree);
    if (rst != SUCCESS) {
        return ERR_EFFECT_INVALID_VALUE;
    }
    if (lightColorDegree == LIGHT_COLOR_PICTURE || lightColorDegree == EXTREMELY_LIGHT_COLOR_PICTURE) {
        uint32_t black = 0xFF000000;
        color = ColorManager::Color(black);
        return SUCCESS;  
    } else {
        uint32_t white = 0xFFFFFFFF;
        color = ColorManager::Color(white);
        return SUCCESS;
    }
};

// 莫兰迪背景取色
void ColorPicker::GenerateMorandiBackgroundColor(HSV& hsv) const
{
    hsv.s = 9;
    hsv.v = 84;
    return;
}

uint32_t ColorPicker::GetMorandiBackgroundColor(ColorManager::Color &color) const
{

    bool rst = GetLargestProportionColor(color);
    if (rst != SUCCESS) {
        return ERR_EFFECT_INVALID_VALUE;
    }
    uint32_t mostColor = ((color.PackValue() >> 32) & 0xFFFFFFFF);


    HSV hsv = RGB2HSV(mostColor);
    bool isBWGColor = IsBlackOrWhiteOrGrayColor(mostColor);
    if (isBWGColor) {
        uint32_t nextMostColor = 0;
        uint32_t nextMostColorCnt = 0;
        bool isExsitColor = false;
        for (int i = 0; i < featureColors.size(); i++) {
            if (!IsBlackOrWhiteOrGrayColor(featureColors[i].first) && featureColors[i].second > nextMostColorCnt) {
                nextMostColor = featureColors[i].first;
                nextMostColorCnt = featureColors[i].second;
                isExsitColor = true;
            }
        }
        if (isExsitColor) {
            HSV nextColorHsv = RGB2HSV(nextMostColor);
            GenerateMorandiBackgroundColor(nextColorHsv);
            nextMostColor = HSVtoRGB(nextColorHsv);
            color = ColorManager::Color(nextMostColor | 0xFF000000);
            return SUCCESS;
        } else {
            hsv.s = 0;
            hsv.v = 77;
            mostColor = HSVtoRGB(hsv);
            color = ColorManager::Color(mostColor | 0xFF000000);
            return SUCCESS;
        }
    } else {
        GenerateMorandiBackgroundColor(hsv);
        mostColor = HSVtoRGB(hsv);
        color = ColorManager::Color(mostColor | 0xFF000000);
        return SUCCESS;
    }
}


// 莫兰迪阴影取色
void ColorPicker::GenerateMorandiShadowColor(HSV& hsv) const
{
    if (hsv.h > 20 && hsv.h <= 60) {
        hsv.s = 53;
        hsv.v = 46;
    } else if (hsv.h > 60 && hsv.h <= 190) {
        hsv.s = 23;
        hsv.v = 36;
    } else if (hsv.h > 190 && hsv.h <= 270) {
        hsv.s = 34;
        hsv.v = 35;
    } else {
        hsv.s = 48;
        hsv.v = 40;
    }

}

uint32_t ColorPicker::GetMorandiShadowColor(ColorManager::Color &color) const
{
    bool rst = GetLargestProportionColor(color);
    if (rst != SUCCESS) {
        return ERR_EFFECT_INVALID_VALUE;
    }
    uint32_t mostColor = ((color.PackValue() >> 32) & 0xFFFFFFFF);

    HSV hsv = RGB2HSV(mostColor);
    bool isBWGColor = IsBlackOrWhiteOrGrayColor(mostColor);
    if (isBWGColor) {
        uint32_t nextMostColor = 0;
        uint32_t nextMostColorCnt = 0;
        bool isExsitColor = false;
        for (int i = 0; i < featureColors.size(); i++) {
            if (!IsBlackOrWhiteOrGrayColor(featureColors[i].first) && featureColors[i].second > nextMostColorCnt) {
                nextMostColor = featureColors[i].first;
                nextMostColorCnt = featureColors[i].second;
                isExsitColor = true;
            }
        }
        if (isExsitColor) {
            HSV nextColorHsv = RGB2HSV(nextMostColor);
            GenerateMorandiShadowColor(nextColorHsv);
            nextMostColor = HSVtoRGB(nextColorHsv);
            color = ColorManager::Color(nextMostColor | 0xFF000000);
            return SUCCESS;
        } else {
            hsv.s = 0;
            hsv.v = 26;
            mostColor = HSVtoRGB(hsv);
            color = ColorManager::Color(mostColor | 0xFF000000);
            return SUCCESS;
        }
    } else {
        GenerateMorandiShadowColor(hsv);
        mostColor = HSVtoRGB(hsv);
        color = ColorManager::Color(mostColor | 0xFF000000);
        return SUCCESS;
    }
}




// 沉浸式背景取色
ColorBrightnessMode ColorPicker::DiscriminateDarkOrBrightColor(const HSV& hsv) const
{
    if (hsv.v <= 80) {
        return ColorBrightnessMode::DARK_COLOR;
    } else {
        if (hsv.h > 20 && hsv.h <= 50) {
            if (hsv.s > 60) {
                return ColorBrightnessMode::HIGH_SATURATION_BRIGHT_COLOR;
            } else {
                return ColorBrightnessMode::LOW_SATURATION_BRIGHT_COLOR;
            }
        } else if (hsv.h > 50 && hsv.h <= 269) {
            if (hsv.s > 40) {
                return ColorBrightnessMode::DARK_COLOR;
            } else {
                return ColorBrightnessMode::LOW_SATURATION_BRIGHT_COLOR;
            }
        } else {
            if (hsv.s > 50) {
                return ColorBrightnessMode::HIGH_SATURATION_BRIGHT_COLOR;
            } else {
                return ColorBrightnessMode::LOW_SATURATION_BRIGHT_COLOR;
            }
        }
    }
}

void ColorPicker::ProcessToBrightColor(HSV& hsv) const
{
    if (hsv.v < 95) {
        return;
    } else {
        hsv.v = 95;
    }
}

void ColorPicker::AdjustToBasicColor(HSV& hsv, double basicS, double basicV) const
{
    double x = hsv.s + hsv.v;
    double y = basicS + basicV;
    if (x <= y) {
        return;
    } else {
        double z = x - y;
        hsv.s = hsv.s - hsv.s / x * z;
        hsv.v = hsv.v - hsv.v / x * z;
        return;
    }

}
void ColorPicker::ProcessToDarkColor(HSV& hsv) const
{
    if (hsv.h >= 18 && hsv.h <= 69) {
        AdjustToBasicColor(hsv, 70, 60);
    } else if (hsv.h > 69 && hsv.h <= 189) {
        AdjustToBasicColor(hsv, 50, 50);
    } else if (hsv.h > 189 && hsv.h <= 269) {
        AdjustToBasicColor(hsv, 70, 70);
    } else {
        AdjustToBasicColor(hsv, 60, 60);
    }
}



uint32_t ColorPicker::GetImmersiveBackgroundColor(ColorManager::Color &color) const
{
    uint32_t colorPicked = 0;
    HSV colorHsv;
    std::pair<uint32_t, uint32_t> mainColor;
    std::pair<uint32_t, uint32_t> secondaryColor;
    if (featureColors.empty()) {
        return ERR_EFFECT_INVALID_VALUE;
    }
    bool hasMainColor = GetDominantColor(mainColor, secondaryColor);
    HSV mainHsv = RGB2HSV(mainColor.first);
    HSV secondaryHsv = RGB2HSV(secondaryColor.first);
    if (hasMainColor || (mainHsv.s >= secondaryHsv.s)) {
        colorHsv = mainHsv;
    } else {
        colorHsv = secondaryHsv;
    }
    ColorBrightnessMode ColorBrightmode = DiscriminateDarkOrBrightColor(colorHsv);
    switch (ColorBrightmode) {
        case ColorBrightnessMode::HIGH_SATURATION_BRIGHT_COLOR:
            ProcessToDarkColor(colorHsv);
            break;
        case ColorBrightnessMode::LOW_SATURATION_BRIGHT_COLOR:
            if (colorHsv.s < 10) {
                ColorBrightnessMode secondaryColorBrightmode = DiscriminateDarkOrBrightColor(secondaryHsv);
                if (secondaryColorBrightmode == ColorBrightnessMode::LOW_SATURATION_BRIGHT_COLOR) {
                    ProcessToBrightColor(mainHsv);
                    colorHsv = mainHsv;
                } else {
                    if (mainColor.second - secondaryColor.second > colorValLen_ / 10) {
                        ProcessToBrightColor(mainHsv);
                        colorHsv = mainHsv;
                    } else {
                        secondaryHsv.s = 10;
                        secondaryHsv.v = 95;
                        colorHsv = secondaryHsv;
                    }
                }
            } else {
                ProcessToBrightColor(mainHsv);
                colorHsv = mainHsv;
            }

            break;
        case ColorBrightnessMode::DARK_COLOR:
            ProcessToDarkColor(colorHsv);
            break;
        default:
            break;
    }
    colorPicked = HSVtoRGB(colorHsv);
    color = ColorManager::Color(colorPicked | 0xFF000000);
    return SUCCESS;

}

// 沉浸式前景取色
uint32_t ColorPicker::GetImmersiveForegroundColor(ColorManager::Color &color) const
{
    // Get mask color
    bool rst = GetImmersiveBackgroundColor(color);
    if (rst != SUCCESS) {
        return ERR_EFFECT_INVALID_VALUE;
    }
    uint32_t colorPicked = ((color.PackValue() >> 32) & 0xFFFFFFFF);

    HSV colorHsv = RGB2HSV(colorPicked);
    ColorBrightnessMode ColorBrightmode = DiscriminateDarkOrBrightColor(colorHsv);
    if ((ColorBrightmode == ColorBrightnessMode::HIGH_SATURATION_BRIGHT_COLOR) || (ColorBrightmode == ColorBrightnessMode::DARK_COLOR)) {
        ProcessToDarkColor(colorHsv);
        if (colorHsv.s >= 20) {
            colorHsv.s = 20;
            colorHsv.v = 100;
        } else {
            colorHsv.v = 100;
        }
    } else {
        ProcessToBrightColor(colorHsv);
        colorHsv.s = 30;
        colorHsv.v = 40;
    }
    colorPicked = HSVtoRGB(colorHsv);
    color = ColorManager::Color(colorPicked | 0xFF000000);
    return SUCCESS;
}

bool ColorPicker::GetDominantColor(std::pair<uint32_t, uint32_t>& mainColor, std::pair<uint32_t, uint32_t >& secondaryColor) const
{
    if (featureColors.empty()) {
        mainColor.first = 0;
        mainColor.second = 0;
        secondaryColor.first = 0;
        secondaryColor.second = 0;
        return false;
    }
    if (featureColors.size() == 1) {
        mainColor.first = featureColors[0].first;
        mainColor.second = featureColors[0].second;
        secondaryColor.first = 0;
        secondaryColor.second = 0;
        return true;
    } else {
        mainColor.first = featureColors[0].first;
        mainColor.second = featureColors[0].second;
        secondaryColor.first = featureColors[1].first;
        secondaryColor.second = featureColors[1].second;
        if (mainColor.second - secondaryColor.second > colorValLen_ / 20) {
            return true;
        }
        return false;
    }
}

// 渐变蒙层取色--加深沉浸色（与背景融合却深于背景）
uint32_t ColorPicker::GetDeepenImmersionColor(ColorManager::Color &color) const
{
    uint32_t colorPicked = 0;
    std::pair<uint32_t, uint32_t> mainColor;
    std::pair<uint32_t, uint32_t> secondaryColor;
    if (featureColors.empty()) {
        return ERR_EFFECT_INVALID_VALUE;
    }
    bool hasMainColor = GetDominantColor(mainColor, secondaryColor);

    if (hasMainColor) {
        HSV hsv = RGB2HSV(mainColor.first);
        hsv.s += 35;
        if (hsv.s > 100) {
            hsv.s = 100;
        }
        if (hsv.v > 10) {
            hsv.v -= 40;
            if (hsv.v < 10) {
                hsv.v = 10;
            }
        }
        colorPicked = HSVtoRGB(hsv);

    } else {
        // If there is no dominant color, return black
        colorPicked = 0x00000000;
    }
    color = ColorManager::Color(colorPicked | 0xFF000000);
    return SUCCESS;
}


bool ColorPicker::IsEquals(double val1, double val2) const
{
    return fabs(val1 - val2) < 0.001;
}

// 将RGB格式转换为HSB格式
HSV ColorPicker::RGB2HSV(uint32_t rgb) const
{
    double r, g, b;
    double h, s, v;
    double minComponent, maxComponent;
    double delta;
    HSV hsv;

    r = GetARGB32ColorR(rgb) / 255.0;
    g = GetARGB32ColorG(rgb) / 255.0;
    b = GetARGB32ColorB(rgb) / 255.0;

    if (r > g) {
        maxComponent = std::max(r, b);
        minComponent = std::min(g, b);
    } else {
        maxComponent = std::max(g, b);
        minComponent = std::min(r, b);
    }

    v = maxComponent;
    delta = maxComponent - minComponent;

    if (IsEquals(maxComponent, 0))
        s = 0.0;
    else
        s = delta / maxComponent;

    if (maxComponent == minComponent) {
        h = 0.0;
    } else {
        if (IsEquals(r, maxComponent) && g >= b) {
            h = 60 * (g - b) / delta + 0;
        } else if (IsEquals(r, maxComponent) && g < b) {
            h = 60 * (g - b) / delta + 360;
        } else if (IsEquals(g, maxComponent)) {
            h = 60 * (b - r) / delta + 120;
        } else {
            h = 60 * (r - g) / delta + 240;
        }
    }

    hsv.h = (int)(h + 0.5);
    hsv.h = (hsv.h > 359) ? (hsv.h - 360) : hsv.h;
    hsv.h = (hsv.h < 0) ? (hsv.h + 360) : hsv.h;
    hsv.s = s * 100;
    hsv.v = v * 100;

    return hsv;
}


// 将HSV转换成RGB
uint32_t ColorPicker::HSVtoRGB(HSV hsv) const
{
    float rgb_min, rgb_max;
    uint32_t r, g, b;
    uint32_t rgb = 0;
    if (hsv.h > 360) {
        hsv.h = 360;
    }
    if (hsv.h < 0) {
        hsv.h = 0;
    }
    if (hsv.s > 100) {
        hsv.s = 100;
    }
    if (hsv.s < 0) {
        hsv.s = 0;
    }
    if (hsv.v > 100) {
        hsv.v = 100;
    }
    if (hsv.v < 0) {
        hsv.v = 0;
    }
    // The brightness is directly proportional to the maximum value that RGB can reach, which is 2.55 times.
    rgb_max = hsv.v * 2.55f;

    // Each time the saturation decreases from 100, the minimum value that RGB can achieve increases linearly by 1/100 from 0 to the maximum value set by the brightness
    rgb_min = rgb_max*(100 - hsv.s)/ 100.0f;

    int i = hsv.h / 60;
    int difs = hsv.h % 60;
    float rgb_Adj = (rgb_max - rgb_min)*difs / 60.0f;

    /**
     * According to the change of H, there are six cases. In each case, a parameter in RBG is linearly
     * transformed (increased or decreased) between the minimum and maximum values that can be achieved
     * by RGB.
     */
    switch (i) {
        case 0:
            r = rgb_max;
            g = rgb_min + rgb_Adj;
            b = rgb_min;
            break;
        case 1:
            r = rgb_max - rgb_Adj;
            g = rgb_max;
            b = rgb_min;
            break;
        case 2:
            r = rgb_min;
            g = rgb_max;
            b = rgb_min + rgb_Adj;
            break;
        case 3:
            r = rgb_min;
            g = rgb_max - rgb_Adj;
            b = rgb_max;
            break;
        case 4:
            r = rgb_min + rgb_Adj;
            g = rgb_min;
            b = rgb_max;
            break;
        default:
            r = rgb_max;
            g = rgb_min;
            b = rgb_max - rgb_Adj;
            break;
    }
    rgb = r << ARGB_R_SHIFT | g << ARGB_G_SHIFT | b << ARGB_B_SHIFT;
    return rgb;
}


} // namespace Rosen
} // namespace OHOS

#ifdef __cplusplus
}
#endif
