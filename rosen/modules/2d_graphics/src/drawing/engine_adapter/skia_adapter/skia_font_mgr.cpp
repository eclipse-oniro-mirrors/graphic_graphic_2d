/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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

#include "skia_font_mgr.h"
#include <codecvt>
#include <locale>
#include <securec.h>

#include "include/core/SkString.h"
#include "include/core/SkTypeface.h"
#ifndef USE_TEXGINE
#include "txt/asset_font_manager.h"
#endif

#include "text/font_mgr.h"
#include "skia_adapter/skia_convert_utils.h"
#include "skia_adapter/skia_font_style_set.h"
#include "skia_adapter/skia_typeface.h"
#include "text/common_utils.h"

namespace OHOS {
namespace Rosen {
namespace Drawing {
namespace {
const uint8_t MOVEBITS = 8;
void SwapBytes(char16_t* srcStr, uint32_t len)
{
    if (srcStr == nullptr || len == 0) {
        return;
    }
    // if is big endian, high-order byte first
    int num = 1;
    if (*(reinterpret_cast<const uint8_t*>(&num)) == 0) {
        return;
    }
    // swap bytes
    for (uint32_t i = 0; i < len; i++) {
        uint16_t temp = static_cast<uint16_t>(srcStr[i]);
        // Swap the byte order of the 16-bit value
        srcStr[i] = static_cast<char16_t>((temp & 0xff) << MOVEBITS | (temp & 0xff00) >> MOVEBITS);
    }
}

bool ConvertToUTF16BE(uint8_t* data, uint32_t dataLen, FontByteArray& fullname)
{
    if (data == nullptr || dataLen == 0) {
        return false;
    }
    // If the encoding format of data is UTF-16, copy it directly
    if (strlen(reinterpret_cast<char*>(data)) < dataLen || !IsUtf8(reinterpret_cast<const char*>(data))) {
        fullname.strData = std::make_unique<uint8_t[]>(dataLen);
        if (memcpy_s(fullname.strData.get(), dataLen, data, dataLen) == EOK) {
            fullname.strLen = dataLen;
            return true;
        }
        return false;
    }
    // If the data format is utf-8, create a converter from UTF-8 to UTF-16
    std::wstring_convert<std::codecvt_utf8_utf16<char16_t>, char16_t> converter;
    std::string utf8String(reinterpret_cast<char*>(data), dataLen);
    std::u16string utf16String = converter.from_bytes(utf8String);
    // Get the byte length and copy the data
    size_t strByteLen = utf16String.size() * sizeof(char16_t);
    if (strByteLen == 0) {
        return false;
    }
    SwapBytes(const_cast<char16_t*>(utf16String.c_str()), strByteLen / sizeof(char16_t));
    fullname.strData = std::make_unique<uint8_t[]>(strByteLen);
    if (memcpy_s(fullname.strData.get(), strByteLen,
        reinterpret_cast<const void*>(utf16String.c_str()), strByteLen) == EOK) {
        fullname.strLen = strByteLen;
        return true;
    }
    return false;
}
}

SkiaFontMgr::SkiaFontMgr(sk_sp<SkFontMgr> skFontMgr) : skFontMgr_(skFontMgr) {}

std::shared_ptr<FontMgrImpl> SkiaFontMgr::CreateDefaultFontMgr()
{
    return std::make_shared<SkiaFontMgr>(SkFontMgr::RefDefault());
}

#ifndef USE_TEXGINE
std::shared_ptr<FontMgrImpl> SkiaFontMgr::CreateDynamicFontMgr()
{
    sk_sp<txt::DynamicFontManager> dynamicFontManager = sk_make_sp<txt::DynamicFontManager>();
    return std::make_shared<SkiaFontMgr>(dynamicFontManager);
}

Typeface* SkiaFontMgr::LoadDynamicFont(const std::string& familyName, const uint8_t* data, size_t dataLength)
{
    auto stream = std::make_unique<SkMemoryStream>(data, dataLength, true);
    auto typeface = SkTypeface::MakeFromStream(std::move(stream));
    auto dynamicFontMgr = static_cast<txt::DynamicFontManager*>(skFontMgr_.get());
    if (familyName.empty()) {
        dynamicFontMgr->font_provider().RegisterTypeface(typeface);
    } else {
        dynamicFontMgr->font_provider().RegisterTypeface(typeface, familyName);
    }
    if (!typeface) {
        return nullptr;
    }
    typeface->setIsCustomTypeface(true);
    std::shared_ptr<TypefaceImpl> typefaceImpl = std::make_shared<SkiaTypeface>(typeface);
    return new Typeface(typefaceImpl);
}

void SkiaFontMgr::LoadThemeFont(const std::string& themeName, std::shared_ptr<Typeface> typeface)
{
    if (typeface == nullptr) {
        return;
    }
    auto dynamicFontMgr = static_cast<txt::DynamicFontManager*>(skFontMgr_.get());
    SkiaTypeface *skiaTypeFace = typeface->GetImpl<SkiaTypeface>();
    if (skiaTypeFace == nullptr) {
        return;
    }
    dynamicFontMgr->font_provider().RegisterTypeface(skiaTypeFace->GetTypeface(), themeName);
}

Typeface* SkiaFontMgr::LoadThemeFont(const std::string& familyName, const std::string& themeName,
    const uint8_t* data, size_t dataLength)
{
    auto dynamicFontMgr = static_cast<txt::DynamicFontManager*>(skFontMgr_.get());
    if (familyName.empty() || data == nullptr) {
        dynamicFontMgr->font_provider().RegisterTypeface(nullptr, themeName);
        return nullptr;
    } else {
        auto stream = std::make_unique<SkMemoryStream>(data, dataLength, true);
        auto typeface = SkTypeface::MakeFromStream(std::move(stream));
        dynamicFontMgr->font_provider().RegisterTypeface(typeface, themeName);
        if (!typeface) {
            return nullptr;
        } else {
            typeface->setIsCustomTypeface(true);
            std::shared_ptr<TypefaceImpl> typefaceImpl = std::make_shared<SkiaTypeface>(typeface);
            return new Typeface(typefaceImpl);
        }
    }
}
#endif

Typeface* SkiaFontMgr::MatchFamilyStyleCharacter(const char familyName[], const FontStyle& fontStyle,
                                                 const char* bcp47[], int bcp47Count,
                                                 int32_t character)
{
    SkFontStyle skFontStyle;
    SkiaConvertUtils::DrawingFontStyleCastToSkFontStyle(fontStyle, skFontStyle);
    SkTypeface* skTypeface =
        skFontMgr_->matchFamilyStyleCharacter(familyName, skFontStyle, bcp47, bcp47Count, character);
    if (!skTypeface) {
        return nullptr;
    }
    std::shared_ptr<TypefaceImpl> typefaceImpl = std::make_shared<SkiaTypeface>(sk_sp(skTypeface));
    return new Typeface(typefaceImpl);
}

FontStyleSet* SkiaFontMgr::MatchFamily(const char familyName[]) const
{
    SkFontStyleSet* skFontStyleSetPtr = skFontMgr_->matchFamily(familyName);
    if (!skFontStyleSetPtr) {
        return nullptr;
    }
    sk_sp<SkFontStyleSet> skFontStyleSet{skFontStyleSetPtr};
    std::shared_ptr<FontStyleSetImpl> fontStyleSetImpl = std::make_shared<SkiaFontStyleSet>(skFontStyleSet);
    return new FontStyleSet(fontStyleSetImpl);
}

Typeface* SkiaFontMgr::MatchFamilyStyle(const char familyName[], const FontStyle& fontStyle) const
{
    SkFontStyle skFontStyle;
    SkiaConvertUtils::DrawingFontStyleCastToSkFontStyle(fontStyle, skFontStyle);
    SkTypeface* skTypeface =
        skFontMgr_->matchFamilyStyle(familyName, skFontStyle);
    if (!skTypeface) {
        return nullptr;
    }
    std::shared_ptr<TypefaceImpl> typefaceImpl = std::make_shared<SkiaTypeface>(sk_sp(skTypeface));
    return new Typeface(typefaceImpl);
}

int SkiaFontMgr::CountFamilies() const
{
    if (skFontMgr_ == nullptr) {
        return 0;
    }
    return skFontMgr_->countFamilies();
}

void SkiaFontMgr::GetFamilyName(int index, std::string& str) const
{
    if (index < 0 || skFontMgr_ == nullptr) {
        return;
    }
    SkString skName;
    skFontMgr_->getFamilyName(index, &skName);
    str.assign(skName.c_str());
}

FontStyleSet* SkiaFontMgr::CreateStyleSet(int index) const
{
    if (index < 0 || skFontMgr_ == nullptr) {
        return nullptr;
    }
    SkFontStyleSet* skFontStyleSetPtr = skFontMgr_->createStyleSet(index);
    if (!skFontStyleSetPtr) {
        return nullptr;
    }
    sk_sp<SkFontStyleSet> skFontStyleSet{skFontStyleSetPtr};
    std::shared_ptr<FontStyleSetImpl> fontStyleSetImpl = std::make_shared<SkiaFontStyleSet>(skFontStyleSet);
    return new FontStyleSet(fontStyleSetImpl);
}

int SkiaFontMgr::GetFontFullName(int fontFd, std::vector<FontByteArray>& fullnameVec)
{
    if (skFontMgr_ == nullptr) {
        return ERROR_TYPE_OTHER;
    }
    std::vector<SkByteArray> skFullnameVec;
    int ret = skFontMgr_->GetFontFullName(fontFd, skFullnameVec);
    if (ret != SUCCESSED) {
        return ret;
    }
    for (SkByteArray &skFullname : skFullnameVec) {
        FontByteArray newFullname = {nullptr, 0};
        if (ConvertToUTF16BE(skFullname.strData.get(), skFullname.strLen, newFullname)) {
            fullnameVec.push_back(std::move(newFullname));
        } else {
            return ERROR_TYPE_OTHER;
        }
    }
    return SUCCESSED;
}

int SkiaFontMgr::ParseInstallFontConfig(const std::string& configPath, std::vector<std::string>& fontPathVec)
{
    if (skFontMgr_ == nullptr) {
        return ERROR_TYPE_OTHER;
    }
    return skFontMgr_->ParseInstallFontConfig(configPath, fontPathVec);
}
} // namespace Drawing
} // namespace Rosen
} // namespace OHOS