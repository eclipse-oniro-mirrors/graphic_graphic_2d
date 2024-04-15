/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "font_collection.h"

#include "include/core/SkTypeface.h"
#include "convert.h"
#include "text/typeface.h"

namespace OHOS {
namespace Rosen {
#define OHOS_THEME_FONT "OhosThemeFont"

std::shared_ptr<FontCollection> FontCollection::Create()
{
    static std::shared_ptr<FontCollection> instance = std::make_shared<AdapterTxt::FontCollection>();
    return instance;
}

std::shared_ptr<FontCollection> FontCollection::From(std::shared_ptr<txt::FontCollection> fontCollection)
{
    return std::make_shared<AdapterTxt::FontCollection>(fontCollection);
}

namespace AdapterTxt {
FontCollection::FontCollection(std::shared_ptr<txt::FontCollection> fontCollection)
    : fontCollection_(fontCollection), dfmanager_(Drawing::FontMgr::CreateDynamicFontMgr())
{
    if (fontCollection_ == nullptr) {
        fontCollection_ = std::make_shared<txt::FontCollection>();
    }
    fontCollection_->SetupDefaultFontManager();
    fontCollection_->SetDynamicFontManager(dfmanager_);
}

FontCollection::~FontCollection()
{
    if (Drawing::Typeface::GetTypefaceUnRegisterCallBack() == nullptr) {
        return;
    }
    for (auto& name : familyNames_) {
        auto styleSet = dfmanager_->MatchFamily(name.c_str());
        if (!styleSet) {
            continue;
        }
        int count = styleSet->Count();
        for (int i = 0; i < count; ++i) {
            Drawing::Typeface* typeface = styleSet->CreateTypeface(i);
            if (!typeface) {
                continue;
            }
            std::shared_ptr<Drawing::Typeface> drawingTypeface(typeface);
            Drawing::Typeface::GetTypefaceUnRegisterCallBack()(drawingTypeface);
        }
    }
}

std::shared_ptr<txt::FontCollection> FontCollection::Get()
{
    return fontCollection_;
}

void FontCollection::DisableFallback()
{
    fontCollection_->DisableFontFallback();
}

void FontCollection::DisableSystemFont()
{
    fontCollection_->SetDefaultFontManager(nullptr);
}

std::shared_ptr<Drawing::FontMgr> FontCollection::GetFontMgr()
{
    return dfmanager_;
}

void FontCollection::AddLoadedFamilyName(const std::string& name)
{
    familyNames_.emplace_back(name);
}

Drawing::Typeface* FontCollection::LoadFont(const std::string &familyName, const uint8_t *data, size_t datalen)
{
    Drawing::Typeface* typeface = dfmanager_->LoadDynamicFont(familyName, data, datalen);
    fontCollection_->ClearFontFamilyCache();
    return typeface;
}

void FontCollection::LoadThemeFont(const std::string &familyName, const uint8_t *data, size_t datalen)
{
    dfmanager_->LoadThemeFont(familyName, OHOS_THEME_FONT, data, datalen);
    fontCollection_->ClearFontFamilyCache();
}
} // namespace AdapterTxt
} // namespace Rosen
} // namespace OHOS
