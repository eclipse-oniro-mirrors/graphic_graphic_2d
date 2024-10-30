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

#include "convert.h"
#include "text/typeface.h"
#include "utils/text_log.h"

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

std::shared_ptr<txt::FontCollection> FontCollection::Get()
{
    return fontCollection_;
}

FontCollection::~FontCollection()
{
    if (Drawing::Typeface::GetTypefaceUnRegisterCallBack() == nullptr) {
        return;
    }

    std::unique_lock<std::mutex> lock(mutex_);
    for (const auto& [id, typeface] : typefaces_) {
        Drawing::Typeface::GetTypefaceUnRegisterCallBack()(typeface);
    }
    typefaces_.clear();
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

bool FontCollection::RegisterTypeface(std::shared_ptr<Drawing::Typeface> typeface)
{
    if (!typeface || !Drawing::Typeface::GetTypefaceRegisterCallBack()) {
        return false;
    }

    std::unique_lock<std::mutex> lock(mutex_);
    if (typefaces_.find(typeface->GetUniqueID()) != typefaces_.end()) {
        return true;
    }
    if (!Drawing::Typeface::GetTypefaceRegisterCallBack()(typeface)) {
        return false;
    }

    typefaces_.emplace(typeface->GetUniqueID(), typeface);
    return true;
}

std::shared_ptr<Drawing::Typeface> FontCollection::LoadFont(
    const std::string &familyName, const uint8_t *data, size_t datalen)
{
    std::shared_ptr<Drawing::Typeface> typeface(dfmanager_->LoadDynamicFont(familyName, data, datalen));
    if (!RegisterTypeface(typeface)) {
        TEXT_LOGE("Failed to register typeface %{public}s.", familyName.c_str());
        return nullptr;
    }
    fontCollection_->ClearFontFamilyCache();
    return typeface;
}

static std::shared_ptr<Drawing::Typeface> CreateTypeFace(const uint8_t *data, size_t datalen)
{
    if (datalen != 0 && data != nullptr) {
        auto stream = std::make_unique<Drawing::MemoryStream>(data, datalen, true);
        return Drawing::Typeface::MakeFromStream(std::move(stream));
    }
    return nullptr;
}

std::shared_ptr<Drawing::Typeface> FontCollection::LoadThemeFont(
    const std::string &familyName, const uint8_t *data, size_t datalen)
{
    std::shared_ptr<Drawing::Typeface> face = CreateTypeFace(data, datalen);
    if (face != nullptr) {
        std::string name = face->GetFamilyName();
        for (auto item : typefaces_) {
            if (name == item.second->GetFamilyName()) {
                dfmanager_->LoadThemeFont(OHOS_THEME_FONT, item.second);
                fontCollection_->ClearFontFamilyCache();
                return item.second;
            }
        }
    }

    std::shared_ptr<Drawing::Typeface> typeface(dfmanager_->LoadThemeFont(familyName, OHOS_THEME_FONT, data, datalen));
    if (!RegisterTypeface(typeface)) {
        TEXT_LOGE("Failed to register typeface %{public}s.", familyName.c_str());
    }
    fontCollection_->ClearFontFamilyCache();
    return typeface;
}

void FontCollection::ClearCaches()
{
    fontCollection_->ClearFontFamilyCache();
}
} // namespace AdapterTxt
} // namespace Rosen
} // namespace OHOS
