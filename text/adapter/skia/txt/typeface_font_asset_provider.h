/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.. All rights reserved.
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

#ifndef ROSEN_MODULES_SPTEXT_TYPEFACE_FONT_ASSET_PROVIDER_H
#define ROSEN_MODULES_SPTEXT_TYPEFACE_FONT_ASSET_PROVIDER_H

#include <string>
#include <unordered_map>
#include <vector>
#include <mutex>

#include "include/core/SkFontMgr.h"
#include "txt/font_asset_provider.h"
#include "utils.h"

namespace txt {
class TypefaceFontStyleSet : public SkFontStyleSet {
public:
    TypefaceFontStyleSet();

    ~TypefaceFontStyleSet() override;

    void registerTypeface(sk_sp<SkTypeface> typeface);

    void unregisterTypefaces();

    int count() override;

    void getStyle(int index, SkFontStyle* style, SkString* name) override;

    SkTypeface* createTypeface(int index) override;

    SkTypeface* matchStyle(const SkFontStyle& pattern) override;

private:
    std::vector<sk_sp<SkTypeface>> typefaces_;

    DISALLOW_COPY_AND_ASSIGN(TypefaceFontStyleSet);
};

class TypefaceFontAssetProvider : public FontAssetProvider {
public:
    TypefaceFontAssetProvider();
    ~TypefaceFontAssetProvider() override;

    void RegisterTypeface(sk_sp<SkTypeface> typeface);

    void RegisterTypeface(sk_sp<SkTypeface> typeface, std::string familyNameAlias);

    size_t GetFamilyCount() const override;

    std::string GetFamilyName(int index) const override;

    SkFontStyleSet* MatchFamily(const std::string& familyName) override;

private:
    std::unordered_map<std::string, sk_sp<TypefaceFontStyleSet>> registeredFamilies_;
    std::vector<std::string> familyNames_;
    mutable std::mutex assetMutex_;

    DISALLOW_COPY_AND_ASSIGN(TypefaceFontAssetProvider);
};
} // namespace txt

#endif // ROSEN_MODULES_SPTEXT_TYPEFACE_FONT_ASSET_PROVIDER_H
