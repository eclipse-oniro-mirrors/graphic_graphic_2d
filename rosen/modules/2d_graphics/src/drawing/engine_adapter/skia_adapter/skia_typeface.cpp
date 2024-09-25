/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "skia_typeface.h"

#include "include/core/SkFontMgr.h"
#include "include/core/SkFontStyle.h"
#include "include/core/SkStream.h"
#include "include/core/SkString.h"
#include "include/private/SkTHash.h"
#include "skia_adapter/skia_convert_utils.h"
#include "skia_adapter/skia_data.h"
#include "skia_adapter/skia_memory_stream.h"
#include "utils/log.h"

namespace OHOS {
namespace Rosen {
namespace Drawing {
SkiaTypeface::SkiaTypeface(sk_sp<SkTypeface> skTypeface) : skTypeface_(skTypeface) {}

sk_sp<SkTypeface> SkiaTypeface::GetTypeface() const
{
    return skTypeface_;
}

std::string SkiaTypeface::GetFamilyName() const
{
    std::string name;
    if (!skTypeface_) {
        LOGD("skTypeface nullptr, %{public}s, %{public}d", __FUNCTION__, __LINE__);
        return name;
    }
    SkString skName;
    skTypeface_->getFamilyName(&skName);
    SkiaConvertUtils::SkStringCastToStdString(skName, name);
    return name;
}

FontStyle SkiaTypeface::GetFontStyle() const
{
    FontStyle fontStyle;
    if (!skTypeface_) {
        LOGD("skTypeface nullptr, %{public}s, %{public}d", __FUNCTION__, __LINE__);
        return fontStyle;
    }
    SkFontStyle skFontStyle = skTypeface_->fontStyle();
    SkiaConvertUtils::SkFontStyleCastToDrawingFontStyle(skFontStyle, fontStyle);
    return fontStyle;
}

size_t SkiaTypeface::GetTableSize(uint32_t tag) const
{
    if (!skTypeface_) {
        LOGD("skTypeface nullptr, %{public}s, %{public}d", __FUNCTION__, __LINE__);
        return 0;
    }
    return skTypeface_->getTableSize(tag);
}

size_t SkiaTypeface::GetTableData(uint32_t tag, size_t offset, size_t length, void* data) const
{
    if (!skTypeface_) {
        LOGD("skTypeface nullptr, %{public}s, %{public}d", __FUNCTION__, __LINE__);
        return 0;
    }
    return skTypeface_->getTableData(tag, offset, length, data);
}

bool SkiaTypeface::GetItalic() const
{
    if (!skTypeface_) {
        LOGD("skTypeface nullptr, %{public}s, %{public}d", __FUNCTION__, __LINE__);
        return false;
    }
    return skTypeface_->isItalic();
}

uint32_t SkiaTypeface::GetUniqueID() const
{
    if (!skTypeface_) {
        LOGD("skTypeface nullptr, %{public}s, %{public}d", __FUNCTION__, __LINE__);
        return 0;
    }
    return skTypeface_->uniqueID();
}

int32_t SkiaTypeface::GetUnitsPerEm() const
{
    if (!skTypeface_) {
        LOGD("SkiaTypeface::GetUnitsPerEm, skTypeface nullptr");
        return 0;
    }
    return skTypeface_->getUnitsPerEm();
}

std::shared_ptr<Typeface> SkiaTypeface::MakeClone(const FontArguments& args) const
{
    if (!skTypeface_) {
        LOGD("SkiaTypeface::MakeClone, skTypeface nullptr");
        return nullptr;
    }

    SkFontArguments skArgs;
    SkiaConvertUtils::DrawingFontArgumentsCastToSkFontArguments(args, skArgs);

    auto cloned = skTypeface_->makeClone(skArgs);
    if (!cloned) {
        return nullptr;
    }
    cloned->setIsCustomTypeface(skTypeface_->isCustomTypeface());
    std::shared_ptr<TypefaceImpl> typefaceImpl = std::make_shared<SkiaTypeface>(cloned);
    return std::make_shared<Typeface>(typefaceImpl);
}

bool SkiaTypeface::IsCustomTypeface() const
{
    if (!skTypeface_) {
        LOGD("skTypeface nullptr, %{public}s, %{public}d", __FUNCTION__, __LINE__);
        return false;
    }
    return skTypeface_->isCustomTypeface();
}

sk_sp<SkTypeface> SkiaTypeface::GetSkTypeface()
{
    if (!skTypeface_) {
        LOGD("skTypeface nullptr, %{public}s, %{public}d", __FUNCTION__, __LINE__);
        return nullptr;
    }
    return skTypeface_;
}

std::shared_ptr<Typeface> SkiaTypeface::MakeDefault()
{
    sk_sp<SkTypeface> skTypeface = SkTypeface::MakeDefault();
    if (!skTypeface) {
        LOGD("skTypeface nullptr, %{public}s, %{public}d", __FUNCTION__, __LINE__);
        return nullptr;
    }
    std::shared_ptr<TypefaceImpl> typefaceImpl = std::make_shared<SkiaTypeface>(skTypeface);
    return std::make_shared<Typeface>(typefaceImpl);
}

std::shared_ptr<Typeface> SkiaTypeface::MakeFromFile(const char path[], int index)
{
    sk_sp<SkTypeface> skTypeface = SkTypeface::MakeFromFile(path, index);
    if (!skTypeface) {
        LOGD("skTypeface nullptr, %{public}s, %{public}d", __FUNCTION__, __LINE__);
        return nullptr;
    }
    skTypeface->setIsCustomTypeface(true);
    std::shared_ptr<TypefaceImpl> typefaceImpl = std::make_shared<SkiaTypeface>(skTypeface);
    return std::make_shared<Typeface>(typefaceImpl);
}

std::shared_ptr<Typeface> SkiaTypeface::MakeFromFile(const char path[], const FontArguments& fontArguments)
{
    std::unique_ptr<SkStreamAsset> skStream = SkStreamAsset::MakeFromFile(path);
    if (skStream == nullptr) {
        LOGD("SkiaTypeface::MakeFromFile, skStream nullptr.");
        return nullptr;
    }
    auto skFontMgr = SkFontMgr::RefDefault();
    if (skFontMgr == nullptr) {
        LOGD("SkiaTypeface::MakeFromFile, skFontMgr nullptr.");
        return nullptr;
    }
    SkFontArguments skFontArguments;
    SkiaConvertUtils::DrawingFontArgumentsCastToSkFontArguments(fontArguments, skFontArguments);
    sk_sp<SkTypeface> skTypeface = skFontMgr->makeFromStream(std::move(skStream), skFontArguments);
    if (!skTypeface) {
        LOGD("SkiaTypeface::MakeFromFile, skTypeface nullptr.");
        return nullptr;
    }
    skTypeface->setIsCustomTypeface(true);
    std::shared_ptr<TypefaceImpl> typefaceImpl = std::make_shared<SkiaTypeface>(skTypeface);
    return std::make_shared<Typeface>(typefaceImpl);
}

std::shared_ptr<Typeface> SkiaTypeface::MakeFromStream(std::unique_ptr<MemoryStream> memoryStream, int32_t index)
{
    if (!memoryStream) {
        LOGD("SkiaTypeface::MakeFromStream, memoryStream nullptr");
        return nullptr;
    }
    std::unique_ptr<SkStreamAsset> skMemoryStream = memoryStream->GetImpl<SkiaMemoryStream>()->GetSkMemoryStream();
    sk_sp<SkTypeface> skTypeface = SkTypeface::MakeFromStream(std::move(skMemoryStream), index);
    if (!skTypeface) {
        LOGD("SkiaTypeface::MakeFromStream, skTypeface nullptr");
        return nullptr;
    }
    skTypeface->setIsCustomTypeface(true);
    std::shared_ptr<TypefaceImpl> typefaceImpl = std::make_shared<SkiaTypeface>(skTypeface);
    return std::make_shared<Typeface>(typefaceImpl);
}

std::shared_ptr<Typeface> SkiaTypeface::MakeFromName(const char familyName[], FontStyle fontStyle)
{
    SkFontStyle skFontStyle;
    SkiaConvertUtils::DrawingFontStyleCastToSkFontStyle(fontStyle, skFontStyle);
    sk_sp<SkTypeface> skTypeface = SkTypeface::MakeFromName(familyName, skFontStyle);
    if (!skTypeface) {
        LOGD("SkiaTypeface::MakeFromName, skTypeface nullptr");
        return nullptr;
    }
    std::shared_ptr<TypefaceImpl> typefaceImpl = std::make_shared<SkiaTypeface>(skTypeface);
    return std::make_shared<Typeface>(typefaceImpl);
}

sk_sp<SkData> SkiaTypeface::SerializeTypeface(SkTypeface* typeface, void* ctx)
{
    if (!typeface) {
        LOGD("typeface nullptr, %{public}s, %{public}d", __FUNCTION__, __LINE__);
        return nullptr;
    }
    TextBlob::Context* textblobCtx = reinterpret_cast<TextBlob::Context*>(ctx);
    if (textblobCtx != nullptr && typeface->isCustomTypeface()) {
        sk_sp<SkTypeface> typefacePtr = sk_ref_sp(typeface);
        auto typefaceImpl = std::make_shared<SkiaTypeface>(typefacePtr);
        auto customTypeface = std::make_shared<Typeface>(typefaceImpl);
        textblobCtx->SetTypeface(customTypeface);
    }
    return typeface->serialize();
}

sk_sp<SkTypeface> SkiaTypeface::DeserializeTypeface(const void* data, size_t length, void* ctx)
{
    if (data == nullptr) {
        LOGD("data nullptr, %{public}s, %{public}d", __FUNCTION__, __LINE__);
        return nullptr;
    }

    TextBlob::Context* textblobCtx = reinterpret_cast<TextBlob::Context*>(ctx);
    if (textblobCtx == nullptr || textblobCtx->GetTypeface() == nullptr) {
        SkMemoryStream stream(data, length);
        return SkTypeface::MakeDeserialize(&stream);
    }
    auto& typeface = textblobCtx->GetTypeface();
    if (typeface == nullptr) {
        LOGD("typeface nullptr, %{public}s, %{public}d", __FUNCTION__, __LINE__);
        return nullptr;
    }
    auto skiaTypeface = typeface->GetImpl<SkiaTypeface>();
    if (skiaTypeface == nullptr) {
        LOGD("skiaTypeface nullptr, %{public}s, %{public}d", __FUNCTION__, __LINE__);
        return nullptr;
    }
    auto skTypeface = skiaTypeface->GetSkTypeface();
    return skTypeface;
}

std::shared_ptr<Data> SkiaTypeface::Serialize() const
{
    if (!skTypeface_) {
        LOGD("skTypeface nullptr, %{public}s, %{public}d", __FUNCTION__, __LINE__);
        return nullptr;
    }
    auto skData = skTypeface_->serialize(SkTypeface::SerializeBehavior::kDoIncludeData);
    auto data = std::make_shared<Data>();
    auto skiaData = data->GetImpl<SkiaData>();
    if (!skiaData) {
        LOGD("skiaData nullptr, %{public}s, %{public}d", __FUNCTION__, __LINE__);
        return nullptr;
    }
    skiaData->SetSkData(skData);
    return data;
}

std::shared_ptr<Typeface> SkiaTypeface::Deserialize(const void* data, size_t size)
{
    SkMemoryStream stream(data, size);
    auto skTypeface = SkTypeface::MakeDeserialize(&stream);
    if (!skTypeface) {
        LOGD("skTypeface nullptr, %{public}s, %{public}d", __FUNCTION__, __LINE__);
        return nullptr;
    }
    auto typefaceImpl = std::make_shared<SkiaTypeface>(skTypeface);
    return std::make_shared<Typeface>(typefaceImpl);
}

uint32_t SkiaTypeface::GetHash() const
{
    if (hash_ != 0) {
        return hash_;
    }
    if (!skTypeface_) {
        LOGD("skTypeface nullptr, %{public}s, %{public}d", __FUNCTION__, __LINE__);
        return hash_;
    }

    auto skData = skTypeface_->serialize(SkTypeface::SerializeBehavior::kDontIncludeData);
    std::unique_ptr<SkStreamAsset> ttfStream = skTypeface_->openExistingStream(0);
    hash_ = SkOpts::hash_fn(skData->data(), skData->size(), ttfStream->getLength());
    return hash_;
}

void SkiaTypeface::SetHash(uint32_t hash)
{
    hash_ = hash;
}

} // namespace Drawing
} // namespace Rosen
} // namespace OHOS