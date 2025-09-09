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

#include "text/typeface.h"

#include "impl_interface/typeface_impl.h"
#include "static_factory.h"

namespace OHOS {
namespace Rosen {
namespace Drawing {
Typeface::Typeface(std::shared_ptr<TypefaceImpl> typefaceImpl) noexcept : typefaceImpl_(typefaceImpl) {}

std::shared_ptr<Typeface> Typeface::MakeDefault()
{
    return StaticFactory::MakeDefault();
}

std::shared_ptr<Typeface> Typeface::MakeFromFile(const char path[], int index)
{
    return StaticFactory::MakeFromFile(path, index);
}

std::shared_ptr<Typeface> Typeface::MakeFromFile(const char path[], const FontArguments& fontArguments)
{
    return StaticFactory::MakeFromFile(path, fontArguments);
}

std::vector<std::shared_ptr<Typeface>> Typeface::GetSystemFonts()
{
    return StaticFactory::GetSystemFonts();
}

void Typeface::RegisterOnTypefaceDestroyed(std::function<void(uint32_t)> cb)
{
    return StaticFactory::RegisterOnTypefaceDestroyed(cb);
}

std::shared_ptr<Typeface> Typeface::MakeFromStream(std::unique_ptr<MemoryStream> memoryStream, int32_t index)
{
    return StaticFactory::MakeFromStream(std::move(memoryStream), index);
}

std::shared_ptr<Typeface> Typeface::MakeFromStream(std::unique_ptr<MemoryStream> memoryStream,
    const FontArguments& fontArguments)
{
    return StaticFactory::MakeFromStream(std::move(memoryStream), fontArguments);
}

std::shared_ptr<Typeface> Typeface::MakeFromName(const char familyName[], FontStyle fontStyle)
{
    return StaticFactory::MakeFromName(familyName, fontStyle);
}

std::string Typeface::GetFamilyName() const
{
    if (typefaceImpl_) {
        return typefaceImpl_->GetFamilyName();
    }
    return std::string();
}

std::string Typeface::GetFontPath() const
{
    return (typefaceImpl_ == nullptr) ? "" : typefaceImpl_->GetFontPath();
}

FontStyle Typeface::GetFontStyle() const
{
    if (typefaceImpl_) {
        return typefaceImpl_->GetFontStyle();
    }
    return FontStyle();
}

size_t Typeface::GetTableSize(uint32_t tag) const
{
    if (typefaceImpl_) {
        return typefaceImpl_->GetTableSize(tag);
    }
    return 0;
}

size_t Typeface::GetTableData(uint32_t tag, size_t offset, size_t length, void* data) const
{
    if (typefaceImpl_) {
        return typefaceImpl_->GetTableData(tag, offset, length, data);
    }
    return 0;
}

bool Typeface::GetItalic() const
{
    if (typefaceImpl_) {
        return typefaceImpl_->GetItalic();
    }
    return false;
}

uint32_t Typeface::GetUniqueID() const
{
    if (typefaceImpl_) {
        return typefaceImpl_->GetUniqueID();
    }
    return 0;
}

int32_t Typeface::GetUnitsPerEm() const
{
    if (typefaceImpl_) {
        return typefaceImpl_->GetUnitsPerEm();
    }
    return 0;
}

std::shared_ptr<Typeface> Typeface::MakeClone(const FontArguments& args) const
{
    if (typefaceImpl_) {
        return typefaceImpl_->MakeClone(args);
    }
    return nullptr;
}

bool Typeface::IsCustomTypeface() const
{
    if (typefaceImpl_) {
        return typefaceImpl_->IsCustomTypeface();
    }
    return false;
}

bool Typeface::IsThemeTypeface() const
{
    if (typefaceImpl_) {
        return typefaceImpl_->IsThemeTypeface();
    }
    return false;
}

std::shared_ptr<Data> Typeface::Serialize() const
{
    if (!typefaceImpl_) {
        return nullptr;
    }
    return typefaceImpl_->Serialize();
}

std::shared_ptr<Typeface> Typeface::Deserialize(const void* data, size_t size)
{
    auto typeface = StaticFactory::DeserializeTypeface(data, size);
    if (typeface != nullptr) {
        typeface->SetSize(size);
    }
    return typeface;
}

std::function<bool(std::shared_ptr<Typeface>)> Typeface::registerTypefaceCallBack_ = nullptr;
void Typeface::RegisterCallBackFunc(std::function<bool(std::shared_ptr<Typeface>)> func)
{
    registerTypefaceCallBack_ = func;
}

std::function<bool(std::shared_ptr<Typeface>)>& Typeface::GetTypefaceRegisterCallBack()
{
    return registerTypefaceCallBack_;
}

std::function<std::shared_ptr<Typeface>(uint64_t)> Typeface::uniqueIdCallBack_ = nullptr;
void Typeface::RegisterUniqueIdCallBack(std::function<std::shared_ptr<Typeface>(uint64_t)> cb)
{
    uniqueIdCallBack_ = cb;
}

std::function<std::shared_ptr<Typeface>(uint64_t)> Typeface::GetUniqueIdCallBack()
{
    return uniqueIdCallBack_;
}

uint32_t Typeface::GetHash() const
{
    if (typefaceImpl_) {
        return typefaceImpl_->GetHash();
    }
    return 0;
}

void Typeface::SetHash(uint32_t hash)
{
    if (typefaceImpl_) {
        typefaceImpl_->SetHash(hash);
    }
}

uint32_t Typeface::GetSize()
{
    if (size_ != 0) {
        return size_;
    }
    if (!typefaceImpl_) {
        return 0;
    }
    auto data = typefaceImpl_->Serialize();
    if (!data) {
        return 0;
    }
    size_ = data->GetSize();
    return size_;
}

void Typeface::SetSize(uint32_t size)
{
    size_ = size;
}
} // namespace Drawing
} // namespace Rosen
} // namespace OHOS
