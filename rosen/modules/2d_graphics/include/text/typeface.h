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

#ifndef TYPEFACE_H
#define TYPEFACE_H

#include <memory>
#include <cstdint>

#include "impl_interface/typeface_impl.h"
#include "text/font_style.h"

namespace OHOS {
namespace Rosen {
namespace Drawing {
class DRAWING_API Typeface {
public:
    explicit Typeface(std::shared_ptr<TypefaceImpl> typefaceImpl) noexcept;
    virtual ~Typeface() = default;

    static std::shared_ptr<Typeface> MakeFromFile(const char path[]);

    /*
     * @brief   Get the familyName for this typeface.
     * @return  FamilyName.
     */
    std::string GetFamilyName() const;

    /*
     * @brief   Get the fontStyle for this typeface.
     * @return  FontStyle.
     */
    FontStyle GetFontStyle() const;

    /*
     * @brief      Get the size of its contents for the given tag.
     * @param tag  The given table tag.
     * @return     If not present, return 0.
     */
    size_t GetTableSize(uint32_t tag) const;

    /*
     * @brief         Get the size of its contents for the given tag.
     * @param tag     The given table tag.
     * @param offset  The offset in bytes into the table's contents where the copy should start from.
     * @param length  The number of bytes.
     * @param data    Storage address.
     * @return        The number of bytes actually copied into data.
     */
    size_t GetTableData(uint32_t tag, size_t offset, size_t length, void* data) const;

    /*
     * @brief   Get fontStyle is italic.
     * @return  If fontStyle is italic, return true.
     */
    bool GetItalic() const;

    /*
     * @brief   Get a 32bit value for this typeface, unique for the underlying font data.
     * @return  UniqueID.
     */
    uint32_t GetUniqueID() const;

    template<typename T>
    const std::shared_ptr<T> GetImpl() const
    {
        if (typefaceImpl_) {
            return typefaceImpl_->DowncastingTo<T>();
        }
        return nullptr;
    }

private:
    std::shared_ptr<TypefaceImpl> typefaceImpl_;
};
} // namespace Drawing
} // namespace Rosen
} // namespace OHOS
#endif