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

#include "measurer.h"

#include <iomanip>
#include <list>
#include <queue>

#include <hb.h>
#include <hb-icu.h>
#include <unicode/utf16.h>
#include <unicode/uchar.h>

namespace Texgine {
struct MeasuringRun {
    size_t start;
    size_t end;
    hb_script_t script = HB_SCRIPT_INVALID;
    std::shared_ptr<Typeface> typeface = nullptr;
};

class MeasurerImpl : public Measurer {
public:
    MeasurerImpl(const std::vector<uint16_t> &text, const FontCollection &fontCollection);
    const std::vector<Boundary> &GetWordBoundary() const override;
    int Measure(CharGroups &cgs) override;
    void SeekTypeface(std::list<struct MeasuringRun> &runs);
    void SeekScript(std::list<struct MeasuringRun> &runs);
    int Shape(CharGroups &cgs, std::list<struct MeasuringRun> &runs, std::vector<Boundary> boundaries_);
    void GenerateHBFeatures(std::vector<hb_feature_t> &fontFeatures, const FontFeatures *ff);

private:
    struct MeasurerCacheKey {
        std::vector<uint16_t> text_;
        FontStyles style_;
        std::string locale_;
        bool rtl_;
        uint32_t size_;
        size_t startIndex_;
        size_t endIndex_;
        double letterSpacing_;
        double wordSpacing_;

        bool operator <(const struct MeasurerCacheKey &rhs) const
        {
            if (startIndex_ != rhs.startIndex_) {
                return startIndex_ < rhs.startIndex_;
            }
            if (endIndex_ != rhs.endIndex_) {
                return endIndex_ < rhs.endIndex_;
            }
            if (text_ != rhs.text_) {
                return text_ < rhs.text_;
            }
            if (rtl_ != rhs.rtl_) {
                return rtl_ < rhs.rtl_;
            }
            if (size_ != rhs.size_) {
                return size_ < rhs.size_;
            }
            if (style_ != rhs.style_) {
                return style_ < rhs.style_;
            }
            if (locale_ != rhs.locale_) {
                return locale_ < rhs.locale_;
            }
            if (letterSpacing_ != rhs.letterSpacing_) {
                return letterSpacing_ < rhs.letterSpacing_;
            }
            if (wordSpacing_ != rhs.wordSpacing_) {
                return wordSpacing_ < rhs.wordSpacing_;
            }
            return false;
        }
    };
    struct MeasurerCacheVal {
        CharGroups cgs_;
        std::vector<Boundary> boundaries_;
    };

    void DoSeekScript(std::list<struct MeasuringRun> &runs, hb_unicode_funcs_t *icuGetUnicodeFuncs);
    int DoShape(CharGroups &cgs, MeasuringRun &run, int &index);
    int GetGlyphs(CharGroups &cgs, MeasuringRun &run, int &index, hb_buffer_t *hbuffer,
        std::shared_ptr<Texgine::Typeface> typeface);
    void DoCgsByCluster(std::map<uint32_t, Texgine::CharGroup> &cgsByCluster);

    static inline std::map<struct MeasurerCacheKey, struct MeasurerCacheVal> cache_;
    std::vector<Boundary> boundaries_;
};

hb_blob_t *HbFaceReferenceTableTypeface(hb_face_t *face, hb_tag_t tag, void *context);
} // namespace Texgine
