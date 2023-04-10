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

#include "utils/memory_reporter.h"

#include <cassert>
#include <mutex>
#include <sstream>
#include <stack>

#include "hb.h"
#include "line_metrics.h"
#include "texgine/any_span.h"
#include "texgine/dynamic_font_provider.h"
#include "texgine/system_font_provider.h"
#include "typeface.h"
#include "typography_impl.h"

namespace OHOS {
namespace TextEngine {
#ifdef TEXGINE_ENABLE_MEMORY
class MemoryReporter {
public:
    static MemoryReporter &GetInstance();
    void Enter(const std::string &scopeType);
    void Exit();
    void Report(const std::string &member, double usage);

private:
    MemoryReporter() = default;
    ~MemoryReporter();
    MemoryReporter(const MemoryReporter &) = delete;
    MemoryReporter(MemoryReporter &&) = delete;
    MemoryReporter& operator=(const MemoryReporter &) = delete;
    MemoryReporter& operator=(MemoryReporter &&) = delete;

    uint64_t now = 0;
    std::vector<std::pair<uint64_t, std::string>> contents;
    std::stack<std::string> scopeStack = {};
};

MemoryReporter &MemoryReporter::GetInstance()
{
    static MemoryReporter instance;
    return instance;
}

void MemoryReporter::Enter(const std::string &scopeType)
{
    scopeStack.push(scopeType);
    contents.push_back(std::make_pair(now, "B" + scopeStack.top()));
}

void MemoryReporter::Exit()
{
    scopeStack.pop();
    contents.push_back(std::make_pair(now, "E"));
}

void MemoryReporter::Report(const std::string &member, double usage)
{
    contents.push_back(std::make_pair(now, "B" + scopeStack.top() + "::" + member));
    now += usage;
    contents.push_back(std::make_pair(now, "Cusage|" + std::to_string(now)));
    contents.push_back(std::make_pair(now, "E"));
}

MemoryReporter::~MemoryReporter()
{
    auto fp = fopen("texgine_usage.trace", "w");
    if (fp == nullptr) {
        return;
    }

    fprintf(fp, "# tracer: nop\n");
    for (const auto &[timeUs, content] : contents) {
        fprintf(fp, "texgine-1 (1) [000] .... %.6lf: tracing_mark_write: %c|1|%s\n",
                timeUs / 1e6, content[0], content.substr(1).c_str());
    }

    fclose(fp);
}

MemoryUsageScope::MemoryUsageScope(const std::string &name)
{
    MemoryReporter::GetInstance().Enter(name);
}

MemoryUsageScope::~MemoryUsageScope()
{
    MemoryReporter::GetInstance().Exit();
}

void DoReportMemoryUsage(const std::string &name, int usage)
{
    MemoryReporter::GetInstance().Report(name, usage);
}
#else
MemoryUsageScope::MemoryUsageScope(const std::string &name)
{
}

MemoryUsageScope::~MemoryUsageScope()
{
}

void DoReportMemoryUsage(const std::string &name, int usage)
{
}
#endif

DECLARE_RMU(std::string)
{
    if (needThis) {
        if (that.capacity() < 16) {
            DoReportMemoryUsage(member, 32);
        } else if (that.capacity() < 24) {
            DoReportMemoryUsage(member, 64);
        } else {
            DoReportMemoryUsage(member, 80 + (that.capacity() - 24) / 16 * 16);
        }
        return;
    }

    if (that.capacity() >= 16 && that.capacity() < 24) {
        DoReportMemoryUsage(member, 32);
    } else {
        DoReportMemoryUsage(member, 48 + (that.capacity() - 24) / 16 * 16);
    }
}

DECLARE_RMU(struct LineMetrics)
{
    MEMORY_USAGE_SCOPE("LineMetrics", that);
    MEMORY_USAGE_REPORT(lineSpans_);
}

DECLARE_RMU(struct TypographyStyle)
{
    MEMORY_USAGE_SCOPE("Typography::Style", that);
    MEMORY_USAGE_REPORT(fontFamilies_);
    MEMORY_USAGE_REPORT(ellipsis_);
    MEMORY_USAGE_REPORT(lineStyle_.fontFamilies_);
    MEMORY_USAGE_REPORT(locale_);
}

DECLARE_RMU(VariantSpan)
{
    if (auto ts = that.TryToTextSpan(); ts != nullptr) {
        ReportMemoryUsage(member, *ts, needThis);
    }

    if (auto as = that.TryToAnySpan(); as != nullptr) {
        ReportMemoryUsage(member, *as, needThis);
    }
}

DECLARE_RMU(AnySpan)
{
    that.ReportMemoryUsage(member, needThis);
}

DECLARE_CLASS_RMU(AnySpan)
{
    MEMORY_USAGE_SCOPE("AnySpan", *this);
}

DECLARE_RMU(Typography)
{
    that.ReportMemoryUsage(member, needThis);
}

DECLARE_CLASS_RMU(TypographyImpl)
{
    MEMORY_USAGE_SCOPE("TypographyImpl", *this);
    MEMORY_USAGE_REPORT(lineMetrics_);
    MEMORY_USAGE_REPORT(typographyStyle_);
    MEMORY_USAGE_REPORT(spans_);
    MEMORY_USAGE_REPORT(fontProviders_);
}

DECLARE_RMU(FontProviders)
{
    MEMORY_USAGE_SCOPE("FontProviders", that);
    MEMORY_USAGE_REPORT(providers_);
    MEMORY_USAGE_REPORT(fontStyleSetCache_);
}

DECLARE_RMU(IFontProvider)
{
    that.ReportMemoryUsage(member, needThis);
}

DECLARE_CLASS_RMU(IFontProvider)
{
    MEMORY_USAGE_SCOPE("IFontProvider", *this);
}

DECLARE_CLASS_RMU(DynamicFontProvider)
{
    MEMORY_USAGE_SCOPE("DynamicFontProvider", *this);
    MEMORY_USAGE_REPORT(fontStyleSetMap_);
}

DECLARE_CLASS_RMU(SystemFontProvider)
{
    MEMORY_USAGE_SCOPE("SystemFontProvider", *this);
}

DECLARE_RMU(TextSpan)
{
    MEMORY_USAGE_SCOPE("TextSpan", that);
    MEMORY_USAGE_REPORT(typeface_);
    MEMORY_USAGE_REPORT(u16vect_);
    MEMORY_USAGE_REPORT(glyphWidths_);
    MEMORY_USAGE_REPORT(cgs_);
}

DECLARE_RMU(Typeface)
{
    MEMORY_USAGE_SCOPE("Typeface", that);
    MEMORY_USAGE_REPORT(hblob_);
    MEMORY_USAGE_REPORT(cmapParser_);
}

DECLARE_RMU(hb_blob_t *)
{
    if (that == nullptr) {
        return;
    }
    DoReportMemoryUsage(member, hb_blob_get_length(const_cast<hb_blob_t *>(that)));
}

DECLARE_RMU(CharGroups)
{
    MEMORY_USAGE_SCOPE("CharGroups", that);
    MEMORY_USAGE_REPORT(pcgs_);
}

DECLARE_RMU(struct TextStyle)
{
    MEMORY_USAGE_SCOPE("TextSpan::Style", that);
    MEMORY_USAGE_REPORT(fontFamilies_);
    MEMORY_USAGE_REPORT(shadows_);
    MEMORY_USAGE_REPORT(fontFeature_);
}

DECLARE_RMU(CmapParser)
{
    MEMORY_USAGE_SCOPE("CmapParser", that);
    MEMORY_USAGE_REPORT(ranges_);
}

DECLARE_RMU(CharGroup)
{
    MEMORY_USAGE_SCOPE("CharGroup", that);
    MEMORY_USAGE_REPORT(chars_);
    MEMORY_USAGE_REPORT(glyphs_);
    MEMORY_USAGE_REPORT(typeface_);
}

DECLARE_RMU(FontFeatures)
{
    MEMORY_USAGE_SCOPE("FontFeatures", that);
    MEMORY_USAGE_REPORT(features_);
}

DECLARE_RMU(Ranges)
{
    MEMORY_USAGE_SCOPE("Ranges", that);
    MEMORY_USAGE_REPORT(ranges_);
    MEMORY_USAGE_REPORT(singles_);
}

#ifdef TEXGINE_ENABLE_MEMORY
DEFINE_RMU(struct Ranges::Range);
#endif
} // namespace TextEngine
} // namespace OHOS
