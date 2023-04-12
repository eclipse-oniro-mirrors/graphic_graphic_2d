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

#include <texgine/dynamic_file_font_provider.h>
#include <texgine/system_font_provider.h>
#include <texgine/typography_builder.h>

#include "feature_test_framework.h"

using namespace OHOS::Rosen::TextEngine;

namespace {
constexpr auto exampleText = "Hello 1234";

struct FeatureInfo {
    std::string path = "";
    std::string fontFamily;
    std::string title_ = "";
    std::map<std::string, int> features;
} infos[] = {
    {
        .title_ = "default",
    },
    {
        .path = RESOURCE_PATH_PREFIX "Roboto-Black.ttf",
        .fontFamily = "Roboto",
        .title_ = "Roboto, pnum",
        .features = {std::pair<std::string, int>("pnum", 1),},
    },
    {
        .path = RESOURCE_PATH_PREFIX "Roboto-Black.ttf",
        .fontFamily = "Roboto",
        .title_ = "Roboto, tnum",
        .features = {std::pair<std::string, int>("tnum", 1),},
    },
    {
        .path = RESOURCE_PATH_PREFIX "Roboto-Black.ttf",
        .fontFamily = "Roboto",
        .title_ = "Roboto, pnum 1, pnum 0, tnum 1",
        .features = {
            std::pair<std::string, int>("pnum", 1),
            std::pair<std::string, int>("pnum", 0),
            std::pair<std::string, int>("tnum", 1),
        },
    },
};

class FeatureTest : public TestFeature {
public:
    FeatureTest() : TestFeature("FeatureTest")
    {
    }

    void Layout()
    {
        for (const auto &info : infos) {
            auto dfprovider = DynamicFileFontProvider::Create();
            dfprovider->LoadFont(info.fontFamily, info.path);
            auto fps = FontProviders::Create();
            fps->AppendFontProvider(dfprovider);
            fps->AppendFontProvider(SystemFontProvider::GetInstance());
            auto builder = TypographyBuilder::Create({}, std::move(fps));

            TextStyle style;
            style.fontFamilies_ = {info.fontFamily};
            style.fontSize_ = 64;
            for (const auto &[feature, value] : info.features) {
                style.fontFeature_.SetFeature(feature, value);
            }

            builder->PushStyle(style);
            builder->AppendSpan(exampleText);
            builder->PopStyle();
            auto typography = builder->Build();
            typography->Layout(300);
            typographies_.push_back({
                .typography = typography,
                .comment = info.title_,
            });
        }
    }
} g_test;
} // namespace
