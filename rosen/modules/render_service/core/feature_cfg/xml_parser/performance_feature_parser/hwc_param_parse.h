/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef HWC_PARAM_PARSE_H
#define HWC_PARAM_PARSE_H

#include "xml_parser_base.h"
#include "hwc_param.h"

namespace OHOS::Rosen {
class HWCParamParse : public XMLParserBase {
public:
    HWCParamParse() = default;
    ~HWCParamParse() = default;

    int32_t ParseFeatureParam(FeatureParamMapType &featureMap, xmlNode &node) override;

private:
    int32_t ParseHwcInternal(FeatureParamMapType &featureMap, xmlNode &node);
    int32_t ParseFeatureMultiParamForApp(xmlNode &node, std::string &name);

    std::shared_ptr<HWCParam> hwcParam_;
};
} // namespace OHOS::Rosen
#endif // HWC_PARAM_PARSE_H