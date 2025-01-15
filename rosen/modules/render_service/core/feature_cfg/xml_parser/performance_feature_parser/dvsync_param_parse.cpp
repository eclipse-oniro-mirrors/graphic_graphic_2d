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

#include "dvsync_param_parse.h"

namespace OHOS::Rosen {

int32_t DvsyncParamParse::ParseFeatureParam(FeatureParamMapType featureMap, xmlNode &node)
{
    RS_LOGI("DvsyncParamParse start");
    xmlNode *currNode = &node;
    if (currNode->xmlChildrenNode == nullptr) {
        RS_LOGD("DvsyncParamParse stop parsing, no children nodes");
        return CCM_GET_CHILD_FAIL;
    }

    currNode = currNode->xmlChildrenNode;
    for (; currNode; currNode = currNode->next) {
        if (currNode->type != XML_ELEMENT_NODE) {
            continue;
        }
        
        if (ParseDvsyncInternal(featureMap, *currNode) != CCM_EXEC_SUCCESS) {
            RS_LOGE("DvsyncParamParse stop parsing, parse internal fail");
            return CCM_PARSE_INTERNAL_FAIL;
        }
    }

    return CCM_EXEC_SUCCESS;
}

int32_t DvsyncParamParse::ParseDvsyncInternal(FeatureParamMapType featureMap, xmlNode &node)
{
    xmlNode *currNode = &node;

    auto iter = featureMap.find("DvsyncConfig");
    if (iter != featureMap.end()) {
        dvsyncParam_ = std::static_pointer_cast<DvsyncParam>(iter->second);
    } else {
        RS_LOGD("DvsyncParamParse stop parsing, no initializing param map");
        return CCM_NO_PARAM;
    }

    // Start Parse Feature Params
    int xmlParamType = GetCcmXmlNodeAsInt(*currNode);
    auto name = ExtractPropertyValue("name", *currNode);
    auto val = ExtractPropertyValue("value", *currNode);
    if (xmlParamType == CCM_XML_FEATURE_SWITCH) {
        bool isEnabled = ParseFeatureSwitch(val);
        if (name == "DvsyncEnabled") {
            dvsyncParam_->SetDvsyncEnable(isEnabled);
            RS_LOGD("DvsyncParamParse parse DvsyncEnabled %{public}d", dvsyncParam_->IsDvsyncEnable());
        } else if (name == "UiDvsyncEnabled") {
            dvsyncParam_->SetUiDvsyncEnable(isEnabled);
            RS_LOGD("DvsyncParamParse parse UiDvsyncEnabled %{public}d", dvsyncParam_->IsUiDvsyncEnable());
        } else if (name == "NativeDvsyncEnabled") {
            dvsyncParam_->SetNativeDvsyncEnable(isEnabled);
            RS_LOGD("DvsyncParamParse parse NativeDvsyncEnabled %{public}d", dvsyncParam_->IsNativeDvsyncEnable());
        }
    } else if (xmlParamType == CCM_XML_FEATURE_SINGLEPARAM) {
        if (name == "DvsyncRsPreCnt") {
            dvsyncParam_->SetRsPreCount(std::atoi(val.c_str()));
            RS_LOGD("DvsyncParamParse parse dvsyncRsPreCnt %{public}d", dvsyncParam_->GetRsPreCount());
        } else if (name == "DvsyncAppPreCnt") {
            dvsyncParam_->SetAppPreCount(std::atoi(val.c_str()));
            RS_LOGD("DvsyncParamParse parse DvsyncAppPreCnt %{public}d", dvsyncParam_->GetAppPreCount());
        } else if (name == "DvsyncNativePreCnt") {
            dvsyncParam_->SetNativePreCount(std::atoi(val.c_str()));
            RS_LOGD("DvsyncParamParse parse dvsyncNativePreCnt %{public}d", dvsyncParam_->GetNativePreCount());
        }
    }

    return CCM_EXEC_SUCCESS;
}
} // namespace OHOS::Rosen