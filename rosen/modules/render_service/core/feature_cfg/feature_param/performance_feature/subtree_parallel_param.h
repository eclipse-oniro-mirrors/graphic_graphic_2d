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

#ifndef SUBTREE_PARAM_H
#define SUBTREE_PARAM_H

#include "feature_param.h"

namespace OHOS::Rosen {
class SubtreeParallelParam : public FeatureParam {
public:
    SubtreeParallelParam() = default;
    ~SubtreeParallelParam() = default;

    static bool GetSubtreeEnable();
    static bool GetRBPolicyEnabled();
    static bool GetMultiWinPolicyEnabled();
    static int GetMultiWinSurfaceNum();
    static int GetRBChildrenWeight();
    static int GetRBSubtreeWeight();
    static std::unordered_map<std::string, std::string> GetSubtreeScene();

protected:
    static void SetSubtreeEnable(bool isSubtreeEnable);
    static void SetMultiWinPolicyEnabled(bool isMultiWinPolicyEnable);
    static void SetRBPolicyEnabled(bool isRBPolicyEnable);
    static void SetMultiWinSurfaceNum(int surfaceNum);
    static void SetRBChildrenWeight(int weight);
    static void SetRBSubtreeWeight(int weight);
    static void SetSubtreeScene(const std::string& appName, const std::string& val);

private:
    inline static bool isSubtreeEnable_ = false;
    inline static bool isMultiWinPolicyEnable_ = false;
    inline static bool isRBPolicyEnable_ = false;
    inline static int multiWinSurfaceNum_ = -1;
    inline static int rbChildrenWeight_ = -1;
    inline static int rbSubTreeWeight_ = -1;
    // <"pkgName", "1">
    inline static std::unordered_map<std::string, std::string> subtreeScene_ = {};

    friend class SubtreeParallelParamParse;
};
} // namespace OHOS::Rosen
#endif // SUBTREE_PARAM_H