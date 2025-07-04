/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include "cj_filter.h"
#include "filter/include/filter_blur_para.h"
#include "filter/include/filter_dispersion_para.h"
#include "filter/include/filter_displacement_distort_para.h"
#include "filter/include/filter_hdr_para.h"
#include "filter/include/filter_pixel_stretch_para.h"
#include "filter/include/filter_radius_gradient_blur_para.h"

namespace OHOS {
namespace Rosen {
using namespace UIEffect;
CJFilter::CJFilter()
{
    std::shared_ptr<Filter> filterObj = std::make_shared<Filter>();
    m_FilterObj = filterObj;
}

void CJFilter::SetBlur(float blur, int32_t* errCode)
{
    if (m_FilterObj == nullptr) {
        *errCode = CJ_ERR_NULL_PTR;
        return;
    }
    std::shared_ptr<FilterBlurPara> para = std::make_shared<FilterBlurPara>();
    para->SetRadius(blur);
    m_FilterObj->AddPara(para);
}
} // namespace Rosen
} // namespace OHOS