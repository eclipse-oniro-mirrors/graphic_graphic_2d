/*
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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
#ifndef RENDER_SERVICE_CLIENT_CORE_COMMON_RS_OBJ_ABS_GEOMETRY_H
#define RENDER_SERVICE_CLIENT_CORE_COMMON_RS_OBJ_ABS_GEOMETRY_H

#include <memory>
#include <optional>

#include "utils/matrix.h"
#include "utils/matrix44.h"
#include "utils/point.h"

#include "common/rs_macros.h"
#include "common/rs_matrix3.h"
#include "common/rs_obj_geometry.h"
#include "common/rs_rect.h"
#include "common/rs_occlusion_region.h"
#include "common/rs_vector2.h"

namespace OHOS {
namespace Rosen {
class RSB_EXPORT RSObjAbsGeometry : public RSObjGeometry {
public:
    RSObjAbsGeometry();
    ~RSObjAbsGeometry() override;
    void ConcatMatrix(const Drawing::Matrix& matrix);
    void UpdateMatrix(const Drawing::Matrix* parentMatrix, const std::optional<Drawing::Point>& offset);

    // Using by RenderService
    void UpdateByMatrixFromSelf();

    const RectI& GetAbsRect() const
    {
        return absRect_;
    }
    RectI MapAbsRectWithMatrix(const RectF& rect, const Drawing::Matrix& matrix) const;
    RectI MapAbsRect(const RectF& rect) const;
    Occlusion::Region MapAbsRegion(const Occlusion::Region& region) const;

    // Converts RectF to RectI by inward rounding (ceil for left/top, floor for right/bottom)
    // to ensure the resulting integer rect is fully contained within the original floating-point rect.
    // attention: used in render node's opaque area calculations
    static RectI DeflateToRectI(const RectF& rect);

    // Converts a RectF to RectI by outward rounding (floor for left/top, ceil for right/bottom)
    // to ensure the original floating-point rect is fully contained within the resulting integer rect.
    // attention: used in render node's draw area calculations
    static RectI InflateToRectI(const RectF& rect);

    static RectF MapRectWithoutRounding(const RectF& rect, const Drawing::Matrix& matrix);
    static RectI MapRect(const RectF& rect, const Drawing::Matrix& matrix);
    static Occlusion::Region MapRegion(const Occlusion::Region& region, const Drawing::Matrix& matrix);

    // return transform matrix (context + self)
    // warning: If the parent node does not have the SandBox attribute, this interface does
    // NOT cause problems. Otherwise, you need to use the GetAbsMatrix interface to multiply
    // the AbsMatrix of the parent node by the left to obtain the matrix of the parent node.
    const Drawing::Matrix& GetMatrix() const;
    // return transform matrix (parent + context + self)
    const Drawing::Matrix& GetAbsMatrix() const;

    bool IsNeedClientCompose() const;

    void SetContextMatrix(const std::optional<Drawing::Matrix>& matrix);

private:
    void UpdateAbsMatrix2D();
    void UpdateAbsMatrix3D();
    void SetAbsRect();

    static Vector2f GetDataRange(float d0, float d1, float d2, float d3);

    RectI absRect_;
    Drawing::Matrix matrix_;
    std::optional<Drawing::Matrix> absMatrix_;
    std::optional<Drawing::Matrix> contextMatrix_;
};
} // namespace Rosen
} // namespace OHOS
#endif // RENDER_SERVICE_CLIENT_CORE_COMMON_RS_OBJ_ABS_GEOMETRY_H
