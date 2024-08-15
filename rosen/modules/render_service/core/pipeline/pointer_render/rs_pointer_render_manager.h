/*
 * Copyright (c) 2024-2024 Huawei Device Co., Ltd.
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

#ifndef RS_POINTER_RENDER_MANAGER_H
#define RS_POINTER_RENDER_MANAGER_H

#include "ipc_callbacks/pointer_render/pointer_luminance_change_callback.h"
#include "pipeline/rs_display_render_node.h"
#include "pipeline/rs_processor.h"
#ifdef RS_ENABLE_VK
#include "pipeline/rs_vk_image_manager.h"
#endif

namespace OHOS::Rosen {

class RSPointerRenderManager {
public:
    RSPointerRenderManager();
    ~RSPointerRenderManager() = default;

#if defined (RS_ENABLE_VK)
    static void InitInstance(const std::shared_ptr<RSVkImageManager>& vkImageManager);
#endif

#if defined (RS_ENABLE_GL) && defined (RS_ENABLE_EGLIMAGE)
    static void InitInstance(const std::shared_ptr<RSEglImageManager>& eglImageManager);
#endif

    static RSPointerRenderManager& GetInstance();
    static int64_t GetCurrentTime();
    void ProcessColorPicker(std::shared_ptr<RSProcessor> processor, std::shared_ptr<Drawing::GPUContext> gpuContext);
    void SetPointerColorInversionConfig(float darkBuffer, float brightBuffer, int64_t interval, int32_t rangeSize);
    void SetPointerColorInversionEnabled(bool enable);
    void RegisterPointerLuminanceChangeCallback(pid_t pid, sptr<RSIPointerLuminanceChangeCallback> callback);
    void UnRegisterPointerLuminanceChangeCallback(pid_t pid);
    void SetCacheImgForPointer(std::shared_ptr<Drawing::Image> cacheImgForPointer)
    {
        cacheImgForPointer_ = cacheImgForPointer;
    }

private:
    void ExecutePointerLuminanceChangeCallback(int32_t brightness);
    void CallPointerLuminanceChange(int32_t brightness);
    bool CheckColorPickerEnabled();
    void CalculateColorRange(RectI& pRect);
    bool CalculateTargetLayer(std::shared_ptr<RSProcessor> processor);
    void RunColorPickerTask();
    std::shared_ptr<Drawing::Image> GetIntersectImageByLayer(const BufferDrawParam& param);
    bool GetIntersectImageBySubset(std::shared_ptr<Drawing::GPUContext> gpuContext);
#if defined (RS_ENABLE_VK)
    std::shared_ptr<Drawing::Image> GetIntersectImageFromVK(Drawing::RectI& imgCutRect,
    std::shared_ptr<Drawing::GPUContext>& context, const BufferDrawParam& param);
#endif
#if defined (RS_ENABLE_GL) && defined (RS_ENABLE_EGLIMAGE)
    std::shared_ptr<Drawing::Image> GetIntersectImageFromGL(Drawing::RectI& imgCutRect,
    std::shared_ptr<Drawing::GPUContext>& context, const BufferDrawParam& param);
#endif
    std::shared_ptr<Drawing::Image> GetImageTexture(std::shared_ptr<Drawing::Image>& image);
    void GetRectAndTargetLayer(std::vector<LayerInfoPtr>& layers, RectI& pRect, int displayNodeIndex);
    void RunColorPickerTaskBackground(BufferDrawParam& param);

private:
    RectI rect_;
    LayerInfoPtr target_;
    std::shared_ptr<RSColorPickerCacheTask> colorPickerTask_;
#if defined (RS_ENABLE_VK)
    std::shared_ptr<RSVkImageManager> vkImageManager_ = nullptr;
#endif
#if defined (RS_ENABLE_GL) && defined (RS_ENABLE_EGLIMAGE)
    std::shared_ptr<RSEglImageManager> eglImageManager_ = nullptr;
#endif
    int16_t luminance_ = 0;
    bool forceCPU_ = false;
    std::shared_ptr<Drawing::Image> image_ = nullptr;
    std::atomic<bool> taskDoing_ = false;
    bool isEnableCursorInversion_ = false;
    std::shared_ptr<Drawing::Image> cacheImgForPointer_ = nullptr;
    std::mutex mtx_;
    std::mutex cursorInvertMutex_;
    std::map<pid_t, sptr<RSIPointerLuminanceChangeCallback>> colorChangeListeners_;
    enum class CursorBrightness {
        NONE,
        BRIGHT,
        DARK
    };
    CursorBrightness brightnessMode_ = CursorBrightness::NONE;
    int64_t lastColorPickerTime_ = 0;
    int64_t colorSamplingInterval_ = 50;
    int32_t rangeSize_ = 0;
    float darkBuffer_ = 0.58f;
    float brightBuffer_ = 0.40f;
};
}
#endif // RS_POINTER_RENDER_MANAGER_H