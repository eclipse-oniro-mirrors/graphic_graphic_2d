/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#ifndef HDI_BACKEND_HDI_LAYER_H
#define HDI_BACKEND_HDI_LAYER_H

#include <array>
#include <stdint.h>
#include <surface.h>
#include "hdi_device.h"
#include "hdi_layer_info.h"


namespace OHOS {
namespace Rosen {

using LayerInfoPtr = std::shared_ptr<HdiLayerInfo>;
struct FPSInfo {
    int64_t presentTime;
    std::vector<std::string> windowsName;
};

class HdiLayer {
public:
    explicit HdiLayer(uint32_t screenId);
    virtual ~HdiLayer();

    static constexpr int FRAME_RECORDS_NUM = 384;

    /* output create and set layer info */
    static std::shared_ptr<HdiLayer> CreateHdiLayer(uint32_t screenId);

    bool Init(const LayerInfoPtr &layerInfo);
    void MergeWithFramebufferFence(const sptr<SyncFence> &fbAcquireFence);
    void MergeWithLayerFence(const sptr<SyncFence> &layerReleaseFence);
    void UpdateCompositionType(GraphicCompositionType type);

    const LayerInfoPtr GetLayerInfo();
    void SetLayerStatus(bool inUsing);
    bool GetLayerStatus() const;
    void UpdateLayerInfo(const LayerInfoPtr &layerInfo);
    int32_t SetHdiLayerInfo(bool isActiveRectSwitching = false);
    uint32_t GetLayerId() const;
    bool RecordPresentTime(int64_t timestamp);
    void RecordMergedPresentTime(int64_t timestamp); // used for uni render layer
    void Dump(std::string &result);
    void DumpMergedResult(std::string &result);  // used for uni render layer
    void ClearDump();

    void SetReleaseFence(const sptr<SyncFence> &layerReleaseFence);
    sptr<SyncFence> GetReleaseFence() const;
    void SavePrevLayerInfo();
    void DumpByName(std::string windowName, std::string &result);
    void SelectHitchsInfo(std::string windowName, std::string &result);

    /* only used for mock tests */
    int32_t SetHdiDeviceMock(HdiDevice* hdiDeviceMock);
    void ClearBufferCache();
private:
    // layer buffer & fence
    class LayerBufferInfo : public RefBase {
    public:
        LayerBufferInfo() = default;
        virtual ~LayerBufferInfo() = default;

        sptr<SurfaceBuffer> sbuffer_ = nullptr;
        sptr<SyncFence> releaseFence_ = SyncFence::InvalidFence();
    };

    std::array<FPSInfo, FRAME_RECORDS_NUM> presentTimeRecords_ {};
    uint32_t count_ = 0;
    std::array<int64_t, FRAME_RECORDS_NUM> mergedPresentTimeRecords_ {}; // used for uni render layer
    uint32_t mergedCount_ = 0; // used for uni render layer
    uint32_t screenId_ = INT_MAX;
    uint32_t layerId_ = INT_MAX;
    bool isInUsing_ = false;
    sptr<LayerBufferInfo> currBufferInfo_ = nullptr;
    sptr<SurfaceBuffer> prevSbuffer_ = nullptr;
    LayerInfoPtr layerInfo_ = nullptr;
    LayerInfoPtr prevLayerInfo_ = nullptr;
    GraphicPresentTimestampType supportedPresentTimestamptype_ = GRAPHIC_DISPLAY_PTS_UNSUPPORTED;
    HdiDevice *device_ = nullptr;
    bool doLayerInfoCompare_ = false;

    std::vector<uint32_t> bufferCache_;
    uint32_t bufferCacheCountMax_ = 0;
    mutable std::mutex mutex_;
    sptr<SurfaceBuffer> currBuffer_ = nullptr;
    bool bufferCleared_ = false;

    int32_t CreateLayer(const LayerInfoPtr &layerInfo);
    void CloseLayer();
    int32_t SetLayerAlpha();
    int32_t SetLayerSize();
    int32_t SetTransformMode();
    int32_t SetLayerVisibleRegion();
    int32_t SetLayerDirtyRegion();
    int32_t SetLayerBuffer();
    int32_t SetLayerCompositionType();
    int32_t SetLayerBlendType();
    int32_t SetLayerCrop();
    int32_t SetLayerZorder();
    int32_t SetLayerPreMulti();
    int32_t SetLayerColor();
    int32_t SetLayerColorTransform();
    int32_t SetLayerColorDataSpace();
    int32_t SetLayerMetaData();
    int32_t SetLayerMetaDataSet();
    sptr<SyncFence> Merge(const sptr<SyncFence> &fence1, const sptr<SyncFence> &fence2);
    int32_t SetLayerTunnelHandle();
    int32_t SetTunnelLayerId();
    int32_t SetTunnelLayerProperty();
    int32_t SetLayerPresentTimestamp();
    int32_t InitDevice();
    bool IsSameLayerMetaData();
    bool IsSameLayerMetaDataSet();
    inline void CheckRet(int32_t ret, const char* func);
    int32_t SetLayerMaskInfo();
    bool CheckAndUpdateLayerBufferCahce(uint32_t sequence, uint32_t& index,
                                        std::vector<uint32_t>& deletingList);

    int32_t SetPerFrameParameters();
    int32_t SetPerFrameParameterSdrNit();
    int32_t SetPerFrameParameterDisplayNit();
    int32_t SetPerFrameParameterBrightnessRatio();
    int32_t SetPerFrameLayerLinearMatrix();
    int32_t SetPerFrameLayerSourceTuning(); // used for source crop tuning
};
} // namespace Rosen
} // namespace OHOS

#endif // HDI_BACKEND_HDI_LAYER_H