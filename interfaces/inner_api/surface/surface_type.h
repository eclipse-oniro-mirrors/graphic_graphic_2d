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

#ifndef INTERFACES_INNERKITS_SURFACE_SURFACE_TYPE_H
#define INTERFACES_INNERKITS_SURFACE_SURFACE_TYPE_H

#include <cstdint>
#include <string>
#include <vector>

#include <graphic_common.h>
#include <display_type.h>

namespace OHOS {
#define SURFACE_MAX_USER_DATA_COUNT 1000
#define SURFACE_MAX_QUEUE_SIZE 32
#define SURFACE_DEFAULT_QUEUE_SIZE 3
#define SURFACE_MAX_STRIDE_ALIGNMENT 32
#define SURFACE_MIN_STRIDE_ALIGNMENT 4
#define SURFACE_DEFAULT_STRIDE_ALIGNMENT 4
#define SURFACE_MAX_SIZE 58982400 // 8K * 8K

/*
 * @brief Defines the buffer usage.
 */
enum {
    GRAPHIC_USAGE_CPU_READ = (1 << 0),        /**< CPU read buffer */
    GRAPHIC_USAGE_CPU_WRITE = (1 << 1),       /**< CPU write memory */
    GRAPHIC_USAGE_MEM_MMZ = (1 << 2),         /**< Media memory zone (MMZ) */
    GRAPHIC_USAGE_MEM_DMA = (1 << 3),         /**< Direct memory access (DMA) buffer */
    GRAPHIC_USAGE_MEM_SHARE = (1 << 4),       /**< Shared memory buffer*/
    GRAPHIC_USAGE_MEM_MMZ_CACHE = (1 << 5),   /**< MMZ with cache*/
    GRAPHIC_USAGE_MEM_FB = (1 << 6),          /**< Framebuffer */
    GRAPHIC_USAGE_ASSIGN_SIZE = (1 << 7),     /**< Memory assigned */
} GraphicBufferUsageType;

/*
 * @brief Enumerates the composition type of a special layer.
 */
typedef enum {
    GRAPHIC_COMPOSITION_CLIENT,       /**< Client composition type. The composer should be the CPU or GPU. */
    GRAPHIC_COMPOSITION_DEVICE,       /**< Device composition type. The composer should be the hardware. */
    GRAPHIC_COMPOSITION_CURSOR,       /**< Cursor composition type, used for cursor. */
    GRAPHIC_COMPOSITION_VIDEO,        /**< Video composition type, used for video. */
    GRAPHIC_COMPOSITION_DEVICE_CLEAR, /**< Device clear composition type, the device will clear the target region. */
    GRAPHIC_COMPOSITION_CLIENT_CLEAR, /**< Client clear composition type, the service will clear the target region. */
    GRAPHIC_COMPOSITION_TUNNEL,       /**< Tunnel composition type, used for tunnel. */
    GRAPHIC_COMPOSITION_BUTT
} GraphicCompositionType;

/*
 * @brief Defines alpha information about a layer.
 */
typedef struct {
    bool enGlobalAlpha;   /**< Global alpha enable bit */
    bool enPixelAlpha;    /**< Pixel alpha enable bit */
    uint8_t alpha0;       /**< Alpha0 value, ranging from 0 to 255 */
    uint8_t alpha1;       /**< Alpha1 value, ranging from 0 to 255 */
    uint8_t gAlpha;       /**< Global alpha value, ranging from 0 to 255 */
} GraphicLayerAlpha;

/*
 * @brief Enumerates layer blending types.
 * The system combines layers based on a specified blending type during hardware acceleration.
 */
typedef enum {
    GRAPHIC_BLEND_NONE = 0,         /**< No blending */
    GRAPHIC_BLEND_CLEAR,            /**< CLEAR blending */
    GRAPHIC_BLEND_SRC,              /**< SRC blending */
    GRAPHIC_BLEND_SRCOVER,          /**< SRC_OVER blending */
    GRAPHIC_BLEND_DSTOVER,          /**< DST_OVER blending */
    GRAPHIC_BLEND_SRCIN,            /**< SRC_IN blending */
    GRAPHIC_BLEND_DSTIN,            /**< DST_IN blending */
    GRAPHIC_BLEND_SRCOUT,           /**< SRC_OUT blending */
    GRAPHIC_BLEND_DSTOUT,           /**< DST_OUT blending */
    GRAPHIC_BLEND_SRCATOP,          /**< SRC_ATOP blending */
    GRAPHIC_BLEND_DSTATOP,          /**< DST_ATOP blending */
    GRAPHIC_BLEND_ADD,              /**< ADD blending */
    GRAPHIC_BLEND_XOR,              /**< XOR blending */
    GRAPHIC_BLEND_DST,              /**< DST blending */
    GRAPHIC_BLEND_AKS,              /**< AKS blending */
    GRAPHIC_BLEND_AKD,              /**< AKD blending */
    GRAPHIC_BLEND_BUTT              /**< Null operation */
} GraphicBlendType;

/*
 * @brief Enumerates image pixel formats.
 */
typedef enum {
    GRAPHIC_PIXEL_FMT_CLUT8 = 0,                 /**< CLUT8 format */
    GRAPHIC_PIXEL_FMT_CLUT1,                     /**< CLUT1 format */
    GRAPHIC_PIXEL_FMT_CLUT4,                     /**< CLUT4 format */
    GRAPHIC_PIXEL_FMT_RGB_565,                   /**< RGB565 format */
    GRAPHIC_PIXEL_FMT_RGBA_5658,                 /**< RGBA5658 format */
    GRAPHIC_PIXEL_FMT_RGBX_4444,                 /**< RGBX4444 format */
    GRAPHIC_PIXEL_FMT_RGBA_4444,                 /**< RGBA4444 format */
    GRAPHIC_PIXEL_FMT_RGB_444,                   /**< RGB444 format */
    GRAPHIC_PIXEL_FMT_RGBX_5551,                 /**< RGBX5551 format */
    GRAPHIC_PIXEL_FMT_RGBA_5551,                 /**< RGBA5551 format */
    GRAPHIC_PIXEL_FMT_RGB_555,                   /**< RGB555 format */
    GRAPHIC_PIXEL_FMT_RGBX_8888,                 /**< RGBX8888 format */
    GRAPHIC_PIXEL_FMT_RGBA_8888,                 /**< RGBA8888 format */
    GRAPHIC_PIXEL_FMT_RGB_888,                   /**< RGB888 format */
    GRAPHIC_PIXEL_FMT_BGR_565,                   /**< BGR565 format */
    GRAPHIC_PIXEL_FMT_BGRX_4444,                 /**< BGRX4444 format */
    GRAPHIC_PIXEL_FMT_BGRA_4444,                 /**< BGRA4444 format */
    GRAPHIC_PIXEL_FMT_BGRX_5551,                 /**< BGRX5551 format */
    GRAPHIC_PIXEL_FMT_BGRA_5551,                 /**< BGRA5551 format */
    GRAPHIC_PIXEL_FMT_BGRX_8888,                 /**< BGRX8888 format */
    GRAPHIC_PIXEL_FMT_BGRA_8888,                 /**< BGRA8888 format */
    GRAPHIC_PIXEL_FMT_YUV_422_I,                 /**< YUV422 interleaved format */
    GRAPHIC_PIXEL_FMT_YCBCR_422_SP,              /**< YCBCR422 semi-planar format */
    GRAPHIC_PIXEL_FMT_YCRCB_422_SP,              /**< YCRCB422 semi-planar format */
    GRAPHIC_PIXEL_FMT_YCBCR_420_SP,              /**< YCBCR420 semi-planar format */
    GRAPHIC_PIXEL_FMT_YCRCB_420_SP,              /**< YCRCB420 semi-planar format */
    GRAPHIC_PIXEL_FMT_YCBCR_422_P,               /**< YCBCR422 planar format */
    GRAPHIC_PIXEL_FMT_YCRCB_422_P,               /**< YCRCB422 planar format */
    GRAPHIC_PIXEL_FMT_YCBCR_420_P,               /**< YCBCR420 planar format */
    GRAPHIC_PIXEL_FMT_YCRCB_420_P,               /**< YCRCB420 planar format */
    GRAPHIC_PIXEL_FMT_YUYV_422_PKG,              /**< YUYV422 packed format */
    GRAPHIC_PIXEL_FMT_UYVY_422_PKG,              /**< UYVY422 packed format */
    GRAPHIC_PIXEL_FMT_YVYU_422_PKG,              /**< YVYU422 packed format */
    GRAPHIC_PIXEL_FMT_VYUY_422_PKG,              /**< VYUY422 packed format */
    GRAPHIC_PIXEL_FMT_VENDER_MASK = 0X7FFF0000,  /**< vendor mask format */
    GRAPHIC_PIXEL_FMT_BUTT = 0X7FFFFFFF          /**< Invalid pixel format */
} GraphicPixelFormat;

/*
 * @brief Enumerates hdi layer types.
 */
typedef enum {
    GRAPHIC_LAYER_TYPE_GRAPHIC,         /**< Graphic layer */
    GRAPHIC_LAYER_TYPE_OVERLAY,         /**< Overlay layer */
    GRAPHIC_LAYER_TYPE_SDIEBAND,        /**< Sideband layer */
    GRAPHIC_LAYER_TYPE_CURSOR,          /**< Cursor Layer */
    GRAPHIC_LAYER_TYPE_BUTT             /**< Empty layer */
} GraphicLayerType;

/*
 * @brief Defines hdi layer information.
 * <b>HdiLayerInfo</b> must be passed to the function, which creates a layer based on the hdi layer info.
 */
typedef struct {
    int32_t width;                /**< Layer width */
    int32_t height;               /**< Layer height */
    GraphicLayerType type;        /**< Layer type, which can be a graphic layer, overlay layer, or sideband layer */
    int32_t bpp;                  /**< Number of bits occupied by each pixel */
    GraphicPixelFormat pixFormat; /**< Pixel format of the layer */
} GraphicLayerInfo;

/*
 * @brief Defines information about the memory to allocate.
 */
typedef struct {
    uint32_t width;                 /**< Width of the requested memory */
    uint32_t height;                /**< Height of the requested memory */
    uint64_t usage;                 /**< Usage of the requested memory */
    GraphicPixelFormat format;      /**< Format of the requested memory */
    uint32_t expectedSize;          /**< Size assigned by memory requester */
} BufferAllocInfo;

/*
 * @brief Defines information for verifying the memory to allocate.
 */
typedef struct {
    uint32_t width;               /**< Width of the memory to allocate */
    uint32_t height;              /**< Height of the memory to allocate */
    uint64_t usage;               /**< Usage of the memory */
    GraphicPixelFormat format;    /**< Format of the memory to allocate */
} BufferVerifyAllocInfo;

/*
 * @brief Enumerates the present timestamp types.
 */
typedef enum {
    GRAPHIC_DISPLAY_PTS_UNSUPPORTED = 0,        /**< Unsupported */
    GRAPHIC_DISPLAY_PTS_DELAY = 1 << 0,         /**< Delay */
    GRAPHIC_DISPLAY_PTS_TIMESTAMP = 1 << 1,     /**< Timestamp */
} GraphicPresentTimestampType;

/*
 * @brief Defines the present timestamp.
 */
typedef struct {
    GraphicPresentTimestampType type;     /**< Present timestamp type */
    int64_t time;                         /**< Present timestamp value */
} GraphicPresentTimestamp;

using Rect = struct Rect {
    int32_t x;
    int32_t y;
    int32_t w;
    int32_t h;
};

using ScalingMode = enum {
    SCALING_MODE_FREEZE = 0,
    SCALING_MODE_SCALE_TO_WINDOW,
    SCALING_MODE_SCALE_CROP,
    SCALING_MODE_NO_SCALE_CROP,
};

using HDRMetaDataType = enum {
    HDR_NOT_USED = 0,
    HDR_META_DATA,
    HDR_META_DATA_SET,
};

typedef enum : uint32_t {
    GRAPHIC_MATAKEY_RED_PRIMARY_X = 0,
    GRAPHIC_MATAKEY_RED_PRIMARY_Y = 1,
    GRAPHIC_MATAKEY_GREEN_PRIMARY_X = 2,
    GRAPHIC_MATAKEY_GREEN_PRIMARY_Y = 3,
    GRAPHIC_MATAKEY_BLUE_PRIMARY_X = 4,
    GRAPHIC_MATAKEY_BLUE_PRIMARY_Y = 5,
    GRAPHIC_MATAKEY_WHITE_PRIMARY_X = 6,
    GRAPHIC_MATAKEY_WHITE_PRIMARY_Y = 7,
    GRAPHIC_MATAKEY_MAX_LUMINANCE = 8,
    GRAPHIC_MATAKEY_MIN_LUMINANCE = 9,
    GRAPHIC_MATAKEY_MAX_CONTENT_LIGHT_LEVEL = 10,
    GRAPHIC_MATAKEY_MAX_FRAME_AVERAGE_LIGHT_LEVEL = 11,
    GRAPHIC_MATAKEY_HDR10_PLUS = 12,
    GRAPHIC_MATAKEY_HDR_VIVID = 13,
} GraphicHDRMetadataKey;

using HDRMetaDataSet = struct HDRMetaDataSet {
    GraphicHDRMetadataKey key = GraphicHDRMetadataKey::GRAPHIC_MATAKEY_RED_PRIMARY_X;
    std::vector<uint8_t> metaData;
};

typedef enum {
    GRAPHIC_COLOR_GAMUT_INVALID = -1,            /**< Invalid */
    GRAPHIC_COLOR_GAMUT_NATIVE = 0,              /**< Native or default */
    GRAPHIC_COLOR_GAMUT_STANDARD_BT601 = 1,      /**< Standard BT601 */
    GRAPHIC_COLOR_GAMUT_STANDARD_BT709 = 2,      /**< Standard BT709 */
    GRAPHIC_COLOR_GAMUT_DCI_P3 = 3,              /**< DCI P3 */
    GRAPHIC_COLOR_GAMUT_SRGB = 4,                /**< SRGB */
    GRAPHIC_COLOR_GAMUT_ADOBE_RGB = 5,           /**< Adobe RGB */
    GRAPHIC_COLOR_GAMUT_DISPLAY_P3 = 6,          /**< display P3 */
    GRAPHIC_COLOR_GAMUT_BT2020 = 7,              /**< BT2020 */
    GRAPHIC_COLOR_GAMUT_BT2100_PQ = 8,           /**< BT2100 PQ */
    GRAPHIC_COLOR_GAMUT_BT2100_HLG = 9,          /**< BT2100 HLG */
    GRAPHIC_COLOR_GAMUT_DISPLAY_BT2020 = 10,     /**< Display BT2020 */
} GraphicColorGamut;

/**
 * @brief Enumerates transform types of images.
 *
 */
typedef enum {
    GRAPHIC_ROTATE_NONE = 0,        /**< No rotation */
    GRAPHIC_ROTATE_90,              /**< Rotation by 90 degrees */
    GRAPHIC_ROTATE_180,             /**< Rotation by 180 degrees */
    GRAPHIC_ROTATE_270,             /**< Rotation by 270 degrees */
    GRAPHIC_ROTATE_BUTT             /**< Invalid operation */
} GraphicTransformType;

using BufferRequestConfig = struct BufferRequestConfig {
    int32_t width;
    int32_t height;
    int32_t strideAlignment;
    int32_t format; // GraphicPixelFormat
    int32_t usage;
    int32_t timeout;
    GraphicColorGamut colorGamut = GraphicColorGamut::GRAPHIC_COLOR_GAMUT_SRGB;
    GraphicTransformType transform = GraphicTransformType::GRAPHIC_ROTATE_NONE;
    bool operator ==(const struct BufferRequestConfig &config) const
    {
        return width == config.width &&
               height == config.height &&
               strideAlignment == config.strideAlignment &&
               format == config.format &&
               usage == config.usage &&
               timeout == config.timeout &&
               colorGamut == config.colorGamut &&
               transform == config.transform;
    }
    bool operator != (const struct BufferRequestConfig &config) const
    {
        return !(*this == config);
    }
};

using BufferFlushConfig = struct BufferFlushConfig {
    Rect damage;
    int64_t timestamp;
};

using SceneType = enum {
    SURFACE_SCENE_TYPE_EGL = 0,
    SURFACE_SCENE_TYPE_MEDIA,
    SURFACE_SCENE_TYPE_CAMERA,
    SURFACE_SCENE_TYPE_CPU,
};
} // namespace OHOS

#endif // INTERFACES_INNERKITS_SURFACE_SURFACE_TYPE_H
