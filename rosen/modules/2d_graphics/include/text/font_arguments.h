/*
 * Copyright 2017 Google Inc.
 *
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#ifndef RSFontArguments_DEFINED
#define RSFontArguments_DEFINED

#include <cstdint>

namespace OHOS {
namespace Rosen {
namespace Drawing {
/** Represents a set of actual arguments for a font. */
struct FontArguments {
    struct VariationPosition {
        struct Coordinate {
            uint32_t axis;
            float value;
        };
        const Coordinate* coordinates;
        int coordinateCount;
    };

    /** Specify a palette to use and overrides for palette entries.
     *
     *  `overrides` is a list of pairs of palette entry index and color.
     *  The overriden palette entries will use the associated color.
     *  Override pairs with palette entry indices out of range will not be applied.
     *  Later override entries override earlier ones.
     */
    struct Palette {
        struct Override {
            int index;
            uint32_t color;
        };
        int index;
        const Override* overrides;
        int overrideCount;
    };

    FontArguments()
            : fCollectionIndex(0)
            , fVariationDesignPosition{nullptr, 0}
            , fPalette{0, nullptr, 0} {}

    /** Specify the index of the desired font.
     *
     *  Font formats like ttc, dfont, cff, cid, pfr, t42, t1, and fon may actually be indexed
     *  collections of fonts.
     */
    FontArguments& SetCollectionIndex(int collectionIndex) {
        fCollectionIndex = collectionIndex;
        return *this;
    }

    /** Specify a position in the variation design space.
     *
     *  Any axis not specified will use the default value.
     *  Any specified axis not actually present in the font will be ignored.
     *
     *  @param position not copied. The value must remain valid for life of SkFontArguments.
     */
    FontArguments& SetVariationDesignPosition(VariationPosition position) {
        fVariationDesignPosition.coordinates = position.coordinates;
        fVariationDesignPosition.coordinateCount = position.coordinateCount;
        return *this;
    }

    int GetCollectionIndex() const {
        return fCollectionIndex;
    }

    VariationPosition GetVariationDesignPosition() const {
        return fVariationDesignPosition;
    }

    FontArguments& SetPalette(Palette palette) {
        fPalette.index = palette.index;
        fPalette.overrides = palette.overrides;
        fPalette.overrideCount = palette.overrideCount;
        return *this;
    }

    Palette GetPalette() const { return fPalette; }

private:
    int fCollectionIndex;
    VariationPosition fVariationDesignPosition;
    Palette fPalette;
};
}
}
}

#endif
