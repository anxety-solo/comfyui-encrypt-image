"""
ComfyUI Image Encryption by ANXETY
==================================

Disk format
-----------
  * Pixels   — deterministic pixel-shuffle keyed on SHA-256(password)
  * Metadata — XOR-cipher + base64, prefixed with `ENC:`
  * Markers  — PNG text chunks: Encrypt=pixel_shuffle_3  and  EncryptPwdSha=…

Decryption points
-----------------
  1. PILImage.open      — covers the internal pipeline
                          (load-image nodes, previews, etc.)
  2. aiohttp middleware — wraps the whole app → covers /view, media assets,
                          thumbnails, and every other route that returns a PNG.
"""

from __future__ import annotations

import traceback
import hashlib
import base64
import sys
import io
from pathlib import Path

import numpy as np
from PIL import Image as PILImage, PngImagePlugin, _util, ImagePalette
from PIL.PngImagePlugin import PngInfo

import folder_paths


# Logging
class Logger:
    _COLORS = {
        'info': '\033[36m',
        'success': '\033[32m',
        'warning': '\033[33m',
        'error': '\033[31m',
    }
    _RESET = '\033[0m'

    def _log(self, level: str, msg: str) -> None:
        color = self._COLORS[level]
        tag = f" [{level.upper()}]:" if level in ('warning', 'error') else ''
        print(f"{color}[EncryptImage]:{self._RESET}{tag} {msg}")

    def info(self, msg: str) -> None: self._log('info', msg)
    def success(self, msg: str) -> None: self._log('success', msg)
    def warning(self, msg: str) -> None: self._log('warning', msg)
    def error(self, msg: str) -> None: self._log('error', msg)

log = Logger()


# Constants
ENCRYPT_PREFIX = 'ENC:'
ENCRYPT_MARKER = 'pixel_shuffle_3'
TAG_LIST       = ['parameters', 'UserComment', 'prompt', 'workflow']
MARKER_KEYS    = {'Encrypt', 'EncryptPwdSha'}
MISMATCH_ERR   = "axes don't match array"

_password: str = '123qwe'


# Helper Functions
def get_sha256(text: str) -> str:
    return hashlib.sha256(text.encode('utf-8')).hexdigest()

def _get_range(s: str, offset: int, length: int = 4) -> str:
    """Circular substring of *s* starting at *offset*"""
    s *= 2
    offset %= len(s) // 2
    return s[offset:offset + length]

def _shuffle(arr: np.ndarray, key: str) -> np.ndarray:
    """Deterministic Fisher-Yates shuffle driven by SHA-256(key)"""
    sha = get_sha256(key)
    n = len(arr)

    for i in range(n):
        j = int(_get_range(sha, i, 8), 16) % (n - i)
        k = n - i - 1
        arr[k], arr[j] = arr[j], arr[k]

    return arr


# Metadata encryption/decryption
def encrypt_tags(metadata: dict, password: str) -> dict:
    """XOR-encrypt TAG_LIST values, base64-encode, and prepend prefix."""
    out = metadata.copy()
    for key in TAG_LIST:
        val = out.get(key)
        if not val:
            continue
        xored = ''.join(
            chr(ord(c) ^ ord(password[i % len(password)]))
            for i, c in enumerate(str(val))
        )
        out[key] = ENCRYPT_PREFIX + base64.b64encode(xored.encode('utf-8')).decode('utf-8')

    return out

def decrypt_tags(metadata: dict, password: str) -> dict:
    """Reverse of encrypt_tags. Non-encrypted values pass through unchanged."""
    out = metadata.copy()
    for key in TAG_LIST:
        val = str(out.get(key, ''))
        if not val.startswith(ENCRYPT_PREFIX):
            continue
        try:
            raw = base64.b64decode(val[len(ENCRYPT_PREFIX):]).decode('utf-8')
            out[key] = ''.join(
                chr(ord(c) ^ ord(password[i % len(password)]))
                for i, c in enumerate(raw)
            )
        except Exception:
            pass

    return out


# Pixel-shuffle image encryption/decryption
def encrypt_image(image: PILImage.Image, password: str) -> np.ndarray:
    """Pixel-shuffle encrypt (rows → columns)"""
    try:
        if image.mode != 'RGBA':
            image = image.convert('RGBA')

        w, h = image.size
        px = np.array(image, dtype=np.uint8)

        y = _shuffle(np.arange(h), get_sha256(password))
        x = _shuffle(np.arange(w), password)

        px = px[y]    # permute rows
        px = px.transpose(1, 0, 2)
        px = px[x]    # permute columns
        px = px.transpose(1, 0, 2)

        return px

    except Exception as e:
        if MISMATCH_ERR not in str(e):
            log.error(f'encrypt_image: {e}')
        return np.array(image.convert('RGBA'), dtype=np.uint8)

def decrypt_image(image: PILImage.Image, password: str) -> np.ndarray:
    """Exact inverse of encrypt_image"""
    try:
        if image.mode != 'RGBA':
            image = image.convert('RGBA')

        w, h = image.size
        px = np.array(image, dtype=np.uint8)

        y = _shuffle(np.arange(h), get_sha256(password))
        x = _shuffle(np.arange(w), password)

        inv_y = np.argsort(y)
        inv_x = np.argsort(x)

        px = px[inv_y]    # restore rows
        px = px.transpose(1, 0, 2)
        px = px[inv_x]    # restore columns
        px = px.transpose(1, 0, 2)

        return px

    except Exception as e:
        if MISMATCH_ERR not in str(e):
            log.error(f'decrypt_image: {e}')
        return np.array(image.convert('RGBA'), dtype=np.uint8)


# Core helper — decrypt a file path → PNG bytes
def decrypt_file_to_png_bytes(file_path: Path) -> bytes | None:
    """
    Open file via original PIL, decrypt pixels + tags,
    and return PNG bytes. Returns None if not encrypted.
    """
    try:
        img = _pil_open_original(str(file_path))

        if img.info.get('Encrypt') != ENCRYPT_MARKER:
            img.close()
            return None

        meta = decrypt_tags(img.info, _password)
        arr = decrypt_image(img, get_sha256(_password))
        img.close()

        dec_img = PILImage.fromarray(arr, mode='RGBA')

        pnginfo = PngInfo()
        for k, v in meta.items():
            if v is not None and k not in MARKER_KEYS:
                try:
                    pnginfo.add_text(k, str(v))
                except Exception:
                    pass

        buf = io.BytesIO()
        dec_img.save(buf, format='PNG', pnginfo=pnginfo)
        dec_img.close()

        return buf.getvalue()

    except Exception as e:
        log.error(f'decrypt_file_to_png_bytes({file_path.name}): {e}')
        return None


# PIL monkey-patch (internal pipeline: load-image nodes, previews, …)
# Guard: run only once even if the module is re-imported
if PILImage.Image.__name__ != 'EncryptedImage':

    _pil_open_original = PILImage.open

    class EncryptedImage(PILImage.Image):
        """PIL Image subclass that transparently encrypts on save()"""
        __name__ = 'EncryptedImage'

        @staticmethod
        def from_image(src: PILImage.Image) -> 'EncryptedImage':
            src = src.copy()
            img = EncryptedImage()

            img.im = src.im
            img._mode = src.mode
            try:
                if src.im.mode:
                    img.mode = src.im.mode
            except Exception:
                pass

            img._size = src.size
            img.format = src.format

            if src.mode in ('P', 'PA'):
                img.palette = src.palette.copy() if src.palette else ImagePalette.ImagePalette()

            img.info = src.info.copy()
            return img

        def save(self, fp, format=None, **params):
            filename = ''

            if isinstance(fp, Path):
                filename = str(fp)
            elif _util.is_path(fp):
                filename = fp
            elif fp == sys.stdout:
                fp = getattr(sys.stdout, 'buffer', fp)

            if not filename and hasattr(fp, 'name') and _util.is_path(fp.name):
                filename = fp.name

            if not filename or not _password or self.info.get('Encrypt') == ENCRYPT_MARKER:
                super().save(fp, format=format, **params)
                return

            backup = PILImage.new('RGBA', self.size)
            backup.paste(self)

            try:
                enc_arr = encrypt_image(self, get_sha256(_password))
                self.paste(PILImage.fromarray(enc_arr, mode='RGBA'))

                enc_meta = encrypt_tags(self.info, _password)
                pnginfo = params.get('pnginfo') or PngInfo()

                for k, v in enc_meta.items():
                    if v:
                        pnginfo.add_text(k, str(v))

                pnginfo.add_text('Encrypt', ENCRYPT_MARKER)
                pnginfo.add_text(
                    'EncryptPwdSha',
                    get_sha256(f"{get_sha256(_password)}Encrypt")
                )

                params['pnginfo'] = pnginfo
                self.format = PngImagePlugin.PngImageFile.format
                super().save(fp, format=self.format, **params)
            except Exception as e:
                if MISMATCH_ERR in str(e) and filename:
                    try:
                        Path(filename).unlink(missing_ok=True)
                    except Exception:
                        pass
                raise
            finally:
                self.paste(backup)
                backup.close()

    def _patched_open(fp, *args, **kwargs):
        """Patched PILImage.open with transparent PNG decryption"""
        try:
            if not _util.is_path(fp) or not Path(fp).suffix:
                return _pil_open_original(fp, *args, **kwargs)

            img = _pil_open_original(fp, *args, **kwargs)

            if _password and img.format and img.format.lower() == 'png':
                meta = decrypt_tags(img.info or {}, _password)

                if meta.get('Encrypt') == ENCRYPT_MARKER:
                    arr = decrypt_image(img, get_sha256(_password))
                    img.paste(PILImage.fromarray(arr, mode='RGBA'))
                    meta['Encrypt'] = None

                img.info = meta

            return EncryptedImage.from_image(img)
        except Exception:
            return _pil_open_original(fp, *args, **kwargs)

    PILImage.Image = EncryptedImage
    PILImage.open = _patched_open

else:
    _pil_open_original = PILImage.open


# aiohttp middleware (/view, media assets, thumbnails — everything in one hook)
def _register_middleware() -> None:
    """
    Prepend a decryption middleware to ComfyUI's aiohttp app.

    Intercepts every web.FileResponse ending with .png. Encrypted files
    are decrypted in-memory; all others pass through unchanged.
    """
    try:
        from aiohttp import web
        from server import PromptServer

        @web.middleware
        async def _decrypt_middleware(request: web.Request, handler) -> web.Response:
            response = await handler(request)

            if not isinstance(response, web.FileResponse):
                return response

            file_path = getattr(response, "_path", None)
            if not file_path or Path(file_path).suffix.lower() != ".png":
                return response

            if not _password:
                return response

            png_bytes = decrypt_file_to_png_bytes(Path(file_path))
            if png_bytes is None:
                return response

            return web.Response(
                body=png_bytes,
                content_type="image/png",
                headers={"Cache-Control": "no-cache, no-store, must-revalidate"},
            )

        # Prepend middleware to ensure it runs first
        app = PromptServer.instance.app
        app._middlewares.insert(0, _decrypt_middleware)

        log.success("Middleware registered — all PNG responses will be decrypted for the browser")

    except Exception as e:
        log.error(f"Failed to register middleware: {e}")
        traceback.print_exc()

_register_middleware()


# ComfyUI node — change password at runtime
class EncryptImagePasswordNode:
    """
    Change the encryption password without restarting ComfyUI.

    Connect a Primitive (STRING) node to new_password and run the workflow once.
    Change takes effect immediately for the current session.
    """

    @classmethod
    def INPUT_TYPES(cls):
        return {
            'required': {
                'new_password': ('STRING', {'default': '', 'multiline': False}),
            },
            'optional': {
                'passthrough': ('*', {}),
            },
        }

    RETURN_TYPES = ()
    FUNCTION     = 'hange_password'
    CATEGORY     = 'utils/encryption'
    OUTPUT_NODE  = True

    def change_password(self, new_password: str, passthrough=None):
        global _password
        new_password = new_password.strip()
        if new_password:
            _password = new_password
            log.success(f"Password updated → {_password!r}")
        else:
            log.warning('Empty password provided — ignoring')
        return ()


# Node registry
NODE_CLASS_MAPPINGS = {
    'EncryptImagePassword': EncryptImagePasswordNode,
}
NODE_DISPLAY_NAME_MAPPINGS = {
    'EncryptImagePassword': '🔒 Encryption Password',
}