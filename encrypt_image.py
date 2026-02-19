import traceback
import hashlib
import base64
import json
import sys
import io
from pathlib import Path

import numpy as np
from PIL import Image as PILImage, PngImagePlugin, _util, ImagePalette
from PIL.PngImagePlugin import PngInfo


# ~~ Constants ~~

ENCRYPT_PREFIX = 'SOBA:'
ENCRYPT_MARKER = 'pixel_shuffle_3'
TAG_LIST = ['prompt', 'workflow']
IMAGE_KEYS = ['Encrypt', 'EncryptPwdSha']
MISMATCH_ERROR = "axes don't match array"

_password: str = '123qwe'


# ~~ Logger ~~

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
        print(f"{color}[ImageEncryption]:{self._RESET}{tag} {msg}")

    def info(self, msg: str) -> None:    self._log('info', msg)
    def success(self, msg: str) -> None: self._log('success', msg)
    def warning(self, msg: str) -> None: self._log('warning', msg)
    def error(self, msg: str) -> None:   self._log('error', msg)

log = Logger()


# ~~ Helpers ~~

def get_sha256(text: str) -> str:
    """Return SHA-256 hex digest of a string"""
    return hashlib.sha256(text.encode('utf-8')).hexdigest()

def _get_range(s: str, offset: int, length: int = 4) -> str:
    """Return a circular substring of *s* starting at *offset*"""
    offset %= len(s)
    return (s * 2)[offset:offset + length]

def _shuffle(arr: np.ndarray, key: str) -> np.ndarray:
    """Deterministic Fisher-Yates shuffle driven by SHA-256(key)"""
    sha = get_sha256(key)
    n = len(arr)
    for i in range(n):
        j = int(_get_range(sha, i, 8), 16) % (n - i)
        k = n - i - 1
        arr[k], arr[j] = arr[j], arr[k]
    return arr

def _xor_str(text: str, password: str) -> str:
    """XOR each character of text against the repeating password"""
    return ''.join(
        chr(ord(c) ^ ord(password[i % len(password)]))
        for i, c in enumerate(text)
    )

def _build_pnginfo(meta: dict, extra: dict | None = None) -> PngInfo:
    """Build PngInfo from a metadata dict, skipping IMAGE_KEYS; extra keys are appended last"""
    pnginfo = PngInfo()
    for k, v in meta.items():
        if v is not None and k not in IMAGE_KEYS:
            try:
                pnginfo.add_text(k, str(v))
            except Exception:
                pass
    for k, v in (extra or {}).items():
        pnginfo.add_text(k, v)
    return pnginfo

def _meta_from_pnginfo(pnginfo) -> dict:
    """Extract tEXt/iTXt key-value pairs from a PngInfo object"""
    meta = {}
    if pnginfo and hasattr(pnginfo, 'chunks'):
        for chunk in pnginfo.chunks:
            try:
                t, d = chunk[0], chunk[1]
                if t in (b'tEXt', b'iTXt'):
                    k, v = d.split(b'\x00', 1)
                    meta[k.decode()] = v.decode(errors='ignore')
            except Exception:
                pass
    return meta


# ~~ Metadata encryption / decryption ~~

def encrypt_tags(metadata: dict, password: str) -> dict:
    """XOR-encrypt all TAG_LIST values, base64-encode, prepend prefix"""
    out = metadata.copy()
    for key in TAG_LIST:
        val = str(out.get(key) or '')
        if val and not val.startswith(ENCRYPT_PREFIX):
            out[key] = ENCRYPT_PREFIX + base64.b64encode(_xor_str(val, password).encode()).decode()
    return out

def decrypt_tags(metadata: dict, password: str) -> dict:
    """Reverse of encrypt_tags; values without the prefix pass through"""
    out = metadata.copy()
    for key in TAG_LIST:
        val = str(out.get(key, ''))
        if val.startswith(ENCRYPT_PREFIX):
            try:
                raw = base64.b64decode(val[len(ENCRYPT_PREFIX):]).decode()
                out[key] = _xor_str(raw, password)
            except Exception:
                pass
    return out


# ~~ Pixel-shuffle image encryption / decryption ~~

def _permute_image(image: PILImage.Image, password: str, inverse: bool = False) -> np.ndarray:
    """Permute rows then columns of image pixels; set inverse=True to reverse"""
    try:
        if image.mode != 'RGBA':
            image = image.convert('RGBA')

        w, h = image.size
        px = np.array(image, dtype=np.uint8)

        y_perm = _shuffle(np.arange(h), get_sha256(password))
        x_perm = _shuffle(np.arange(w), password)
        if inverse:
            y_perm, x_perm = np.argsort(y_perm), np.argsort(x_perm)

        return px[y_perm].transpose(1, 0, 2)[x_perm].transpose(1, 0, 2)
    except Exception as e:
        if MISMATCH_ERROR not in str(e):
            log.error(f"_permute_image: {e}")
        return np.array(image.convert('RGBA'), dtype=np.uint8)

def encrypt_image(image: PILImage.Image, password: str) -> np.ndarray:
    """Pixel-shuffle encrypt an image (rows then columns)"""
    return _permute_image(image, password)

def decrypt_image(image: PILImage.Image, password: str) -> np.ndarray:
    """Exact inverse of encrypt_image"""
    return _permute_image(image, password, inverse=True)


# ~~ Core helper ~~

def decrypt_file_to_png_bytes(file_path: Path) -> bytes | None:
    """Decrypt an encrypted PNG on disk → raw PNG bytes, or None if not encrypted"""
    try:
        img = _pil_open_original(str(file_path))
        if img.info.get('Encrypt') != ENCRYPT_MARKER:
            img.close()
            return None

        meta = decrypt_tags(img.info, _password)
        arr = decrypt_image(img, get_sha256(_password))
        img.close()

        dec_img = PILImage.fromarray(arr, mode='RGBA')
        buf = io.BytesIO()
        dec_img.save(buf, format='PNG', pnginfo=_build_pnginfo(meta))
        dec_img.close()
        return buf.getvalue()
    except Exception as e:
        log.error(f"decrypt_file_to_png_bytes({file_path.name}): {e}")
        return None

def encrypt_file_inplace(file_path: Path) -> bool:
    """Encrypt a PNG file in-place (used for /input uploads)"""
    try:
        img = _pil_open_original(str(file_path))
        if img.info.get('Encrypt') == ENCRYPT_MARKER:
            img.close()
            return False

        enc_meta = encrypt_tags(dict(img.info), _password)
        enc_arr = encrypt_image(img, get_sha256(_password))
        img.close()

        enc_img = PILImage.fromarray(enc_arr, mode='RGBA')
        pnginfo = _build_pnginfo(enc_meta, {
            'Encrypt': ENCRYPT_MARKER,
            'EncryptPwdSha': get_sha256(f"{get_sha256(_password)}Encrypt"),
        })
        # Call the real PIL save to avoid being caught by EncryptedImage.save()
        # which would try to double-encrypt
        PILImage.Image.__bases__[0].save(enc_img, str(file_path), format='PNG', pnginfo=pnginfo)
        enc_img.close()
        log.success(f"Encrypted input file: {file_path.name}")
        return True
    except Exception as e:
        log.error(f"encrypt_file_inplace({file_path.name}): {e}")
        return False


# ~~ PIL monkey-patch ~~

if PILImage.Image.__name__ != 'EncryptedImage':

    _pil_open_original = PILImage.open

    class EncryptedImage(PILImage.Image):
        """PIL Image subclass that transparently encrypts on save()"""
        __name__ = 'EncryptedImage'

        @staticmethod
        def from_image(src: PILImage.Image) -> 'EncryptedImage':
            """Construct an EncryptedImage by copying all attributes from an existing PIL Image"""
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
            """Save the image, encrypting pixels and metadata on the fly; on error log and abort"""
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
                self.paste(PILImage.fromarray(encrypt_image(self, get_sha256(_password)), mode='RGBA'))
                raw_meta = _meta_from_pnginfo(params.get('pnginfo'))
                meta = encrypt_tags(raw_meta or self.info, _password)
                params['pnginfo'] = _build_pnginfo(meta, {
                    'Encrypt': ENCRYPT_MARKER,
                    'EncryptPwdSha': get_sha256(f"{get_sha256(_password)}Encrypt"),
                })
                self.format = PngImagePlugin.PngImageFile.format
                super().save(fp, format=self.format, **params)
            except Exception as e:
                log.error(f"EncryptedImage.save({filename!r}): {e}")
            finally:
                self.paste(backup)
                backup.close()

    def _patched_open(fp, *args, **kwargs):
        """Patched PILImage.open that transparently decrypts encrypted PNG files"""
        try:
            if not _util.is_path(fp) or not Path(fp).suffix:
                return _pil_open_original(fp, *args, **kwargs)

            img = _pil_open_original(fp, *args, **kwargs)

            if _password and img.format and img.format.lower() == 'png':
                meta = decrypt_tags(img.info or {}, _password)
                if meta.get('Encrypt') == ENCRYPT_MARKER:
                    img.paste(PILImage.fromarray(decrypt_image(img, get_sha256(_password)), mode='RGBA'))
                    meta['Encrypt'] = None
                img.info = meta
            return EncryptedImage.from_image(img)
        except Exception:
            return _pil_open_original(fp, *args, **kwargs)

    PILImage.Image = EncryptedImage
    PILImage.open = _patched_open

else:
    _pil_open_original = PILImage.open


# ~~ aiohttp middleware ~~

def _register_middleware() -> None:
    """Register middleware: decrypt served images + encrypt uploads"""
    try:
        from aiohttp import web
        from server import PromptServer
        import folder_paths

        input_dir = Path(folder_paths.get_input_directory())

        # Middleware 1: serve decrypted images transparently
        @web.middleware
        async def _decrypt_middleware(request: web.Request, handler) -> web.Response:
            """Intercept file responses and return decrypted PNG bytes if the file is encrypted"""
            response = await handler(request)

            file_path = getattr(response, '_path', None)
            if (not isinstance(response, web.FileResponse)
                    or not file_path
                    or Path(file_path).suffix.lower() != '.png'
                    or not _password):
                return response

            png_bytes = decrypt_file_to_png_bytes(Path(file_path))
            if png_bytes is None:
                return response

            return web.Response(
                body=png_bytes,
                content_type='image/png',
                headers={'Cache-Control': 'no-cache, no-store, must-revalidate'},
            )

        # Middleware 2: encrypt images uploaded to the /input folder
        @web.middleware
        async def _upload_encrypt_middleware(request: web.Request, handler) -> web.Response:
            """Intercept image uploads to /input and encrypt the saved file in-place"""
            response = await handler(request)

            if (request.method != 'POST'
                    or not request.path.rstrip('/').endswith('/upload/image')
                    or response.status not in (200, 201)):
                return response

            try:
                body = (getattr(response, 'body', None)
                        or (getattr(response, 'text', '') or '').encode())
                data = json.loads(body)
                filename = data.get('name', '')
                subfolder = data.get('subfolder', '')

                if not filename or data.get('type', 'input') != 'input':
                    return response
                file_path = input_dir / subfolder / filename if subfolder else input_dir / filename
                if not file_path.exists():
                    return response

                # Try to open as image — if PIL can't open it
                try:
                    img = _pil_open_original(str(file_path))
                    img.verify()
                    img = _pil_open_original(str(file_path))  # reopen after verify()
                except Exception:
                    log.warning(f"Skipping non-image upload: {filename}")
                    return response

                already_encrypted = img.info.get('Encrypt') == ENCRYPT_MARKER
                img.close()
                if not already_encrypted:
                    # For all image formats: convert → encrypted PNG in-place
                    encrypt_file_inplace(file_path)
            except Exception as e:
                log.error(f"Upload encrypt middleware: {e}")

            return response

        app = PromptServer.instance.app
        app._middlewares.insert(0, _upload_encrypt_middleware)
        app._middlewares.insert(0, _decrypt_middleware)

        log.success('Middleware running (decrypt + upload-encrypt)')

    except Exception as e:
        log.error(f"Middleware not running: {e}")
        traceback.print_exc()

_register_middleware()


# ~~ Node registry ~~

NODE_CLASS_MAPPINGS = {}
NODE_DISPLAY_NAME_MAPPINGS = {}