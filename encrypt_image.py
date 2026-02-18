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
TAG_LIST = ['parameters', 'UserComment', 'prompt', 'workflow']
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


# ~~ Metadata encryption / decryption ~~

def encrypt_tags(metadata: dict, password: str) -> dict:
    """XOR-encrypt all TAG_LIST values, base64-encode, prepend SOBA: prefix"""
    out = metadata.copy()
    for key in TAG_LIST:
        val = out.get(key)
        if not val:
            continue
        if str(val).startswith(ENCRYPT_PREFIX):
            continue  # already encrypted
        xored = ''.join(
            chr(ord(c) ^ ord(password[i % len(password)]))
            for i, c in enumerate(str(val))
        )
        out[key] = ENCRYPT_PREFIX + base64.b64encode(xored.encode('utf-8')).decode('utf-8')
    return out

def decrypt_tags(metadata: dict, password: str) -> dict:
    """Reverse of encrypt_tags; values without the prefix pass through"""
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


# ~~ Pixel-shuffle image encryption / decryption ~~

def encrypt_image(image: PILImage.Image, password: str) -> np.ndarray:
    """Pixel-shuffle encrypt an image (rows then columns)"""
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
        if MISMATCH_ERROR not in str(e):
            log.error(f"encrypt_image: {e}")
        return np.array(image.convert('RGBA'), dtype=np.uint8)

def decrypt_image(image: PILImage.Image, password: str) -> np.ndarray:
    """Exact inverse of encrypt_image"""
    try:
        if image.mode != 'RGBA':
            image = image.convert('RGBA')

        w, h = image.size
        px = np.array(image, dtype=np.uint8)

        inv_y = np.argsort(_shuffle(np.arange(h), get_sha256(password)))
        inv_x = np.argsort(_shuffle(np.arange(w), password))

        px = px[inv_y]    # restore rows
        px = px.transpose(1, 0, 2)
        px = px[inv_x]    # restore columns
        px = px.transpose(1, 0, 2)

        return px
    except Exception as e:
        if MISMATCH_ERROR not in str(e):
            log.error(f"decrypt_image: {e}")
        return np.array(image.convert('RGBA'), dtype=np.uint8)


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
        pnginfo = PngInfo()
        for k, v in meta.items():
            if v is not None and k not in IMAGE_KEYS:
                try:
                    pnginfo.add_text(k, str(v))
                except Exception:
                    pass

        buf = io.BytesIO()
        dec_img.save(buf, format='PNG', pnginfo=pnginfo)
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
            return False  # already encrypted

        existing_meta = dict(img.info)
        enc_meta = encrypt_tags(existing_meta, _password)

        enc_arr = encrypt_image(img, get_sha256(_password))
        img.close()

        enc_img = PILImage.fromarray(enc_arr, mode='RGBA')

        pnginfo = PngInfo()
        for k, v in enc_meta.items():
            if v is not None and k not in IMAGE_KEYS:
                try:
                    pnginfo.add_text(k, str(v))
                except Exception:
                    pass
        pnginfo.add_text('Encrypt', ENCRYPT_MARKER)
        pnginfo.add_text('EncryptPwdSha', get_sha256(f"{get_sha256(_password)}Encrypt"))

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

                pnginfo = params.get('pnginfo') or PngInfo()
                if self.info.get('Encrypt') != ENCRYPT_MARKER:
                    enc_meta = encrypt_tags(self.info, _password)
                    for k, v in enc_meta.items():
                        if v and k not in IMAGE_KEYS:
                            pnginfo.add_text(k, str(v))

                pnginfo.add_text('Encrypt', ENCRYPT_MARKER)
                pnginfo.add_text('EncryptPwdSha', get_sha256(f"{get_sha256(_password)}Encrypt"))

                params['pnginfo'] = pnginfo
                self.format = PngImagePlugin.PngImageFile.format
                super().save(fp, format=self.format, **params)
            except Exception as e:
                if MISMATCH_ERROR in str(e) and filename:
                    try:
                        Path(filename).unlink(missing_ok=True)
                    except Exception:
                        pass
                raise
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
            response = await handler(request)

            if not isinstance(response, web.FileResponse):
                return response
            file_path = getattr(response, '_path', None)
            if not file_path or Path(file_path).suffix.lower() != '.png':
                return response
            if not _password:
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
            response = await handler(request)

            if request.method != 'POST':
                return response
            if not request.path.rstrip('/').endswith('/upload/image'):
                return response
            if response.status not in (200, 201):
                return response

            try:
                body_bytes = b''
                if hasattr(response, 'body') and response.body:
                    body_bytes = response.body
                elif hasattr(response, 'text') and response.text:
                    body_bytes = response.text.encode()

                data      = json.loads(body_bytes)
                filename  = data.get('name', '')
                subfolder = data.get('subfolder', '')
                file_type = data.get('type', 'input')

                if not filename or file_type != 'input':
                    return response

                file_path = (input_dir / subfolder / filename
                             if subfolder else input_dir / filename)

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

                if already_encrypted:
                    return response  # PNG already encrypted, nothing to do

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