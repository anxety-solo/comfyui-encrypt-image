from PIL.PngImagePlugin import PngInfo
from pathlib import Path
import folder_paths
from PIL import Image as PILImage, PngImagePlugin, _util, ImagePalette
import numpy as np
import hashlib
import base64
import json
import sys
from typing import Optional
from comfy.cli_args import args

# Constants
ENCRYPT_PREFIX = "ENC:"
TAG_LIST = ['parameters', 'UserComment', 'prompt', 'workflow']
IMAGE_EXTENSIONS = ['.png', '.jpg', '.jpeg', '.webp', '.avif']
IMAGE_KEYS = ['Encrypt', 'EncryptPwdSha']

# Password setup (can be changed via node)
_password = "123qwe"

# Helper functions
def get_range(input_str: str, offset: int, range_len=4) -> str:
    offset = offset % len(input_str)
    return (input_str * 2)[offset:offset + range_len]

def get_sha256(input_str: str) -> str:
    return hashlib.sha256(input_str.encode('utf-8')).hexdigest()

def shuffle_array(arr, key):
    sha_key = get_sha256(key)
    arr_len = len(arr)
    for i in range(arr_len):
        s_idx = arr_len - i - 1
        to_index = int(get_range(sha_key, i, range_len=8), 16) % (arr_len - i)
        arr[s_idx], arr[to_index] = arr[to_index], arr[s_idx]
    return arr

def encrypt_tags(metadata, password):
    if not password:
        return metadata
    encrypted_metadata = metadata.copy()
    for key in TAG_LIST:
        if key in metadata:
            value = str(metadata[key])
            encrypted_value = ''.join(
                chr(ord(c) ^ ord(password[i % len(password)]))
                for i, c in enumerate(value)
            )
            encrypted_value = base64.b64encode(encrypted_value.encode('utf-8')).decode('utf-8')
            encrypted_metadata[key] = f"{ENCRYPT_PREFIX}{encrypted_value}"
    return encrypted_metadata

def decrypt_tags(metadata, password):
    if not password:
        return metadata
    decrypted_metadata = metadata.copy()
    for key in TAG_LIST:
        if key in metadata and str(metadata[key]).startswith(ENCRYPT_PREFIX):
            encrypted_value = metadata[key][len(ENCRYPT_PREFIX):]
            try:
                decoded = base64.b64decode(encrypted_value).decode('utf-8')
                decrypted_value = ''.join(
                    chr(ord(c) ^ ord(password[i % len(password)]))
                    for i, c in enumerate(decoded)
                )
                decrypted_metadata[key] = decrypted_value
            except Exception:
                decrypted_metadata[key] = metadata[key]
    return decrypted_metadata

def encrypt_image(image: PILImage.Image, password):
    try:
        width, height = image.size
        x_arr = np.arange(width)
        shuffle_array(x_arr, password)
        y_arr = np.arange(height)
        shuffle_array(y_arr, get_sha256(password))
        pixel_array = np.array(image)

        _pixel_array = pixel_array.copy()
        for x in range(height):
            pixel_array[x] = _pixel_array[y_arr[x]]
        pixel_array = np.transpose(pixel_array, axes=(1, 0, 2))

        _pixel_array = pixel_array.copy()
        for x in range(width):
            pixel_array[x] = _pixel_array[x_arr[x]]
        pixel_array = np.transpose(pixel_array, axes=(1, 0, 2))

        return pixel_array
    except Exception:
        return np.array(image)

def decrypt_image(image: PILImage.Image, password):
    try:
        width, height = image.size
        x_arr = np.arange(width)
        shuffle_array(x_arr, password)
        y_arr = np.arange(height)
        shuffle_array(y_arr, get_sha256(password))
        pixel_array = np.array(image)

        _pixel_array = pixel_array.copy()
        for x in range(height):
            pixel_array[y_arr[x]] = _pixel_array[x]
        pixel_array = np.transpose(pixel_array, axes=(1, 0, 2))

        _pixel_array = pixel_array.copy()
        for x in range(width):
            pixel_array[x_arr[x]] = _pixel_array[x]
        pixel_array = np.transpose(pixel_array, axes=(1, 0, 2))

        return pixel_array
    except Exception:
        return np.array(image)

# Encrypted Image class
if PILImage.Image.__name__ != 'EncryptedImage':
    super_open = PILImage.open
    
    class EncryptedImage(PILImage.Image):
        __name__ = "EncryptedImage"
        
        @staticmethod
        def from_image(image: PILImage.Image):
            image = image.copy()
            img = EncryptedImage()
            img.im = image.im
            img._mode = image.mode
            if image.im.mode:
                try:
                    img.mode = image.im.mode
                except Exception:
                    pass
            img._size = image.size
            img.format = image.format
            if image.mode in ("P", "PA"):
                img.palette = image.palette.copy() if image.palette else ImagePalette.ImagePalette()
            img.info = image.info.copy()
            return img
            
        def save(self, fp, format=None, **params):
            filename = ""
            if isinstance(fp, Path):
                filename = str(fp)
            elif _util.is_path(fp):
                filename = fp
            elif fp == sys.stdout:
                try:
                    fp = sys.stdout.buffer
                except AttributeError:
                    pass
            
            if not filename and hasattr(fp, "name") and _util.is_path(fp.name):
                filename = fp.name
            
            if not filename or not _password:
                super().save(fp, format=format, **params)
                return
            
            if self.info.get('Encrypt') == 'pixel_shuffle_3':
                super().save(fp, format=format, **params)
                return
            
            # Create backup of original image
            back_img = PILImage.new('RGBA', self.size)
            back_img.paste(self)
            
            try:
                # Encrypt image
                encrypted_img = PILImage.fromarray(encrypt_image(self, get_sha256(_password)))
                self.paste(encrypted_img)
                encrypted_img.close()
                
                # Prepare metadata
                encrypted_info = encrypt_tags(self.info, _password)
                pnginfo = params.get('pnginfo', PngImagePlugin.PngInfo()) or PngImagePlugin.PngInfo()
                
                for key, value in encrypted_info.items():
                    if value:
                        pnginfo.add_text(key, str(value))
                
                pnginfo.add_text('Encrypt', 'pixel_shuffle_3')
                pnginfo.add_text('EncryptPwdSha', get_sha256(f'{get_sha256(_password)}Encrypt'))
                
                params.update(pnginfo=pnginfo)
                self.format = PngImagePlugin.PngImageFile.format
                super().save(fp, format=self.format, **params)
                
            except Exception as e:
                if "axes don't match array" in str(e):
                    if filename:
                        fn = Path(filename)
                        try:
                            fn.unlink(missing_ok=True)
                        except:
                            pass
                raise
            finally:
                # Restore original image in memory
                self.paste(back_img)
                back_img.close()

    def open_image(fp, *args, **kwargs):
        try:
            if not _util.is_path(fp) or not Path(fp).suffix:
                return super_open(fp, *args, **kwargs)
                
            img = super_open(fp, *args, **kwargs)
            
            if _password and img.format.lower() == PngImagePlugin.PngImageFile.format.lower():
                pnginfo = img.info or {}
                pnginfo = decrypt_tags(pnginfo, _password)
                
                if pnginfo.get("Encrypt") == 'pixel_shuffle_3':
                    decrypted_img = PILImage.fromarray(decrypt_image(img, get_sha256(_password)))
                    img.paste(decrypted_img)
                    decrypted_img.close()
                    pnginfo["Encrypt"] = None
                    
            return EncryptedImage.from_image(img)
            
        except Exception:
            return super_open(fp, *args, **kwargs)
    
    # Override PIL functions
    PILImage.Image = EncryptedImage
    PILImage.open = open_image

# ComfyUI Node - Password Change Node
class EncryptImagePasswordNode:
    """
    Node for changing the encryption password.
    Connect to this node and provide a new password to change it.
    """
    
    def __init__(self):
        pass
        
    @classmethod
    def INPUT_TYPES(cls):
        return {
            "required": {
                "new_password": ("STRING", {"default": "", "multiline": False}),
            },
            "optional": {
                "dummy_input": ("*", {}),
            }
        }
        
    RETURN_TYPES = ()
    FUNCTION = "change_password"
    CATEGORY = "utils/encryption"
    OUTPUT_NODE = True
    
    def change_password(self, new_password, dummy_input=None):
        global _password
        if new_password and new_password.strip():
            _password = new_password.strip()
            print(f"Encryption password changed to: {_password}")
        return ()

# Node mappings
NODE_CLASS_MAPPINGS = {
    "EncryptImagePassword": EncryptImagePasswordNode
}

NODE_DISPLAY_NAME_MAPPINGS = {
    "EncryptImagePassword": "🔒 Change Encryption Password"
}