"""clickboard_core: the engine behind Clickboard.

One user's machines find each other (Tiny-Web account or shared passphrase),
connect over mutual TLS and exchange framed messages. ClipboardSync adds
clipboard, image and file sync on top.

Part of clickboard_core. PolyForm Small Business License 1.0.0, see LICENSE.
"""
from . import common
from .clipboard import Clip, ClipboardSync, human_size
from .common import CORE_VERSION, MIN_PASSPHRASE, log, set_app
from .config import Config
from .mesh import Mesh
from .protocol import Link
from .tinyweb import SIGNUP_EMAIL, SIGNUP_SMS_FALLBACK, api_post, signup_info

__all__ = ["Clip", "ClipboardSync", "Config", "CORE_VERSION", "Link", "Mesh", "MIN_PASSPHRASE",
           "SIGNUP_EMAIL", "SIGNUP_SMS_FALLBACK", "api_post", "common", "human_size", "log",
           "set_app", "signup_info"]
