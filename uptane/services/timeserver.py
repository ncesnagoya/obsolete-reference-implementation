"""
<Program Name>
  timeserver.py

<Purpose>
  Provides core functionality to be used by an Uptane-compliant Timeserver.
  Initialized with a key, the Timeserver will, when given a list of nonces,
  return a signed time attestation that includes those nonces.

"""
from __future__ import unicode_literals

import uptane # Import before TUF modules; may change tuf.conf values.
import uptane.formats
import uptane.common
import uptane.encoding.asn1_codec as asn1_codec

from uptane.encoding.asn1_codec import DATATYPE_TIME_ATTESTATION

import tuf
PYASN1_EXISTS = False
try:
 import pyasn1.type
except ImportError:
 uptane.logger.error('pyasn1 library not found. Proceeding using JSON only.')
else:
 PYASN1_EXISTS = True

import time
#log = uptane.logging.getLogger('timeserver')

# 2025.05.15 nosho ntpサーバーライブラリ追加
import ntplib
from datetime import datetime, timedelta, timezone


timeserver_key = None





def set_timeserver_key(private_key):

  global timeserver_key

  tuf.formats.ANYKEY_SCHEMA.check_match(private_key)

  # TODO: Add check to make sure it's a private key, not a public key.

  timeserver_key = private_key


# 2025.05.15 nosho 追記　ntpサーバーから時刻取得し、JST(日本標準時)に変換して返す
# tests/test_get_time.pyに単体テストコード
def get_time_ntp(nonces, use_ntp=True): # 関数名注意
  """
  時刻を取得する関数。
  use_ntp=True の場合は NTPサーバーから取得し、失敗時にはローカル時刻へフォールバック。
  use_ntp=False の場合は最初からローカル時刻を使用。

  :param nonces: リスト形式のnonce
  :param use_ntp: TrueでNTP時刻を使用。Falseでローカル時刻。
  :return: time_attestation dict
  """
  uptane.formats.NONCE_LIST_SCHEMA.check_match(nonces)

  clock = None

  # 2025.05.15 nosho ntpサーバーライブラリ追加
  try:
    if use_ntp:
      # ntpクライアント作成
      ntp_client = ntplib.NTPClient()
      # ntpサーバーから時刻を取得 (タイムアウトで内部から取得へ切替可能か確認する)
      response = ntp_client.request('ntp.nict.jp', version=3)
      clock = datetime.utcfromtimestamp(response.tx_time)
      print("外部サーバーから時刻取得", clock)
    else:
      clock = tuf.formats.unix_timestamp_to_datetime(int(time.time()))
      print("ローカル時刻を使用", e)
  except Exception as e:
    clock = tuf.formats.unix_timestamp_to_datetime(int(time.time()))
    print("外部サーバーから時刻取得失敗、ローカル時刻を使用", e)

  # Get the time, format it appropriately, and check the resulting format.
  # e.g. '2016-10-10T11:37:30Z'
  clock = clock.strftime('%Y-%m-%dT%H:%M:%SZ')
  tuf.formats.ISO8601_DATETIME_SCHEMA.check_match(clock)
  print(clock)
  time_attestation = {
    'time': clock,
    'nonces': nonces
  }

  return time_attestation


def get_time(nonces):
  uptane.formats.NONCE_LIST_SCHEMA.check_match(nonces)

  # Get the time, format it appropriately, and check the resulting format.
  # e.g. '2016-10-10T11:37:30Z'
  clock = tuf.formats.unix_timestamp_to_datetime(int(time.time()))
  clock = clock.isoformat() + 'Z'
  tuf.formats.ISO8601_DATETIME_SCHEMA.check_match(clock)

  time_attestation = {
    'time': clock,
    'nonces': nonces
  }

  return time_attestation


def get_signed_time(nonces):
  time_attestation = get_time_ntp(nonces)

  signable_time_attestation = tuf.formats.make_signable(time_attestation)
  uptane.formats.SIGNABLE_TIMESERVER_ATTESTATION_SCHEMA.check_match(
      signable_time_attestation)

  uptane.common.sign_signable(
      signable_time_attestation,
      [timeserver_key],
      DATATYPE_TIME_ATTESTATION,
      metadata_format='json')

  return signable_time_attestation





def get_signed_time_der(nonces):
  """
  Same as get_signed_time, but converts the resulting Python dictionary into
  an ASN.1 representation, encodes it as DER (Distinguished Encoding Rules),
  replaces the signature with a signature over the hash of the DER encoding of
  the 'signed' portion of the data (the time and nonces).
  """
  if not PYASN1_EXISTS:
    raise uptane.Error('This Timeserver does not support DER: pyasn1 is not '
        'installed.')
  time_attestation = get_time(nonces)

  signable_time_attestation = tuf.formats.make_signable(time_attestation)
  uptane.formats.SIGNABLE_TIMESERVER_ATTESTATION_SCHEMA.check_match(
      signable_time_attestation)

  # Convert it, re-signing over the hash of the DER encoding of the attestation.
  der_attestation = asn1_codec.convert_signed_metadata_to_der(
      signable_time_attestation, DATATYPE_TIME_ATTESTATION,
      private_key=timeserver_key, resign=True)


  return der_attestation
