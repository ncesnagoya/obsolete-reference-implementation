import pytest
import time
# from datetime import datetime
import uptane.services.timeserver as timeserver
import tuf
import uptane.formats
from unittest import mock


# 2025.05.19 nosho get_time()のテストコード
def test_get_time_with_valid_nonces():
    nonces = [1, 2, 3]
    result = timeserver.get_time(nonces)

    # schemaに合っているか
    uptane.formats.TIMESERVER_ATTESTATION_SCHEMA.check_match(result)
    print(result)
    # タイムスタンプの形式が正しいか
    tuf.formats.ISO8601_DATETIME_SCHEMA.check_match(result['time'])

    assert result['nonces'] == nonces


def test_get_time_returns_different_times():
    nonces = [10]
    t1 = timeserver.get_time(nonces)
    time.sleep(1)
    t2 = timeserver.get_time(nonces)
    assert t1 != t2  # 少なくともタイムスタンプが違うはず


def test_get_time_with_empty_nonce_list():
    result = timeserver.get_time([])
    uptane.formats.TIMESERVER_ATTESTATION_SCHEMA.check_match(result)


def test_get_time_with_duplicate_nonces():
    result = timeserver.get_time([1, 2, 1])
    uptane.formats.TIMESERVER_ATTESTATION_SCHEMA.check_match(result)


def test_get_time_invalid_inputs():
    with pytest.raises(tuf.FormatError):
        timeserver.get_time(None)
    with pytest.raises(tuf.FormatError):
        timeserver.get_time("not a list")
    with pytest.raises(tuf.FormatError):
        timeserver.get_time(12345)


def test_get_time_fallback_on_ntp_failure():
    nonces = [1, 2, 3]

    # ntplib.NTPClient().request をモックして例外を発生させる
    with mock.patch('ntplib.NTPClient.request', side_effect=Exception("NTP error")):
        result = timeserver.get_time(nonces)

    # 結果がスキーマに合っていることを確認
    uptane.formats.TIMESERVER_ATTESTATION_SCHEMA.check_match(result)
    tuf.formats.ISO8601_DATETIME_SCHEMA.check_match(result['time'])

    # 正しい nonces が返っているか確認
    assert result['nonces'] == nonces
