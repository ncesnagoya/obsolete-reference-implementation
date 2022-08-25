import tuf
import tuf.util
import tuf.asn1_codec as asn1_codec
import tuf.conf
import tuf.repository_tool as repo_tool # to import a key for a signing attempt
import unittest
import sys # Python version
import os # getcwd()

tuf.conf.METADATA_FORMAT = 'json'

import tuf.encoding.root_asn1_coder as root_asn1_coder
import tuf.encoding.snapshot_asn1_coder as snapshot_asn1_coder
import tuf.encoding.timestamp_asn1_coder as timestamp_asn1_coder
import tuf.encoding.targets_asn1_coder as targets_asn1_coder
import tuf.encoding.metadata_asn1_definitions as metadata_asn1_spec
from tuf.encoding import hex_from_octetstring

import tuf.keys
import hashlib

class TestASN1Conversion(unittest.TestCase):

  @classmethod
  def setUpClass(cls):

    private_key_fname = os.path.join(
        os.getcwd(), 'repository_data', 'keystore', 'targets_key')

    cls.test_signing_key = repo_tool.import_ed25519_privatekey_from_file(
        private_key_fname, 'password')


  def test_hex_from_octetstring(self):

    original_hex_str = '5f1a1354'

    octet_str = metadata_asn1_spec.OctetString(hexValue=original_hex_str)

    hex_str = hex_from_octetstring(octet_str)

    self.assertEqual(original_hex_str, hex_str)

    # TODO: Add some more tests using key data.



  # THIS NEXT TEST fails because the TUF root.json test file in question here
  # uses an RSA key, which the ASN1 conversion does not yet support.
  # TODO: FIX.
  # Our ASN1 conversion doesn't seem to support RSA keys. In particular, it is
  # being assumed that the key values are hex strings ('f9ac1325...') but an
  # RSA public key value is e.g. '-----BEGIN PUBLIC
  # KEY------\nMIIBojANBgk...\n...'
  @unittest.expectedFailure
  def test_1asn_convert_root(self):
    """
    Test ASN.1-only conversion for a Root role from the old TUF sample data.
    """
    asn1_pydict_conversion_tester(
        'repository_data/repository/metadata/root.json', self)



  # THIS NEXT TEST fails because the TUF root.json test file in question here
  # uses an RSA key, which the ASN1 conversion does not yet support.
  # TODO: FIX.
  # Our ASN1 conversion doesn't seem to support RSA keys. In particular, it is
  # being assumed that the key values are hex strings ('f9ac1325...') but an
  # RSA public key value is e.g. '-----BEGIN PUBLIC
  # KEY------\nMIIBojANBgk...\n...'
  @unittest.expectedFailure
  def test_1der_convert_root_tuf(self):
    """
    Test ASN.1 conversions with DER encoding for a Root role from the old TUF
    sample data.
    """
    der_conversion_tester(
        'repository_data/repository/metadata/root.json', self)



  def test_2asn_convert_root_uptane(self):
    """
    Test ASN.1-only conversion for Root roles from the Uptane samples.
    """
    asn1_pydict_conversion_tester(
        'repository_data/uptane_mainrepo_root.json', self)

    asn1_pydict_conversion_tester(
        'repository_data/uptane_director_root.json', self)


  def test_2der_convert_root_uptane(self):
    """
    Test ASN.1 conversions with DER encoding for Root roles from the Uptane
    samples.
    """
    der_conversion_tester(
        'repository_data/uptane_mainrepo_root.json', self)
    der_conversion_tester(
        'repository_data/uptane_director_root.json', self)



  def test_3asn_convert_timestamp_tuf(self):
    """
    Test ASN.1-only conversion for a Timestamp role from the old TUF sample
    data.
    """
    asn1_pydict_conversion_tester(
        'repository_data/repository/metadata/timestamp.json', self)



  def test_3der_convert_timestamp_tuf(self):
    """
    Test ASN.1 conversions with DER encoding for a Timestamp role from the old
    TUF sample data.
    """
    der_conversion_tester(
        'repository_data/repository/metadata/timestamp.json', self)



  def test_4asn_convert_timestamp_uptane(self):
    """
    Test ASN.1-only conversion for Timestamp roles from Uptane sample data.
    """
    asn1_pydict_conversion_tester(
        'repository_data/uptane_mainrepo_timestamp.json', self)

    asn1_pydict_conversion_tester(
        'repository_data/uptane_director_timestamp.json', self)


  def test_4der_convert_timestamp_uptane(self):
    """
    Test ASN.1 conversions with DER encoding for Timestamp roles from Uptane
    sample data.
    """
    der_conversion_tester(
        'repository_data/uptane_mainrepo_timestamp.json', self)

    der_conversion_tester(
        'repository_data/uptane_director_timestamp.json', self)



  def test_5asn_convert_snapshot_tuf(self):
    """
    Test ASN.1-only conversion for a Snapshot role from the old TUF sample
    data.
    """
    asn1_pydict_conversion_tester(
        'repository_data/repository/metadata/snapshot.json', self)



  def test_5der_convert_snapshot_tuf(self):
    """
    Test ASN.1 conversions with DER encoding for a Snapshot role from the old
    TUF sample data.
    """
    der_conversion_tester(
        'repository_data/repository/metadata/snapshot.json', self)



  def test_6asn_convert_snapshot_uptane(self):
    """
    Test ASN.1-only conversion for Snapshot roles from Uptane samples.
    """
    asn1_pydict_conversion_tester(
        'repository_data/uptane_mainrepo_snapshot.json', self)

    asn1_pydict_conversion_tester(
        'repository_data/uptane_director_snapshot.json', self)


  def test_6asn_convert_snapshot_uptane(self):
    """
    Test ASN.1 conversions with DER encoding for Snapshot roles from Uptane
    samples.
    """
    der_conversion_tester(
        'repository_data/uptane_mainrepo_snapshot.json', self)

    der_conversion_tester(
        'repository_data/uptane_director_snapshot.json', self)



  def test_7asn_convert_targets_minimal(self):
    """
    Test ASN.1-only conversion for a Targets role that contains no delegations
    and specifies no targets. This comes from Uptane sample metadata.
    """
    asn1_pydict_conversion_tester(
        'repository_data/uptane_mainrepo_targets_minimal.json', self)



  def test_7der_convert_targets_minimal(self):
    """
    Test ASN.1 conversions with DER encoding for a Targets role that contains
    no delegations and specifies no targets. This comes from Uptane sample
    metadata.
    """
    der_conversion_tester(
        'repository_data/uptane_mainrepo_targets_minimal.json', self)



  def test_8asn_convert_targets_no_delegations(self):
    """
    Test ASN.1-only conversion for Targets roles that contain no delegations but
    which specify targets. These come from Uptane sample metadata.
    """
    asn1_pydict_conversion_tester(
        'repository_data/uptane_mainrepo_targets_no_delegations.json', self)

    asn1_pydict_conversion_tester(
        'repository_data/uptane_director_targets.json', self)



  def test_8der_convert_targets_no_delegations(self):
    """
    Test ASN.1 conversion with DER encoding for Targets roles that contain no
    delegations but which specify targets. These come from Uptane sample
    metadata.
    """
    der_conversion_tester(
        'repository_data/uptane_mainrepo_targets_no_delegations.json', self)

    der_conversion_tester(
        'repository_data/uptane_director_targets.json', self)



  @unittest.expectedFailure
  # THIS NEXT TEST fails because the provided targets role includes delegations,
  # and the current ASN.1 conversion code does not support delegations (and
  # must be updated to do so).
  def test_9asn_convert_targets_no_targetinfo(self):
    """
    Test ASN.1-only conversion for a Targets role that contains delegations
    but specifies no targets.
    """
    asn1_pydict_conversion_tester(
        'repository_data/targets_simpler.json', self)



  @unittest.expectedFailure
  # THIS NEXT TEST fails because the provided targets role includes delegations,
  # and the current ASN.1 conversion code does not support delegations (and
  # must be updated to do so).
  def test_9der_convert_targets_no_targetinfo(self):
    """
    Test ASN.1 conversions with DER encoding for a Targets role that contains
    delegations but specifies no targets.
    """
    der_conversion_tester(
        'repository_data/targets_simpler.json', self)



  @unittest.expectedFailure
  # THIS NEXT TEST FAILS because the provided targets role includes delegations,
  # and the current ASN.1 conversion code does not support delegations (and
  # must be updated to do so).
  def test_10asn_convert_targets(self):
    """
    Test ASN.1-only conversion for a Targets role containing delegations and
    specifying targets. This comes from Uptane sample metadata.
    """
    asn1_pydict_conversion_tester(
        'repository_data/uptane_mainrepo_targets.json', self)
    # No delegations for the Director, so no Director test case.



  @unittest.expectedFailure
  # THIS NEXT TEST FAILS because the provided targets role includes delegations,
  # and the current ASN.1 conversion code does not support delegations (and
  # must be updated to do so).
  def test_10der_convert_targets(self):
    """
    Test ASN.1 conversions with DER encoding for a Targets role containing
    delegations and specifying targets. This comes from Uptane sample metadata.
    """
    der_conversion_tester(
        'repository_data/uptane_mainrepo_targets.json', self)
    # No delegations for the Director, so no Director test case.



  def test_11asn_convert_delegated_targets(self):
    """
    Test ASN.1-only conversion for a delegated Targets role (from an old TUF
    set of sample data).
    """
    asn1_pydict_conversion_tester(
        'repository_data/repository/metadata/role1.json', self)



  def test_11der_convert_delegated_targets(self):
    """
    Test ASN.1 conversions with DER encoding for a delegated Targets role (from
    an old TUF set of sample data).
    """
    der_conversion_tester(
        'repository_data/repository/metadata/role1.json', self)



  def test_12asn_convert_delegated_targets_uptane(self):
    """
    Test ASN.1-only conversion for a delegated Targets role from Uptane sample
    data.
    """
    asn1_pydict_conversion_tester(
        'repository_data/uptane_mainrepo_role1.json', self)
    # No delegations for the Director, so no Director test case.



  def test_12der_convert_delegated_targets_uptane(self):
    """
    Test ASN.1 conversions with DER encoding for a delegated Targets role from
    Uptane sample data.
    """
    der_conversion_tester(
        'repository_data/uptane_mainrepo_role1.json', self)
    # No delegations for the Director, so no Director test case.



  # THIS NEXT TEST fails because the TUF targets.json test file used here
  # uses a custom parameter that the ASN1 conversion does not yet support,
  # specifically 'file_permissions'.
  # TODO: <~> FIX. In order to be TUF compliant, ASN.1 metadata has to be
  # able to take arbitrary custom key-value pairs.
  # Targets custom data can be arbitrary. The targetsmetadata.py converter does
  # not support that and has to. It'll need to treat everything it's given as a
  # string regardless of its type and covert it to ASN1 with the name
  # preserved, in a dict of some sort....
  @unittest.expectedFailure
  def test_13asn_convert_targets_with_custom(self):
    """
    Test ASN.1-only conversion for a Targets role that contains an unexpected
    custom parameter. (This is permitted by the spec.)
    """
    asn1_pydict_conversion_tester(
        'repository_data/repository/metadata/targets.json', self)



  # THIS NEXT TEST fails because the TUF targets.json test file used here
  # uses a custom parameter that the ASN1 conversion does not yet support,
  # specifically 'file_permissions'.
  # TODO: <~> FIX. In order to be TUF compliant, ASN.1 metadata has to be
  # able to take arbitrary custom key-value pairs.
  # Targets custom data can be arbitrary. The targetsmetadata.py converter does
  # not support that and has to. It'll need to treat everything it's given as a
  # string regardless of its type and covert it to ASN1 with the name
  # preserved, in a dict of some sort....
  @unittest.expectedFailure
  def test_13der_convert_targets_with_custom(self):
    """
    Test ASN.1 conversions with DER encoding for a Targets role that contains
    an unexpected custom parameter. (This is permitted by the spec.)
    """
    der_conversion_tester(
        'repository_data/repository/metadata/targets.json', self)





def asn1_pydict_conversion_tester(json_fname, cls):
  """
  Given the filename of a JSON metadata role file, read it in and convert it
  into a pyasn1-based Python dictionary representations of the same data,
  then back into JSON-compatible Python dict, ensuring that the original and
  the converted-and-converted-back dictionary are equivalent.

  This test does not convert test encoding into DER.

  This test also does not test signature conversion! (Signatures are signed
  over DER encoding and this test does not encode to DER. Since the conversion
  is tested to make sure that when converted back, the data is the same,
  signatures are also not affected in that regard.)

  Note:
  This function takes as a second parameter the unittest.TestCase object whose
  functions (assertTrue etc) it can use. This is awkward and inappropriate. :P
  Find a different means of providing modularity instead of this one.
  (Can't just have this method in the class above because it would be run as
  a test. Could have default parameters and do that, but that's clunky, too.)
  """

  # 1. Load the given file (assume JSON) and extract the signed portion.
  json_signed_only_pydict = tuf.util.load_file(json_fname)['signed']


  # 2. Guess type of metadata role file.

  # Assume filename is '.../<role>.json' or '.../..._<role>.json'.
  # Isolate <role>.
  shorter_fname = json_fname[:-5] # Strip .json
  if '/' in shorter_fname:
    shorter_fname = shorter_fname[shorter_fname.rfind('/') + 1:]

  if '_' not in shorter_fname:
    role_type = shorter_fname

  else:
    role_type = shorter_fname[shorter_fname.rfind('_') + 1:]

  if role_type not in ['root', 'snapshot', 'timestamp', 'targets']:
    if 'root' in shorter_fname:
      role_type = 'root'
    elif 'snapshot' in shorter_fname:
      role_type = 'snapshot'
    elif 'timestamp' in shorter_fname:
      role_type = 'timestamp'
    elif 'targets' in shorter_fname:
      role_type = 'targets'
    else:
      # Assume this is a delegated targets role.
      role_type = 'targets'

  # 3. Choose the appropriate module given the role type and convert the
  #    JSON-compatible pydict into a pyasn1-compatible pydict and back.
  module = asn1_codec.SUPPORTED_ASN1_METADATA_MODULES[role_type]

  asn1_signed_only_pydict = module.get_asn_signed(json_signed_only_pydict)
  json_again = module.get_json_signed({'signatures': [], 'signed': asn1_signed_only_pydict})

  cls.assertTrue(json_signed_only_pydict == json_again)






def der_conversion_tester(json_fname, cls):
  """
  Given the filename of a JSON metadata role file, read it in and try performing
  various conversions into DER-encoded ASN.1 and back. Test to make sure that
  data is equivalent, and that new signatures (if re-signing is employed) are
  valid.

  Note:
  This function takes as a second parameter the unittest.TestCase object whose
  functions (assertTrue etc) it can use. This is awkward and inappropriate. :P
  Find a different means of providing modularity instead of this one.
  (Can't just have this method in the class above because it would be run as
  a test. Could have default parameters and do that, but that's clunky, too.)
  """


  role_signable_pydict = tuf.util.load_file(json_fname)

  # Test each of the different kinds of conversions


  # Test type 1: only-signed
  # Convert and return only the 'signed' portion, the metadata payload itself,
  # without including any signatures.
  role_signed_only_der = asn1_codec.convert_signed_metadata_to_der(
      role_signable_pydict, only_signed=True)
  cls.assertTrue(is_valid_nonempty_der(role_signed_only_der))
  # TODO: Convert this 'signed'-only DER back to JSON and compare the 'signed'
  # portion to the original 'signed' portion. (Do I need a new func for this?
  # The conversion from DER assumes it's in a struct matching the signable role
  # format....)

  # Now, for the purpose of testing the re-signing function below, take the hash
  # of the DER encoding of the 'signed' portion of the role metadata.
  der_signed_hash = hashlib.sha256(role_signed_only_der).digest()


  # Test type 2: full conversion
  # Convert the full signable ('signed' and 'signatures'), maintaining the
  # existing signature in a new format and encoding.
  role_signable_der = asn1_codec.convert_signed_metadata_to_der(
      role_signable_pydict)

  cls.assertTrue(is_valid_nonempty_der(role_signable_der))

  pydict_again = asn1_codec.convert_signed_der_to_dersigned_json(
      role_signable_der)

  cls.assertEqual(role_signable_pydict, pydict_again)


  # Test type 3: full conversion with re-signing
  # Convert the full signable ('signed' and 'signatures'), but discarding the
  # original signatures and re-signing over, instead, the hash of the converted,
  # ASN.1/DER 'signed' element.
  role_signable_der = asn1_codec.convert_signed_metadata_to_der(
      role_signable_pydict, resign=True,
      private_key=cls.test_signing_key)

  cls.assertTrue(is_valid_nonempty_der(role_signable_der))

  pydict_again = asn1_codec.convert_signed_der_to_dersigned_json(
      role_signable_der)

  # The signature has changed, but the 'signed' elements should not have, so
  # compare those (for the original vs converted-and-converted-back check).
  cls.assertEqual(role_signable_pydict['signed'], pydict_again['signed'])

  # The 'signatures' portion of the converted-back JSON-compatible pydict
  # should now contain a correct signature over a hash of the DER encoding of
  # the 'signed' portion of the metadata (which we also calculated earlier in
  # this test function). Check the signature.
  cls.assertTrue(tuf.keys.verify_signature(
      cls.test_signing_key,
      pydict_again['signatures'][0],
      der_signed_hash))





def is_valid_nonempty_der(der_string):
  """
  Currently a hacky test to see if the result is a non-empty byte string.

  This CAN raise false failures, stochastically, in Python2. In Python2,
  where bytes and str are the same type, we check to see if, anywhere in the
  string, there is a character requiring a \\x escape, as would almost
  certainly happen in an adequately long DER string of bytes. As a result,
  short or very regular strings may raise false failures in Python2.

  The best way to really do this test is to decode the DER and see if
  believable ASN.1 has come out of it.
  """
  if not der_string:
    return False
  elif sys.version_info.major < 3:
    return '\\x' in repr(der_string)
  else:
    return isinstance(der_string, bytes)





if __name__ == '__main__':
  unittest.main()

