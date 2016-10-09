# The code below is intended to be run IN THREE PYTHON SHELLS:
# - One for the Main Repository ("supplier")
# - One for the Director Repository
# - One for the client

# Each shell should be run in a python environment (the same environment is
# fine) that has the awwad/tuf:pinning version of TUF installed. In order to
# get everything you need, run the following:
# `pip install cffi==1.7.0 pycrypto==2.6.1 pynacl==1.0.1 cryptography`
# `pip install git+git://github.com/awwad/tuf.git@pinning`

# If you're going to be running the ASN.1 encoding scripts (not involved here),
# you'll also need to `pip install pyasn1`

# In each python window, run:
#   import uptane_test_instructions as u

# Then run the following:
# In the mainrepo's window:
#   u.mainrepo()

# In the director's window:
#   u.director()

# In the client's window:
# (AFTER THE OTHER TWO HAVE FINISHED STARTING UP AND ARE HOSTING)
#   u.client()


# ----------------
# Main repo window
# ----------------

def mainrepo():

  import os
  import sys, subprocess, time # For hosting and arguments
  import tuf.repository_tool as rt
  import shutil # for rmtree

  WORKING_DIR = os.getcwd()
  MAIN_REPO_DIR = os.path.join(WORKING_DIR, 'repomain')
  TARGETS_DIR = os.path.join(MAIN_REPO_DIR, 'targets')
  MAIN_REPO_HOST = 'http://localhost'
  MAIN_REPO_PORT = 30300


  # Whether to use existing keys or create new ones, an argument to the script.
  # (If you just copy-paste all this code in a python shell, you'll get False and
  #  use existing keys, so have the key files or override this value.)

  use_new_keys = len(sys.argv) == 2 and sys.argv[1] == '--newkeys'


  # Create target files: file1.txt and file2.txt

  if os.path.exists(TARGETS_DIR):
    shutil.rmtree(TARGETS_DIR)

  os.makedirs(TARGETS_DIR)

  fobj = open(os.path.join(TARGETS_DIR, 'file1.txt'), 'w')
  fobj.write('Contents of file1.txt')
  fobj.close()
  fobj = open(os.path.join(TARGETS_DIR, 'file2.txt'), 'w')
  fobj.write('Contents of file2.txt')
  fobj.close()


  # Create repo at './repomain'

  repomain = rt.create_new_repository('repomain')


  # Create keys and/or load keys into memory.

  if use_new_keys:
    rt.generate_and_write_ed25519_keypair('mainroot', password='pw')
    rt.generate_and_write_ed25519_keypair('maintimestamp', password='pw')
    rt.generate_and_write_ed25519_keypair('mainsnapshot', password='pw')
    rt.generate_and_write_ed25519_keypair('maintargets', password='pw')
    rt.generate_and_write_ed25519_keypair('mainrole1', password='pw')

  key_root_pub = rt.import_ed25519_publickey_from_file('mainroot.pub')
  key_root_pri = rt.import_ed25519_privatekey_from_file('mainroot', password='pw')
  key_timestamp_pub = rt.import_ed25519_publickey_from_file('maintimestamp.pub')
  key_timestamp_pri = rt.import_ed25519_privatekey_from_file('maintimestamp', password='pw')
  key_snapshot_pub = rt.import_ed25519_publickey_from_file('mainsnapshot.pub')
  key_snapshot_pri = rt.import_ed25519_privatekey_from_file('mainsnapshot', password='pw')
  key_targets_pub = rt.import_ed25519_publickey_from_file('maintargets.pub')
  key_targets_pri = rt.import_ed25519_privatekey_from_file('maintargets', password='pw')
  key_role1_pub = rt.import_ed25519_publickey_from_file('mainrole1.pub')
  key_role1_pri = rt.import_ed25519_privatekey_from_file('mainrole1', password='pw')


  # Add top level keys to the main repository.

  repomain.root.add_verification_key(key_root_pub)
  repomain.timestamp.add_verification_key(key_timestamp_pub)
  repomain.snapshot.add_verification_key(key_snapshot_pub)
  repomain.targets.add_verification_key(key_targets_pub)
  repomain.root.load_signing_key(key_root_pri)
  repomain.timestamp.load_signing_key(key_timestamp_pri)
  repomain.snapshot.load_signing_key(key_snapshot_pri)
  repomain.targets.load_signing_key(key_targets_pri)


  # Perform delegation from mainrepo's targets role to mainrepo's role1 role.

  repomain.targets.delegate('role1', [key_role1_pub],
      ['repomain/targets/file1.txt', 'repomain/targets/file2.txt'],
      threshold=1, backtrack=True,
      restricted_paths=[os.path.join(TARGETS_DIR, 'file*.txt')])


  # Add delegated role keys to repo

  repomain.targets('role1').load_signing_key(key_role1_pri)


  # Write the metadata files out to mainrepo's 'metadata.staged'

  repomain.write()


  # Move staged metadata (from the write above) to live metadata directory.

  if os.path.exists(os.path.join(MAIN_REPO_DIR, 'metadata')):
    shutil.rmtree(os.path.join(MAIN_REPO_DIR, 'metadata'))

  shutil.copytree(
      os.path.join(MAIN_REPO_DIR, 'metadata.staged'),
      os.path.join(MAIN_REPO_DIR, 'metadata'))



  # Prepare to host the main repo contents

  os.chdir(MAIN_REPO_DIR)

  command = []
  if sys.version_info.major < 3:  # Python 2 compatibility
    command = ['python', '-m', 'SimpleHTTPServer', str(MAIN_REPO_PORT)]
  else:
    command = ['python', '-m', 'http.server', str(MAIN_REPO_PORT)]

  # Begin hosting mainrepo.

  server_process = subprocess.Popen(command, stderr=subprocess.PIPE)
  print('Main Repo server process started.')
  print('Main Repo server process id: ' + str(server_process.pid))
  print('Main Repo serving on port: ' + str(MAIN_REPO_PORT))
  url = MAIN_REPO_HOST + ':' + str(MAIN_REPO_PORT) + '/'
  print('Main Repo URL is: ' + url)

  # Wait / allow any exceptions to kill the server.

  try:
    time.sleep(10000) # Stop hosting after a while.
  except:
    print('Exception caught')
    pass
  finally:
    if server_process.returncode is None:
      print('Terminating Main Repo server process ' + str(server_process.pid))
      server_process.kill()





# ----------------
# Director window
# ----------------

def director():
  import os # For paths and symlink
  import shutil # For copying directory trees
  import sys, subprocess, time # For hosting
  import tuf.repository_tool as rt


  WORKING_DIR = os.getcwd()
  MAIN_REPO_DIR = os.path.join(WORKING_DIR, 'repomain')
  DIRECTOR_REPO_DIR = os.path.join(WORKING_DIR, 'repodirector')
  TARGETS_DIR = os.path.join(MAIN_REPO_DIR, 'targets')
  DIRECTOR_REPO_HOST = 'http://localhost'
  DIRECTOR_REPO_PORT = 30301

  use_new_keys = len(sys.argv) == 2 and sys.argv[1] == '--newkeys'


  # Create repo at './repodirector'

  repodirector = rt.create_new_repository('repodirector')


  # Create keys and/or load keys into memory.

  if use_new_keys:
    rt.generate_and_write_ed25519_keypair('directorroot', password='pw')
    rt.generate_and_write_ed25519_keypair('directortimestamp', password='pw')
    rt.generate_and_write_ed25519_keypair('directorsnapshot', password='pw')
    rt.generate_and_write_ed25519_keypair('director', password='pw') # targets


  key_dirroot_pub = rt.import_ed25519_publickey_from_file('directorroot.pub')
  key_dirroot_pri = rt.import_ed25519_privatekey_from_file('directorroot', password='pw')
  key_dirtime_pub = rt.import_ed25519_publickey_from_file('directortimestamp.pub')
  key_dirtime_pri = rt.import_ed25519_privatekey_from_file('directortimestamp', password='pw')
  key_dirsnap_pub = rt.import_ed25519_publickey_from_file('directorsnapshot.pub')
  key_dirsnap_pri = rt.import_ed25519_privatekey_from_file('directorsnapshot', password='pw')
  key_dirtarg_pub = rt.import_ed25519_publickey_from_file('director.pub')
  key_dirtarg_pri = rt.import_ed25519_privatekey_from_file('director', password='pw')


  # Add top level keys to the main repository.

  repodirector.root.add_verification_key(key_dirroot_pub)
  repodirector.timestamp.add_verification_key(key_dirtime_pub)
  repodirector.snapshot.add_verification_key(key_dirsnap_pub)
  repodirector.targets.add_verification_key(key_dirtarg_pub)
  repodirector.root.load_signing_key(key_dirroot_pri)
  repodirector.timestamp.load_signing_key(key_dirtime_pri)
  repodirector.snapshot.load_signing_key(key_dirsnap_pri)
  repodirector.targets.load_signing_key(key_dirtarg_pri)


  # Add target to director.
  # FOR NOW, we symlink the targets files on the director.
  # In the future, we probably have to have the repository tools add a function
  # like targets.add_target_from_metadata that doesn't require an actual target
  # file to exist, but instead provides metadata on some hypothetical file that
  # the director may not physically hold.
  if os.path.exists(os.path.join(DIRECTOR_REPO_DIR, 'targets', 'file2.txt')):
    os.remove(os.path.join(DIRECTOR_REPO_DIR, 'targets', 'file2.txt'))

  os.symlink(os.path.join(TARGETS_DIR, 'file2.txt'),
      os.path.join(DIRECTOR_REPO_DIR, 'targets', 'file2.txt'))

  repodirector.targets.add_target(
      os.path.join(DIRECTOR_REPO_DIR, 'targets', 'file2.txt'),
      custom={"ecu-serial-number": "some_ecu_serial", "type": "application"})


  # Write to director repo's metadata.staged.
  repodirector.write()


  # Move staged metadata (from the write) to live metadata directory.

  if os.path.exists(os.path.join(DIRECTOR_REPO_DIR, 'metadata')):
    shutil.rmtree(os.path.join(DIRECTOR_REPO_DIR, 'metadata'))

  shutil.copytree(
      os.path.join(DIRECTOR_REPO_DIR, 'metadata.staged'),
      os.path.join(DIRECTOR_REPO_DIR, 'metadata'))


  # Prepare to host the director repo contents.

  os.chdir(DIRECTOR_REPO_DIR)

  command = []
  if sys.version_info.major < 3: # Python 2 compatibility
    command = ['python', '-m', 'SimpleHTTPServer', str(DIRECTOR_REPO_PORT)]
  else:
    command = ['python', '-m', 'http.server', str(DIRECTOR_REPO_PORT)]

  # Begin hosting the director's repository.

  server_process = subprocess.Popen(command, stderr=subprocess.PIPE)
  print('Director repo server process started.')
  print('Director repo server process id: ' + str(server_process.pid))
  print('Director repo serving on port: ' + str(DIRECTOR_REPO_PORT))
  url = DIRECTOR_REPO_HOST + ':' + str(DIRECTOR_REPO_PORT) + '/'
  print('Director repo URL is: ' + url)

  # Wait / allow any exceptions to kill the server.

  try:
    time.sleep(10000) # Stop hosting after a while.
  except:
    print('Exception caught')
    pass
  finally:
    if server_process.returncode is None:
      print('Terminating Director repo server process ' + str(server_process.pid))
      server_process.kill()





# ----------------
# Client window
# ----------------

def client():
  # Make client directory and copy the root file from the repository.
  import os # For paths and makedirs
  import shutil # For copyfile
  import tuf.client.updater

  WORKING_DIR = os.getcwd()
  CLIENT_DIR = os.path.join(WORKING_DIR, 'clientane')
  CLIENT_METADATA_DIR_MAINREPO_CURRENT = os.path.join(CLIENT_DIR, 'metadata', 'mainrepo', 'current')
  CLIENT_METADATA_DIR_MAINREPO_PREVIOUS = os.path.join(CLIENT_DIR, 'metadata', 'mainrepo', 'previous')
  CLIENT_METADATA_DIR_DIRECTOR_CURRENT = os.path.join(CLIENT_DIR, 'metadata', 'director', 'current')
  CLIENT_METADATA_DIR_DIRECTOR_PREVIOUS = os.path.join(CLIENT_DIR, 'metadata', 'director', 'previous')
  CLIENT_STUBREPO_DIR = os.path.join(CLIENT_DIR, 'stubrepos', '')

  # Note that the hosts and ports are drawn from pinned.json now.

  MAIN_REPO_DIR = os.path.join(WORKING_DIR, 'repomain')
  TARGETS_DIR = os.path.join(MAIN_REPO_DIR, 'targets')
  #MAIN_REPO_HOST = 'http://localhost'
  #MAIN_REPO_PORT = 30300
  DIRECTOR_REPO_DIR = os.path.join(WORKING_DIR, 'repodirector')
  #DIRECTOR_REPO_HOST = 'http://localhost'
  #DIRECTOR_REPO_PORT = 30301

  if os.path.exists(CLIENT_DIR):
    shutil.rmtree(CLIENT_DIR)

  for d in [
      CLIENT_METADATA_DIR_MAINREPO_CURRENT,
      CLIENT_METADATA_DIR_MAINREPO_PREVIOUS,
      CLIENT_METADATA_DIR_DIRECTOR_CURRENT,
      CLIENT_METADATA_DIR_DIRECTOR_PREVIOUS]:
    os.makedirs(d)

  # Get the root.json file from the mainrepo (would come with this client).
  shutil.copyfile(
      os.path.join(MAIN_REPO_DIR, 'metadata.staged', 'root.json'),
      os.path.join(CLIENT_METADATA_DIR_MAINREPO_CURRENT, 'root.json'))

  # Get the root.json file from the director repo (would come with this client).
  shutil.copyfile(
      os.path.join(DIRECTOR_REPO_DIR, 'metadata.staged', 'root.json'),
      os.path.join(CLIENT_METADATA_DIR_DIRECTOR_CURRENT, 'root.json'))

  # Add a pinned.json to this client (softlink it from a saved copy).
  os.symlink(
      os.path.join(WORKING_DIR, 'pinned.json'),
      os.path.join(CLIENT_DIR, 'metadata', 'pinned.json'))

  # Configure tuf with the client's metadata directories (where it stores the
  # metadata it has collected from each repository, in subdirectories).
  tuf.conf.repository_directory = CLIENT_DIR # This setting should probably be called client_directory instead, post-TAP4.

  # Create a TAP-4-compliant updater object. This will read pinning.json
  # and create single-repository updaters within it to handle connections to
  # each repository.
  upd = tuf.client.updater.Updater('updater')

  # Starting with just the root.json files for the director and mainrepo, and
  # pinned.json, the client will now use TUF to connect to each repository and
  # download/update top-level metadata. This call updates metadata from both
  # repositories.
  upd.refresh()

  # This call determines what the right fileinfo (hash, length, etc) for
  # target file file2.txt is. This begins by matching paths/patterns in
  # pinned.json to determine which repository to connect to. Since pinned.json
  # in this case assigns all targets to a multi-repository delegation requiring
  # consensus between the two repos "director" and "mainrepo", this call will
  # retrieve metadata from both repositories and compare it to each other, and
  # only return fileinfo if it can be retrieved from both repositories and is
  # identical (the metadata in the "custom" fileinfo field need not match, and
  # should not, since the Director will include ECU IDs in this field, and the
  # mainrepo cannot.
  # In this particular case, fileinfo will match and be stored, since both
  # repositories list file2.txt as a target, and they both have matching metadata
  # for it.
  file2_trustworthy_info = upd.target('file2.txt')

  # If you execute the following, commented-out command, you'll get a not found
  # error, because while the mainrepo specifies file1.txt, the Director does not.
  # Anything the Director doesn't also list can't be validated.
  # file1_trustworthy_info = upd.target('file1.txt')

  # Delete file2.txt if it already exists.
  if os.path.exists('./file2.txt'):
    os.remove('./file2.txt')

  # Now that we have fileinfo for file2.txt, matching the Director and mainrepo
  # (Supplier), we can download the file and only keep it if it matches that
  # fileinfo. This call will try every mirror on every repository within the
  # appropriate delegation in pinned.json until one of them works. In this case,
  # both the Director and mainrepo (Supplier) are hosting the file, just for my
  # convenience in setup. If you remove the file from the Director before calling
  # this, it will still work (assuming mainrepo still has it).
  # (The second argument here is just where to put the file.)

  upd.download_target(file2_trustworthy_info, '.')

  if os.path.exists('./file2.txt'):
    print('File file2.txt has successfully been validated and downloaded.')
    #assert False, 'File file2.txt has successfully been validated and downloaded.'
  else:
    print('Nope, file2.txt was not downloaded.')
    assert False