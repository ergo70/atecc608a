from cryptoauthlib import *
from cryptoauthlib.device import *
from threading import Lock
from uuid import UUID

"""This module exposes some of the functionality of the Microchip Technology Inc atecc608a cryptochip.

   Low level functions are already available through cryptoauthlib (https://github.com/MicrochipTech/cryptoauthlib),
   developed by Microchip Technology Inc.

   This aims to provide high level functionality, ready to use with only basic knowledge about the inner
   workings of the atecc608a device."""

__author__ = "Ernst-Georg Schmid"
__copyright__ = "Copyright (c) 2019 Bayer AG, Ernst-Georg Schmid"
__license__ = "MIT"
__version__ = "1.0"
__maintainer__ = "Ernst-Georg Schmid"
__email__ = "pgchem@tuschehund.de"

atca_names_map = {'i2c': 'i2c', 'hid': 'kithid',
                  'sha': 'sha204', 'ecc': 'eccx08'}


class _Singleton(type):
    _instances = {}

    def __call__(cls, *args, **kwargs):
        if cls not in cls._instances:
            cls._instances[cls] = super(
                _Singleton, cls).__call__(*args, **kwargs)
        return cls._instances[cls]


class Atecc608aException(Exception):
    pass


class Device(metaclass=_Singleton):

    FIRST_MONOTONIC_COUNTER = 0
    SECOND_MONOTONIC_COUNTER = 1
    AES_BLOCKSIZE = 16

    def __init__(self, i2c_bus=1, i2c_address=0x60):
        self.lock = Lock()

        with self.lock:
            load_cryptoauthlib()
            cfg = eval('cfg_at{}a_{}_default()'.format(
                atca_names_map.get('ecc'), atca_names_map.get('i2c')))
            icfg = getattr(cfg.cfg, 'atca{}'.format('i2c'))
            setattr(icfg, 'slave_address', i2c_address << 1)
            setattr(icfg, 'bus', i2c_bus)
            self.cfg = cfg

    def _check_valid_slot(self, slot):
        if type(slot) is int:
            if slot < 0 or slot > 15:
                raise Atecc608aException(
                    'Slot {} out of range'.format(slot))
        else:
            raise Atecc608aException('Invalid slot number. Must be integer.')

    def _serial_number(self):
        serial = bytearray(9)

        with self.lock:
            # self._init_device()
            status = atcab_read_serial_number(serial)
            success = (Status.ATCA_SUCCESS == status)

        if success:
            return serial
        else:
            raise Atecc608aException(
                'Serial number failed with status {}'.format(status))

    def _read_config(self):
        with self.lock:
            # self._init_device()
            config_data = bytearray(128)
            status = atcab_read_config_zone(config_data)
            success = (Status.ATCA_SUCCESS == status)
            if success:
                return Atecc608aConfig.from_buffer(config_data)
            else:
                raise Atecc608aException(
                    'Read config failed with status {}'.format(status))

    def _read_public_key(self, slot):
        self._check_valid_slot(slot)

        config = self._read_config()

        with self.lock:
            # self._init_device()
            if not config.KeyConfig[slot].Private:
                # Public key slot. Proceed.
                public_key = bytearray(64)
                status = atcab_read_pubkey(slot, public_key)
                success = (Status.ATCA_SUCCESS == status)

                if success:
                    return public_key
                else:
                    raise Atecc608aException(
                        'Read public key from slot {} failed with status {}'.format(slot, status))

    def _read_public_key_from_keypair(self, slot):
        self._check_valid_slot(slot)

        config = self._read_config()

        with self.lock:
            # self._init_device()
            if config.KeyConfig[slot].Private:
                # Private key slot. Proceed.
                public_key = bytearray(64)
                status = atcab_get_pubkey(slot, public_key)
                success = (Status.ATCA_SUCCESS == status)

                if success:
                    return public_key
                else:
                    raise Atecc608aException(
                        'Read public key from keypair in slot {} failed with status {}'.format(slot, status))

    def _gen_keypair(self, slot, lock_slot_after_generation, i_am_really_really_sure):
        self._check_valid_slot(slot)

        config = self._read_config()

        with self.lock:
            # self._init_device()
            if config.KeyConfig[slot].Private:
                # Private key slot. Proceed.
                if config.LockValue != 0x55:
                    # Data zone is already locked, additional checks apply
                    if not config.SlotConfig[slot].WriteConfig & 0x02:
                        raise Atecc608aException(
                            'Keypair generation (GenKey) is disabled for slot {}'.format(slot))
                    if not config.SlotLocked & (1 << slot):
                        raise Atecc608aException(
                            'Slot {} has been locked'.format(slot))
                    if config.KeyConfig[slot].ReqAuth:
                        raise Atecc608aException(
                            'Slot {} requires authorization'.format(slot))
                    if config.KeyConfig[slot].PersistentDisable:
                        raise Atecc608aException(
                            'Slot {} requires persistent latch'.format(slot))

                    # Generate key pair in given slot
                    public_key = bytearray(64)
                    status = atcab_genkey(slot, public_key)
                    success = (Status.ATCA_SUCCESS == status)
                    if success:
                        if lock_slot_after_generation and 'yes' == i_am_really_really_sure:
                            # Lock down key pair in given slot
                            status = atcab_lock_data_slot(slot)
                            success = (Status.ATCA_SUCCESS == status)
                            if not success:
                                raise Atecc608aException(
                                    'Locking down slot {} failed with status {}'.format(slot, status))

                        return public_key
                    else:
                        raise Atecc608aException(
                            'Keypair generation (GenKey) in slot {} failed with status {}'.format(slot, status))
            else:
                raise Atecc608aException(
                    'Slot {} is not suitable to hold a private key'.format(slot))

    def _write_32_bytes_to_slot(self, data, slot, lock_slot_after_generation, i_am_really_really_sure):
        self._check_valid_slot(slot)
        if (not type(data) is bytearray) and 32 != len(data):
            raise Atecc608aException(
                'Data must be bytearray[32]')

        # Read the device configuration
        config = self._read_config()

        with self.lock:
            # self._init_device()
            if not config.KeyConfig[slot].Private:
                # Private key slot. Proceed.
                if config.LockValue != 0x55:
                    # Data zone is already locked, additional checks apply
                    if not config.SlotLocked & (1 << slot):
                        raise Atecc608aException(
                            'Slot {} has been locked'.format(slot))
                    if config.KeyConfig[slot].ReqAuth:
                        raise Atecc608aException(
                            'Slot {} requires authorization'.format(slot))
                    if config.KeyConfig[slot].PersistentDisable:
                        raise Atecc608aException(
                            'Slot {} requires persistent latch'.format(slot))

                    status = atcab_write_bytes_zone(2, slot, 0, data, 32)
                    success = (Status.ATCA_SUCCESS == status)
                    if success:
                        if lock_slot_after_generation and 'yes' == i_am_really_really_sure:
                            status = atcab_lock_data_slot(slot)
                            success = (Status.ATCA_SUCCESS == status)
                            if not success:
                                raise Atecc608aException(
                                    'Locking down slot {} failed with status {}'.format(slot, status))
                    else:
                        raise Atecc608aException(
                            'Data write to slot {} failed with status {}'.format(slot, status))
            else:
                raise Atecc608aException(
                    'Slot {} is not suitable to hold data'.format(slot))

    def _aes128_pad(self, block):
        """16 byte block padding according to J.-P. Aumasson, Serious Cryptography, 2018, Page 69-70."""
        if type(block) is bytearray:
            blocksize = len(block)
            if blocksize == 0 or blocksize == self.AES_BLOCKSIZE:
                return block
            elif 0 < blocksize < self.AES_BLOCKSIZE:
                num_bytes = self.AES_BLOCKSIZE-blocksize
                return block + bytearray([num_bytes for _ in range(num_bytes)])

        return None

    def _aes128_unpad(self, block):
        """16 byte block unpadding according to J.-P. Aumasson, Serious Cryptography, 2018, Page 69-70."""
        if type(block) is bytearray and len(block) == self.AES_BLOCKSIZE:
            padbytes = [
                bytearray(
                    [16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16]),
                bytearray(
                    [15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15]),
                bytearray(
                    [14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14, 14]),
                bytearray(
                    [13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13, 13]),
                bytearray(
                    [12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12, 12]),
                bytearray(
                    [11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11]),
                bytearray(
                    [10, 10, 10, 10, 10, 10, 10, 10, 10, 10]),
                bytearray(
                    [9, 9, 9, 9, 9, 9, 9, 9, 9]),
                bytearray(
                    [8, 8, 8, 8, 8, 8, 8, 8]),
                bytearray(
                    [7, 7, 7, 7, 7, 7, 7]),
                bytearray(
                    [6, 6, 6, 6, 6, 6]),
                bytearray(
                    [5, 5, 5, 5, 5]),
                bytearray(
                    [4, 4, 4, 4]),
                bytearray(
                    [3, 3, 3]),
                bytearray(
                    [2, 2]),
                bytearray(
                    [1])
            ]

            for p in range(self.AES_BLOCKSIZE):
                pos = block.rfind(bytes(padbytes[p]))
                if pos != -1:
                    return(block[:pos])

            return block

        return None

    def _aes128_encrypt_cbc(self, plaintext, slot, iv, key_block):
        self._check_valid_slot(slot)
        if iv:
            if not (type(iv) is bytearray and len(iv) == self.AES_BLOCKSIZE):
                raise Atecc608aException('IV must be a bytearray[16]')
            _iv = iv
        else:
            _iv = self.random_32_bytes()[: 16]

        if not (type(plaintext) is bytearray and len(plaintext) > 0):
            raise Atecc608aException(
                'Plaintext must be a non-empty bytearray')
        else:
            num_blocks, remainder = divmod(len(plaintext), self.AES_BLOCKSIZE)

            if remainder == 0:
                plaintext += bytearray(
                    [self.AES_BLOCKSIZE for _ in range(self.AES_BLOCKSIZE)])

            num_blocks += 1

        with self.lock:
            # self._init_device()
            ctx = atca_aes_cbc_ctx()
            status = atcab_aes_cbc_init(
                ctx, slot, key_block, _iv)

            success = (Status.ATCA_SUCCESS == status)

            if success:
                ciphertext = bytearray()

                start_pos = 0
                end_pos = self.AES_BLOCKSIZE

                for b in range(1, num_blocks+1):
                    ciphertext_block = bytearray(self.AES_BLOCKSIZE)

                    if b < num_blocks:
                        plaintext_block = plaintext[start_pos:end_pos]
                    else:
                        plaintext_block = self._aes128_pad(
                            plaintext[start_pos:end_pos])

                    status = atcab_aes_cbc_encrypt_block(
                        ctx, plaintext_block, ciphertext_block)

                    if not (Status.ATCA_SUCCESS == status):
                        success = False

                    ciphertext += ciphertext_block
                    start_pos = end_pos
                    end_pos += self.AES_BLOCKSIZE

                if not success:
                    raise Atecc608aException(
                        'AES128 CBC encryption with key in slot {} failed with status {}'.format(slot, status))

                return _iv, ciphertext
            else:
                raise Atecc608aException(
                    'AES128 CBC setup from key in slot {} failed with status {}'.format(slot, status))

    def _aes128_decrypt_cbc(self, ciphertext, slot, iv, key_block):
        self._check_valid_slot(slot)
        if iv:
            if not (type(iv) is bytearray and len(iv) == self.AES_BLOCKSIZE):
                raise Atecc608aException('IV must be a bytearray[16]')
        else:
            raise Atecc608aException('IV missing')

        if not (type(ciphertext) is bytearray and len(ciphertext) > 0):
            raise Atecc608aException(
                'Ciphertext must be a non-empty bytearray')
        else:
            num_blocks, remainder = divmod(len(ciphertext), self.AES_BLOCKSIZE)
            if remainder != 0:
                raise Atecc608aException(
                    'Ciphertext size must be divisible by {} without remainder'.format(self.AES_BLOCKSIZE))

        with self.lock:
            # self._init_device()
            ctx = atca_aes_cbc_ctx()
            status = atcab_aes_cbc_init(
                ctx, slot, key_block, iv)
            success = (Status.ATCA_SUCCESS == status)

            if success:
                plaintext = bytearray()

                start_pos = 0
                end_pos = self.AES_BLOCKSIZE

                for b in range(1, num_blocks+1):
                    ciphertext_block = ciphertext[start_pos:end_pos]
                    plaintext_block = bytearray(self.AES_BLOCKSIZE)
                    status = atcab_aes_cbc_decrypt_block(
                        ctx, ciphertext_block, plaintext_block)

                    if not (Status.ATCA_SUCCESS == status):
                        success = False

                    if b < num_blocks:
                        plaintext += plaintext_block
                    else:
                        plaintext += self._aes128_unpad(plaintext_block)

                    start_pos = end_pos
                    end_pos += self.AES_BLOCKSIZE

                if not success:
                    raise Atecc608aException(
                        'AES128 CBC decryption with key in slot {} failed with status {}'.format(slot, status))

                return plaintext
            else:
                raise Atecc608aException(
                    'AES128 CBC setup from key in slot {} failed with status {}'.format(slot, status))

    def _device_type(self):
        """Return the device type."""

        # 0: ATSHA204A
        # 1: ATECC108A
        # 2: ATECC508A
        # 3: ATECC608A
        # 4: ATCA_DEV_UNKNOWN

        with self.lock:
            # self._init_device()
            status = atcab_get_device_type()
            success = (ATCADeviceType.ATCA_DEV_UNKNOWN != status)

            if not success:
                raise Atecc608aException(
                    'Reading device type failed with status {}'.format(status))

        return status

    # User servicable parts below

    def read_twatchdog(self):
        """Read tWatchdog setting in seconds."""
        config = self._read_config()

        t_watchdog = config.ChipMode.WatchdogDuration

        if t_watchdog == 0:
            return 1.3
        elif t_watchdog == 1:
            return 10.0

    def attach_device(self):
        """Initialize the device."""
        with self.lock:
            if not (Status.ATCA_SUCCESS == atcab_init(self.cfg)):
                raise Atecc608aException(
                    'Init of device on I2C bus {} at I2C address 0x{:02x} failed with status {}'.format(i2c_bus, i2c_address, status))

        if self._device_type() != 3:
            raise Atecc608aException(
                'Devices other than atecc608a not implemented')

    def sleep_device(self):
        """Set the device to sleep mode."""
        with self.lock:
            if not (Status.ATCA_SUCCESS == atcab_sleep()):
                raise Atecc608aException(
                    'Sleep of device on I2C bus {} at I2C address 0x{:02x} failed with status {}'.format(i2c_bus, i2c_address, status))

    def idle_device(self):
        """Set the device to idle mode. This disables the sleep watchdog!

           Use this for operations exceeding tWatchdog. Leave idle mode by wakeup_device()."""
        with self.lock:
            if not (Status.ATCA_SUCCESS == atcab_idle()):
                raise Atecc608aException(
                    'Idling of device on I2C bus {} at I2C address 0x{:02x} failed with status {}'.format(i2c_bus, i2c_address, status))

    def wakeup_device(self):
        """Wake up the device"""
        with self.lock:
            if not (Status.ATCA_SUCCESS == atcab_wakeup()):
                raise Atecc608aException(
                    'Wake up of device on I2C bus {} at I2C address 0x{:02x} failed with status {}'.format(i2c_bus, i2c_address, status))

    def detach_device(self):
        """Release the device."""
        with self.lock:
            if not (Status.ATCA_SUCCESS == atcab_release()):
                raise Atecc608aException(
                    'Release of device on I2C bus {} at I2C address 0x{:02x} failed with status {}'.format(i2c_bus, i2c_address, status))

    def sign_message(self, slot, msg):
        """Sign a 32 byte message with the EC private key in the given slot."""
        self._check_valid_slot(slot)

        if not (type(msg) is bytearray and len(msg) == 32):
            raise Atecc608aException(
                'Message must be a bytearray[32]')

        with self.lock:
            # self._init_device()
            signature = bytearray(64)
            status = atcab_sign(slot, msg, signature)
            success = (Status.ATCA_SUCCESS == status)

            if success:
                return signature
            else:
                raise Atecc608aException(
                    'Signing with key from slot {} failed with status {}'.format(slot, status))

    def verify_message(self, msg, signature, public_key):
        """Verify a 32 byte message with a signature and the EC public key in the given slot."""
        if not (type(msg) is bytearray and len(msg) == 32):
            raise Atecc608aException(
                'Message must be a bytearray[32]')

        if not (type(signature) is bytearray and len(signature) == 64):
            raise Atecc608aException(
                'Signature must be a bytearray[64]')

        if not (type(public_key) is bytearray and len(public_key) == 64):
            raise Atecc608aException(
                'Public key must be a bytearray[64]')

        with self.lock:
            # self._init_device()
            is_verified = AtcaReference(2)
            status = atcab_verify_extern(
                msg, signature, public_key, is_verified)
            success = (Status.ATCA_SUCCESS == status)

            if success:
                if is_verified == 1:
                    return True
                elif is_verified == 0:
                    return False
                else:
                    raise Atecc608aException(
                        'Something wicked this way comes!')
            else:
                raise Atecc608aException(
                    'Verify with key from slot {} failed with status {}'.format(slot, status))

    def sha256(self, data):
        """Generate the SHA-256 hash of the data given."""
        if not (type(data) is bytearray and len(data) > 0):
            raise Atecc608aException('Data must be bytearray and not empty.')

        with self.lock:
            # self._init_device()
            digest = bytearray(32)
            status = atcab_sha(len(data), data, digest)
            success = (Status.ATCA_SUCCESS == status)

            if success:
                return digest
            else:
                raise Atecc608aException(
                    'SHA-256 failed with status {}'.format(status))

    def read_32_bytes_from_slot(self, slot):
        """Read 32 bytes from the given slot as bytearray."""
        self._check_valid_slot(slot)
        data = bytearray(32)

        with self.lock:
            # self._init_device()
            status = atcab_read_bytes_zone(2, slot, 0, data, 32)
            success = (Status.ATCA_SUCCESS == status)

            if success:
                return data
            else:
                raise Atecc608aException(
                    'Data read from slot {} failed with status {}'.format(slot, status))

    def random_32_bytes(self):
        """Return 32 random generated bytes from the device as bytearray."""
        entropy = bytearray(32)

        with self.lock:
            # self._init_device()
            status = atcab_random(entropy)
            success = (Status.ATCA_SUCCESS == status)

            if not success:
                raise Atecc608aException(
                    'Reading random 32 bytes failed with status {}'.format(status))

        return entropy

    def device_revision(self):
        """Return the device revision as bytearray[4]."""
        with self.lock:
            # self._init_device()
            revision = bytearray(4)
            status = atcab_info(revision)
            success = (Status.ATCA_SUCCESS == status)

            if not success:
                raise Atecc608aException(
                    'Reading device revision failed with status {}'.format(status))

        return revision

    def device_serial_number(self):
        """Return the unique 9 byte serial number of the device as colon separated hexadecimal string."""
        serial = self._serial_number()
        return ''.join(':{:02x}'.format(b) for b in serial)[1:]

    def device_UUID(self, cust=b'\x01'):
         """Return a stable unique UUID based on the serial number of the device and a custom byte."""
        if not (type(cust) is bytes and 1 == len(cust)):
            raise Atecc608aException('Custom byte must be exactly one byte.')
        serial = self._serial_number()
        return UUID(bytes=(bytes(serial + b'\x0a\xff\x11\x03\x19\x71' + cust)))

    def increment_monotonic_counter(self, counter):
        """Increment the given monotonic counter and return its new value."""
        if counter not in [self.FIRST_MONOTONIC_COUNTER, self.SECOND_MONOTONIC_COUNTER]:
            raise Atecc608aException(
                'Only counters {} and {} can be incremented'.format(self.FIRST_MONOTONIC_COUNTER, self.SECOND_MONOTONIC_COUNTER))

        with self.lock:
            # self._init_device()
            newval = AtcaReference(-1)
            status = atcab_counter_increment(counter, newval)
            success = (Status.ATCA_SUCCESS == status)

        if success:
            newval = int(newval)
            return newval
        else:
            raise Atecc608aException(
                'Increment monotonic counter {} failed with status {}'.format(counter, status))

    def read_monotonic_counter(self, counter):
        """Read the given monotonic counter and return its current value."""
        if counter not in [self.FIRST_MONOTONIC_COUNTER, self.SECOND_MONOTONIC_COUNTER]:
            raise Atecc608aException(
                'Only counters {} and {} can be read'.format(self.FIRST_MONOTONIC_COUNTER, self.SECOND_MONOTONIC_COUNTER))

        with self.lock:
            # self._init_device()
            currval = AtcaReference(-1)
            status = atcab_counter_read(counter, currval)
            success = (Status.ATCA_SUCCESS == status)

        if success:
            return currval
        else:
            raise Atecc608aException(
                'Read monotonic counter {} failed with status {}'.format(counter, status))

    def read_public_key_from_keypair(self, slot):
        """Read the public key of a EC keypair in the given slot."""
        return self._read_public_key_from_keypair(slot)

    def generate_keypair(self, slot, lock_slot_after_generation=False, i_am_really_really_sure='NO!'):
        """Generate a random EC keypair in the given slot.

           The slot will only be locked if its lockable and you are really, really sure."""
        return self._gen_keypair(slot, lock_slot_after_generation, i_am_really_really_sure)

    def write_32_bytes_to_slot(self, data, slot, lock_slot_after_generation=False, i_am_really_really_sure='NO!'):
        """Write the 32 bytes given to the given slot.

           The slot will only be locked if its lockable and you are really, really sure."""
        self._write_32_bytes_to_slot(
            data, slot, lock_slot_after_generation, i_am_really_really_sure)

    def aes128_encrypt_cbc_eiv(self, plaintext, slot, iv=None, key_block=0):
        """Encrypt a plaintext with AES128 and the key in the given slot.

           The IV is random generated and will be returned."""
        return self._aes128_encrypt_cbc(plaintext, slot, iv, key_block)

    def aes128_decrypt_cbc_eiv(self, ciphertext, slot, iv, key_block=0):
        """Decrypt a plaintext with AES128 and the key in the given slot.

           The IV is random generated and will be returned."""
        return self._aes128_decrypt_cbc(ciphertext, slot, iv, key_block)

    def aes128_encrypt_cbc_pb(self, plaintext, slot, key_block=0):
        """Encrypt a plaintext with AES128 and the key in the given slot."""
        phantom_block = self.random_32_bytes()[:16]
        _plaintext = phantom_block + plaintext
        _, ciphertext = self._aes128_encrypt_cbc(
            _plaintext, slot, None, key_block)
        return ciphertext

    def aes128_decrypt_cbc_pb(self, ciphertext, slot, key_block=0):
        """Decrypt a plaintext with AES128 and the key in the given slot."""
        phantom_iv = self.random_32_bytes()[:16]
        plaintext = self._aes128_decrypt_cbc(
            ciphertext, slot, phantom_iv, key_block)
        return plaintext[self.AES_BLOCKSIZE:]

    def public_key2PEM(self, public_key):
        """Convert a 256 byte EC public key into PEM format."""
        if type(public_key) is bytearray and len(public_key) == 64:
            return convert_ec_pub_to_pem(public_key)
        else:
            raise Atecc608aException(
                'ECC public key must be of type bytearray[64]')
