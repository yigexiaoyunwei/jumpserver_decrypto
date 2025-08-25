import pymysql
from pymysql import cursors
import csv
import config
from ctypes import *
from pycryptodo import math
from tqdm import tqdm
import psycopg2
import psycopg2.extras

cipher_alg_id = {
    "sm4_ebc": 0x00000401,
    "sm4_cbc": 0x00000402,
}

ECCref_MAX_BITS = 512
ECCref_MAX_LEN = int((ECCref_MAX_BITS + 7) / 8)

hash_alg_id = {
    "sm3": 0x00000001,
    "sha1": 0x00000002,
    "sha256": 0x00000004,
    "sha512": 0x00000008,
}


class Digest:

    def __init__(self, session, alg_name="sm3"):
        if hash_alg_id[alg_name] is None:
            raise Exception("unsupported hash alg {}".format(alg_name))

        self._alg_name = alg_name
        self._session = session
        self.__init_hash()

    def __init_hash(self):
        self._session.hash_init(hash_alg_id[self._alg_name])

    def update(self, data):
        self._session.hash_update(data)

    def final(self):
        return self._session.hash_final()

    def reset(self):
        self.__init_hash()

    def destroy(self):
        self._session.close()


class PiicoError(Exception):
    def __init__(self, msg, ret):
        super().__init__(self)
        self.__ret = ret
        self.__msg = msg

    def __str__(self):
        return "piico error: {} return code: {}".format(self.__msg, self.hex_ret(self.__ret))

    @staticmethod
    def hex_ret(ret):
        return hex(ret & ((1 << 32) - 1))


class ECCCipher:
    def __init__(self, session, public_key, private_key):
        self._session = session
        self.public_key = public_key
        self.private_key = private_key

    def encrypt(self, plain_text):
        return self._session.ecc_encrypt(self.public_key, plain_text, 0x00020800)

    def decrypt(self, cipher_text):
        return self._session.ecc_decrypt(self.private_key, cipher_text, 0x00020800)


class EBCCipher:

    def __init__(self, session, key_val):
        self._session = session
        self._key = self.__get_key(key_val)
        self._alg = "sm4_ebc"
        self._iv = None

    def __get_key(self, key_val):
        key_val = self.__padding(key_val)
        return self._session.import_key(key_val)

    @staticmethod
    def __padding(val):
        val = bytes(val)
        while len(val) == 0 or len(val) % 16 != 0:
            val += b'\0'
        return val

    def encrypt(self, plain_text):
        plain_text = self.__padding(plain_text)
        cipher_text = self._session.encrypt(plain_text, self._key, cipher_alg_id[self._alg], self._iv)
        return bytes(cipher_text)

    def decrypt(self, cipher_text):
        plain_text = self._session.decrypt(cipher_text, self._key, cipher_alg_id[self._alg], self._iv)
        return bytes(plain_text)

    def destroy(self):
        self._session.destroy_cipher_key(self._key)
        self._session.close()

class CBCCipher(EBCCipher):

    def __init__(self, session, key, iv):
        super().__init__(session, key)
        self._iv = iv
        self._alg = "sm4_cbc"

class EncodeMixin:
    def encode(self):
        raise NotImplementedError


class ECCrefPublicKey(Structure, EncodeMixin):
    _fields_ = [
        ('bits', c_uint),
        ('x', c_ubyte * ECCref_MAX_LEN),
        ('y', c_ubyte * ECCref_MAX_LEN),
    ]

    def encode(self):
        return bytes([0x04]) + bytes(self.x[32:]) + bytes(self.y[32:])


class ECCrefPrivateKey(Structure, EncodeMixin):
    _fields_ = [
        ('bits', c_uint,),
        ('K', c_ubyte * ECCref_MAX_LEN),
    ]

    def encode(self):
        return bytes(self.K[32:])


class ECCCipherEncode(EncodeMixin):

    def __init__(self):
        self.x = None
        self.y = None
        self.M = None
        self.C = None
        self.L = None

    def encode(self):
        c1 = bytes(self.x[32:]) + bytes(self.y[32:])
        c2 = bytes(self.C[:self.L])
        c3 = bytes(self.M)
        return bytes([0x04]) + c1 + c2 + c3


def new_ecc_cipher_cla(length):
    _cache = {}
    cla_name = "ECCCipher{}".format(length)
    if _cache.__contains__(cla_name):
        return _cache[cla_name]
    else:
        cla = type(cla_name, (Structure, ECCCipherEncode), {
            "_fields_": [
                ('x', c_ubyte * ECCref_MAX_LEN),
                ('y', c_ubyte * ECCref_MAX_LEN),
                ('M', c_ubyte * 32),
                ('L', c_uint),
                ('C', c_ubyte * length)
            ]
        })
        _cache[cla_name] = cla
        return cla


class ECCKeyPair:
    def __init__(self, public_key, private_key):
        self.public_key = public_key
        self.private_key = private_key

class BaseMixin:

    def __init__(self):
        self._driver = None
        self._session = None


class SM2Mixin(BaseMixin):
    def ecc_encrypt(self, public_key, plain_text, alg_id):

        pos = 1
        k1 = bytes([0] * 32) + bytes(public_key[pos:pos + 32])
        k1 = (c_ubyte * len(k1))(*k1)
        pos += 32
        k2 = bytes([0] * 32) + bytes(public_key[pos:pos + 32])

        pk = ECCrefPublicKey(c_uint(0x40), (c_ubyte * len(k1))(*k1), (c_ubyte * len(k2))(*k2))

        plain_text = (c_ubyte * len(plain_text))(*plain_text)
        ecc_data = new_ecc_cipher_cla(len(plain_text))()
        ret = self._driver.SDF_ExternalEncrypt_ECC(self._session, c_int(alg_id), pointer(pk), plain_text,
                                                   c_int(len(plain_text)), pointer(ecc_data))
        if ret != 0:
            raise Exception("ecc encrypt failed", ret)
        return ecc_data.encode()

    def ecc_decrypt(self, private_key, cipher_text, alg_id):

        k = bytes([0] * 32) + bytes(private_key[:32])
        vk = ECCrefPrivateKey(c_uint(0x40), (c_ubyte * len(k))(*k))

        pos = 1
        # c1
        x = bytes([0] * 32) + bytes(cipher_text[pos:pos + 32])
        pos += 32
        y = bytes([0] * 32) + bytes(cipher_text[pos:pos + 32])
        pos += 32

        # c2
        c = bytes(cipher_text[pos:-32])
        l = len(c)

        # c3
        m = bytes(cipher_text[-32:])

        ecc_data = new_ecc_cipher_cla(l)(
            (c_ubyte * 64)(*x),
            (c_ubyte * 64)(*y),
            (c_ubyte * 32)(*m),
            c_uint(l),
            (c_ubyte * l)(*c),
        )
        temp_data = (c_ubyte * l)()
        temp_data_length = c_int()
        ret = self._driver.SDF_ExternalDecrypt_ECC(self._session, c_int(alg_id), pointer(vk),
                                                   pointer(ecc_data),
                                                   temp_data, pointer(temp_data_length))
        if ret != 0:
            raise Exception("ecc decrypt failed", ret)
        return bytes(temp_data[:temp_data_length.value])


class SM3Mixin(BaseMixin):
    def hash_init(self, alg_id):
        ret = self._driver.SDF_HashInit(self._session, c_int(alg_id), None, None, c_int(0))
        if ret != 0:
            raise PiicoError("hash init failed,alg id is {}".format(alg_id), ret)

    def hash_update(self, data):
        data = (c_ubyte * len(data))(*data)
        ret = self._driver.SDF_HashUpdate(self._session, data, c_int(len(data)))
        if ret != 0:
            raise PiicoError("hash update failed", ret)

    def hash_final(self):
        result_data = (c_ubyte * 32)()
        result_length = c_int()
        ret = self._driver.SDF_HashFinal(self._session, result_data, pointer(result_length))
        if ret != 0:
            raise PiicoError("hash final failed", ret)
        return bytes(result_data[:result_length.value])


class SM4Mixin(BaseMixin):

    def import_key(self, key_val):
        # to c lang
        key_val = (c_ubyte * len(key_val))(*key_val)

        key = c_void_p()
        ret = self._driver.SDF_ImportKey(self._session, key_val, c_int(len(key_val)), pointer(key))
        if ret != 0:
            raise PiicoError("import key failed", ret)
        return key

    def destroy_cipher_key(self, key):
        ret = self._driver.SDF_DestroyKey(self._session, key)
        if ret != 0:
            raise Exception("destroy key failed")

    def encrypt(self, plain_text, key, alg, iv=None):
        return self.__do_cipher_action(plain_text, key, alg, iv, True)

    def decrypt(self, cipher_text, key, alg, iv=None):
        return self.__do_cipher_action(cipher_text, key, alg, iv, False)

    def __do_cipher_action(self, text, key, alg, iv=None, encrypt=True):
        text = (c_ubyte * len(text))(*text)
        if iv is not None:
            iv = (c_ubyte * len(iv))(*iv)

        temp_data = (c_ubyte * len(text))()
        temp_data_length = c_int()
        if encrypt:
            ret = self._driver.SDF_Encrypt(self._session, key, c_int(alg), iv, text, c_int(len(text)), temp_data,
                                           pointer(temp_data_length))
            if ret != 0:
                raise PiicoError("encrypt failed", ret)
        else:
            ret = self._driver.SDF_Decrypt(self._session, key, c_int(alg), iv, text, c_int(len(text)), temp_data,
                                           pointer(temp_data_length))
            if ret != 0:
                raise PiicoError("decrypt failed", ret)
        return temp_data[:temp_data_length.value]


def get_mysql_conn():
    try:
        conn = pymysql.connect(
            host=config.host,
            port=config.port,
            user=config.user,
            password=config.password,
            database=config.database
        )
        return conn
    except pymysql.MySQLError as e:
        print(f"Error connecting to MySQL Database: {e}")
        return None
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        return None


class Session(SM2Mixin, SM3Mixin, SM4Mixin):
    def __init__(self, driver, session):
        super().__init__()
        self._session = session
        self._driver = driver

    def get_device_info(self):
        pass

    def generate_random(self, length=64):
        random_data = (c_ubyte * length)()
        ret = self._driver.SDF_GenerateRandom(self._session, c_int(length), random_data)
        if ret != 0:
            raise PiicoError("generate random error", ret)
        return bytes(random_data)

    def generate_ecc_key_pair(self, alg_id):
        public_key = ECCrefPublicKey()
        private_key = ECCrefPrivateKey()
        ret = self._driver.SDF_GenerateKeyPair_ECC(self._session, c_int(alg_id), c_int(256), pointer(public_key),
                                                   pointer(private_key))
        if ret != 0:
            raise PiicoError("generate ecc key pair failed", ret)
        return ECCKeyPair(public_key.encode(), private_key.encode())

    def close(self):
        ret = self._driver.SDF_CloseSession(self._session)
        if ret != 0:
            raise PiicoError("close session failed", ret)

class Device:
    _driver = None
    __device = None

    def open(self, driver_path="./libpiico_ccmu.so"):
        # load driver
        self.__load_driver(driver_path)
        # open device
        self.__open_device()

    def close(self):
        if self.__device is None:
            raise Exception("device not turned on")
        ret = self._driver.SDF_CloseDevice(self.__device)
        if ret != 0:
            raise Exception("turn off device failed")
        self.__device = None

    def new_session(self):
        session = c_void_p()
        ret = self._driver.SDF_OpenSession(self.__device, pointer(session))
        if ret != 0:
            raise Exception("create session failed")
        return Session(self._driver, session)

    def generate_ecc_key_pair(self):
        session = self.new_session()
        return session.generate_ecc_key_pair(alg_id=0x00020200)

    def generate_random(self, length=64):
        session = self.new_session()
        return session.generate_random(length)

    def new_sm2_ecc_cipher(self, public_key, private_key):
        session = self.new_session()
        return ECCCipher(session, public_key, private_key)

    def new_sm4_ebc_cipher(self, key_val):
        session = self.new_session()
        return EBCCipher(session, key_val)

    def new_sm4_cbc_cipher(self, key_val, iv):
        session = self.new_session()
        return CBCCipher(session, key_val, iv)

    def new_digest(self, mode="sm3"):
        session = self.new_session()
        return Digest(session, mode)

    def __load_driver(self, path):
        # check driver status
        if self._driver is not None:
            raise Exception("already load driver")
        # load driver
        self._driver = cdll.LoadLibrary(path)

    def __open_device(self):
        device = c_void_p()
        ret = self._driver.SDF_OpenDevice(pointer(device))
        if ret != 0:
            raise PiicoError("open piico device failed", ret)
        self.__device = device


def open_piico_device(driver_path) -> Device:
    d = Device()
    d.open(driver_path)
    return d

def get_jp_info(conn):
    result = ()
    try:
        # sql = 'select accounts_account.`name` as account_name, accounts_account.username, accounts_account.secret_type, accounts_account._secret as secret, accounts_account.is_active, assets_asset.address, assets_asset.`name` as asset_name, assets_platform.`name` as platform_name, assets_platform.type from accounts_account INNER JOIN assets_asset ON accounts_account.asset_id=assets_asset.id INNER JOIN assets_platform ON assets_asset.platform_id=assets_platform.id;'
        sql = 'select accounts_account.`name` as account_name, accounts_account.username, accounts_account.secret_type, accounts_account.secret, accounts_account.is_active, assets_asset.address, assets_asset.`name` as asset_name, assets_platform.`name` as platform_name, assets_platform.type from accounts_account INNER JOIN assets_asset ON accounts_account.asset_id=assets_asset.id INNER JOIN assets_platform ON assets_asset.platform_id=assets_platform.id;'
        cursor = conn.cursor(cursors.DictCursor)
        cursor.execute(sql)
        result = cursor.fetchall()
    except Exception as e:
        sql = 'select accounts_account.`name` as account_name, accounts_account.username, accounts_account.secret_type, accounts_account._secret as secret, accounts_account.is_active, assets_asset.address, assets_asset.`name` as asset_name, assets_platform.`name` as platform_name, assets_platform.type from accounts_account INNER JOIN assets_asset ON accounts_account.asset_id=assets_asset.id INNER JOIN assets_platform ON assets_asset.platform_id=assets_platform.id;'
        # sql = 'select accounts_account.`name` as account_name, accounts_account.username, accounts_account.secret_type, accounts_account.secret, accounts_account.is_active, assets_asset.address, assets_asset.`name` as asset_name, assets_platform.`name` as platform_name, assets_platform.type from accounts_account INNER JOIN assets_asset ON accounts_account.asset_id=assets_asset.id INNER JOIN assets_platform ON assets_asset.platform_id=assets_platform.id;'
        cursor = conn.cursor(cursors.DictCursor)
        cursor.execute(sql)
        result = cursor.fetchall()

    cursor.close()
    return result


def get_postgresql_conn():
    conn = psycopg2.connect(dbname=config.database, user=config.user, password=config.password, host=config.host, port=config.port)
    cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)

    sql = 'SELECT accounts_account.name AS account_name,accounts_account.username,accounts_account.secret_type,accounts_account._secret AS secret,accounts_account.is_active,assets_asset.address,assets_asset.name AS asset_name,assets_platform.name AS platform_name,assets_platform.type FROM accounts_account INNER JOIN assets_asset ON accounts_account.asset_id = assets_asset.id INNER JOIN assets_platform ON assets_asset.platform_id = assets_platform.id;'
    cursor.execute(sql)
    result = cursor.fetchall()
    conn.close()
    # 需要转成 list[dict]，跟 MySQL 统一
    return [dict(row) for row in result]

def read_text_file(file_path):
    try:
        with open(file_path, 'r') as file:
            return file.read()
    except FileNotFoundError:
        print(f"File not found: {file_path}")
        return None

def write_data_to_file(file, data):
    writer = csv.DictWriter(file, fieldnames=['account_name', 'username', 'secret_type', 'secret', 'is_active', 'address', 'asset_name', 'platform_name', 'type'])
    writer.writeheader()
    for e in tqdm(data):
        crypto = math.Crypto(e, config.SECRET_KEY)
        e['secret'] = crypto.decrypt()
        writer.writerow(e)



if __name__ == "__main__":
    result = ()
    if config.type == 1:
        conn = get_mysql_conn()
        result = get_jp_info(conn)
        conn.close()
    if config.type == 2:
        result = get_postgresql_conn()

    f = open("jumpserver.csv", 'w', newline='')
    write_data_to_file(f, result)
    f.close()
