import fingerprint as fp
import serial

HEAD = 0xF5
TAIL = 0xF5

IMG_MAX = 9176


class FpController:
    def __init__(self, port, baudrate, timeout):
        self.ser = serial.Serial(port, baudrate, timeout=timeout)

    def __del__(self):
        self.ser.close()

    def is_valid(self, res):
        assert res[0] == HEAD and res[len(res) - 1] == TAIL, 'response data start HEAD and end TAIL byte(0xF5)'
        q3 = res[4]
        if not q3 == fp.ACK_SUCCESS:
            if q3 == fp.ACK_FULL:
                raise AssertionError("user's fingerprint number not exceed 4095")
            elif q3 == fp.ACK_TIMEOUT:
                raise RuntimeError('Read Fingerprint Timeout')
            elif q3 == fp.ACK_FAIL:
                raise RuntimeError('Read Fingerprint Not Read')
            elif q3 == fp.ACK_USER_EXIST:
                raise RuntimeError('User Exist')
            elif q3 == fp.ACK_NO_USER:
                raise RuntimeError('No User of this fingerprint')
            elif q3 == fp.ACK_NO_USER:
                raise RuntimeError('No User')
        return True

    def set_dormant_state(self):
        self.ser.write(fp.set_dormant_state())
        res = self.ser.read(8)

    def get_fingerprint_mode(self):
        self.ser.write(fp.fingerprint_mode('read'))
        res = self.ser.read(8)
        self.is_valid(res)

        if res[3] == 0:
            return 'allow repeat'
        elif res[3] == 1:
            return 'prohibit repeat'

    def set_fingerprint_mode(self, repeat):
        """

        :param repeat: boolean
        :return:
        """
        self.ser.write(fp.fingerprint_mode('set', repeat=repeat))
        res = self.ser.read(8)
        self.is_valid(res)

    def first_add_fp(self, user_id):
        self.ser.write(fp.add_fingerprint_first(user_id))
        res = self.ser.read(8)
        return res[4]

    def second_add_fp(self, user_id):
        self.ser.write(fp.add_fingerprint_second(user_id))
        res = self.ser.read(8)
        return res[4]

    def third_app_fp(self, user_id):
        self.ser.write(fp.add_fingerprint_third(user_id))
        res = self.ser.read(8)
        return res[4]

    def add_fingerprint(self, user_id):
        """
        Add fingerprint process
        3 times read attempt
        :param user_id: string
        :return: boolean
        """
        res = self.first_add_fp(user_id)
        self.is_valid(res)
        res = self.second_add_fp(user_id)
        self.is_valid(res)
        res = self.third_app_fp(user_id)
        self.is_valid(res)

        return True

    def del_user(self, user_id):
        """
        Delete specified user
        :param uid: str
        :return: boolean
        """
        self.ser.write(fp.del_specified_user(user_id))
        res = self.ser.read(8)
        self.is_valid(res)

        return True

    def get_total_user_cnt(self):
        self.ser.write(fp.get_total_users())
        res = self.ser.read(8)
        self.is_valid(res)
        return int.from_bytes(res[2:4], 'big')

    def compare_by_id(self, user_id):
        self.ser.write(fp.compare_by_id(user_id))
        res = self.ser.read(8)
        self.is_valid(res)
        return True

    def compare_fingerprint_get_id(self):
        """

        :return: user_id str
        """
        self.ser.write(fp.compare_many())
        res = self.ser.read(8)
        self.is_valid(res)
        return res[2:4].decode()

    def get_user_privilege(self, user_id):
        """

        :param user_id: str
        :return: privilege int
        """
        self.ser.write(fp.get_user_privilege(user_id))
        res = self.ser.read(8)
        if res[4] == fp.ACK_NO_USER:
            raise RuntimeError('Not Match User of user_id')
        return int.from_bytes(res[4], 'big')

    def get_dsp_module_version(self):
        self.ser.write(fp.get_dsp_version())
        head = self.ser.read(8)
        if self.is_valid(head):
            data_len = int.from_bytes(head[2:4])
            packet = self.ser.read(data_len + 3)
            assert packet[0] == HEAD and packet[-1] == TAIL
            chk = len(packet) - 2
            data = packet[1:chk]
            return data.decode()

    def set_comparison_level(self, level):
        self.ser.write(fp.set_comp_level(level))
        res = self.ser.read(8)
        self.is_valid(res)

    def get_compparison_level(self):
        self.ser.write(fp.get_comp_level())
        res = self.ser.read(8)
        self.is_valid(res)
        return res[3]

    def acquire_uploaded_imgs(self):
        self.ser.write(fp.acquire_upload_imgs())
        head = self.ser.read(8)
        if self.is_valid(head):
            length = int.from_bytes(head[2:4], 'big')
            packet = self.ser.read(length + 3)
            assert packet[0] == HEAD and packet[-1] == TAIL
            chk = len(packet) - 2
            data = packet[1:chk]
            assert len(data) <= IMG_MAX, 'img size should less than IMG_MAX bytes'
            return data

    def extracted_uploaded_eigenvalue(self):
        self.ser.write(fp.upload_extract_eigenvalue())
        head = self.ser.read(8)
        if self.is_valid(head):
            data_len = head[2:4]
            packet = self.ser.read(data_len + 3)
            assert packet[0] == HEAD and packet[-1] == TAIL
            data = packet[4:-2]
            assert len(data) <= 193, 'eigen values less than 193 bytes'
            return data

    def send_eigenval_and_comparison(self, eigen_val):
        """

        :param eigen_val: binary data
        :return: boolean
        """
        self.ser.write(fp.download_eigenvalues_comp_fingerprint(eigen_val))
        res = self.ser.read(8)
        self.is_valid(res)
        return True

    def send_egval_and_comparison_by_id(self, user_id, eigen_val):
        self.ser.write(fp.download_eigenvalues_comp_db_by_id(user_id, eigen_val))
        res = self.ser.read(8)
        self.is_valid(res)
        return True

    def send_egval_and_find_id_privilege(self, eigen_val):
        self.ser.write(fp.download_eigenvalues_comp_db_many(eigen_val))
        res = self.ser.read(8)
        assert res[0] == HEAD and res[-1] == TAIL
        user_id = res[2:4].decode()
        self.is_valid(res)
        status = res[4]
        return user_id, status

    def get_specifed_eigen_val_by_id(self, user_id):
        """

        :param user_id: str
        :return: id str, privilege int, eigenvalues binary
        """
        self.ser.write(fp.upload_dsp_by_id(user_id))
        head = self.ser.read(8)
        self.is_valid(head)
        data_len = int.from_bytes(head[2:4], 'big')
        packet = self.ser.read(data_len + 3)
        res_id = packet[1:3].decode()
        res_pri = packet[3]
        res_eg_val = packet[4:-2]
        return res_id, res_pri, res_eg_val

    def send_eigenval_and_save_by_id(self, user_id, eigen_val):
        self.ser.write(fp.download_eigenvalue_save_by_id(user_id, eigen_val))
        res = self.ser.read(8)
        self.is_valid(res)

    def get_all_users(self):
        """

        :return: array of (id str, privilege int)
        """
        self.ser.write(fp.all_user_id_privilege())
        head = self.ser.read(8)
        self.is_valid(head)
        data_len = int.from_bytes(head[2:4])
        packet = self.ser.read(data_len)
        assert packet[0] == HEAD and packet[-1] == TAIL
        num = int.from_bytes(packet[1:3])
        users_data = packet[3:-2]
        users = []
        for idx, data in range (num):
            id_idx = 3 * idx
            pri_idx = 3 * idx + 2
            user_id = users_data[id_idx:id_idx+2].decode()
            privilege = users_data[pri_idx]
            user = (user_id, privilege)
            users.append(user)

        return users

    def set_timeout(self, timeout):
        """

        :param timeout: int range of 0-255 approximately 0.2-0.3 * timeout
        :return:
        """
        self.ser.write(fp.set_timeout(timeout))
        res = self.ser.read(8)
        self.is_valid(res)

    def get_timeout(self):
        self.ser.write(fp.get_timeout())
        res = self.ser.read(8)
        self.is_valid(res)
        return res[3]

