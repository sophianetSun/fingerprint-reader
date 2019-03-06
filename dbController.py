import sqlite3
import datetime

class DBController:
    def __init__(self, db_file):
        self.conn = sqlite3.connect(db_file)
        self.cur = self.conn.cursor()

    def __del__(self):
        self.conn.close()

    def set_up(self):
        cur = self.cur
        cur.execute('''CREATE TABLE IF NOT EXISTS fingerprints
                        (fpid INT PRIMARY KEY, username TEXT)''')
        cur.execute("""CREATE TABLE IF NOT EXISTS workrecord
                        (no INT AUTO INCREMENT, username TEXT, date TEXT, time TEXT)""")
        self.conn.commit()

    def finger_count(self):
        cur = self.cur
        cur.execute('SELECT count(*) FROM fingerprints')
        return cur.fetchone()

    def highest_fpid(self):
        cur = self.cur
        cur.execute('SELECT fpid, username FROM fingerprints ORDER BY fpid DESC LIMIT 1')
        result = cur.fetchone()
        return result[0]

    def add_finger(self, user_name):
        new_id = self.highest_fpid() + 1
        self.conn.execute(
            'INSERT INTO fingerprints(fpid, username) VALUES(?, ?)',
            (new_id, user_name))

    def del_by_id(self, fpid):
        pass

    def del_by_user(self, username):
        pass

    def record(self, username):
        now = datetime.datetime.now()
        date = now.date().isoformat()
        time = now.time().strftime('%H:%M:%S')
        self.conn.execute(
            'INSERT INTO workrecord(username, date, time) values (?, ?, ?)',
            (username, date, time))

    def get_workrecord(self, date, username=None):
        pass


con = DBController(':memory:')
assert type(con) == DBController
con.set_up()

assert con.finger_count() < 4095, "module could be saved fingerprints not exceed maximum"