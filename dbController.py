import sqlite3
import datetime


class DBController:
    def __init__(self, db_file):
        self.conn = sqlite3.connect(db_file, isolation_level=None)
        self.cur = self.conn.cursor()

    def __del__(self):
        self.cur.close()
        self.conn.close()

    def set_up(self):
        cur = self.cur
        cur.execute('''CREATE TABLE IF NOT EXISTS fingerprints
                        (fpid INT PRIMARY KEY, username TEXT);''')
        cur.execute('''CREATE TABLE IF NOT EXISTS workrecord
                        (no INT AUTO INCREMENT, username TEXT, datetime TEXT);''')
        self.conn.commit()

    def finger_count(self):
        cur = self.cur
        cur.execute('SELECT count(*) FROM fingerprints;')
        return cur.fetchone()[0]

    def highest_fpid(self):
        cur = self.cur
        cur.execute('SELECT fpid, username FROM fingerprints ORDER BY fpid DESC LIMIT 1;')
        result = cur.fetchone()
        if result:
            result = result[0]
        else:
            result = 0
        return result

    def add_finger(self, user_name):
        new_id = self.highest_fpid() + 1
        self.conn.execute('INSERT INTO fingerprints(fpid, username) VALUES(?, ?);',
            (new_id, user_name))
        return new_id

    def find_finger(self, fpid):
        cur = self.cur
        cur.execute('SELECT username FROM fingerprints WHERE fpid = ?;', (fpid,))
        result = cur.fetchone()
        if result:
            return result[0]
        else:
            return 'Nobody'

    def get_fingers(self, username=None):
        cur = self.cur
        if not username:
            cur.execute('SELECT fpid, username FROM fingerprints;')
        else:
            cur.execute('SELECT fpid, username FROM fingerprints WHERE username LIKE "%{}%";'.format(username))
        result = cur.fetchall()
        return result

    def del_by_id(self, fpid):
        return self.conn.execute('DELETE FROM fingerprints WHERE fpid = ?;', (fpid,)).rowcount

    def del_by_user(self, username):
        return self.conn.execute('DELETE FROM fingerprints WHERE username = ?;', (username,)).rowcount

    def del_all_fingers(self):
        return self.conn.execute('DELETE FROM fingerprints;')

    def record(self, username):
        now = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        return self.conn.execute('INSERT INTO workrecord(username, datetime) values (?, ?);', (username, now)).rowcount

    def get_workrecord(self, date=None, username=None):
        cur = self.cur
        if date and username:
            cur.execute('SELECT datetime, username FROM workrecord WHERE datetime like "%?%" AND username = ? '
                        'ORDER BY datetime;', (date, username))
        elif date:
            cur.execute('SELECT datetime, username FROM workrecord WHERE datetime like "%?%" '
                        'ORDER BY datetime;', (date,))
        elif username:
            cur.execute('SELECT datetime, username FROM workrecord WHERE username = ? ORDER BY datetime;', (username,))
        else:
            cur.execute('SELECT datetime, username FROM workrecord ORDER BY datetime')
        result = cur.fetchall()
        return result


def test():
    con = DBController(':memory:')
    assert type(con) == DBController
    con.set_up()
    assert len(con.get_workrecord()) == 0, 'query should be empty'
    assert con.finger_count() < 4095, "module could be saved fingerprints not exceed maximum"
    con.add_finger('kim sun woo')
    assert con.highest_fpid() == 1 and len(con.get_fingers()) == 1, 'db add one finger'
    assert con.get_fingers('sun woo')[0][1] == 'kim sun woo', 'should query correct'
    assert con.find_finger(1) == 'kim sun woo', 'find username by fingerprint id'
    print(con.find_finger(1))
    assert con.record('kim sun woo') == 1, 'attendance'
    print(con.get_workrecord())
    assert con.del_by_id(1) == 1, 'delete id result be 1'
    print(con.add_finger('kim sun woo'), con.add_finger('kim sun woo'))
    assert con.del_by_user('kim sun woo') == 2, 'del all by username'