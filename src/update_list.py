#!/usr/bin/python
import re
import requests
import os 

print("updating list...")
common_url = 'https://mirror.tuna.tsinghua.edu.cn/ubuntu/pool/main/g/glibc/'
# url = 'http://archive.ubuntu.com/ubuntu/pool/main/g/glibc/'
old_url = 'http://old-releases.ubuntu.com/ubuntu/pool/main/g/glibc/'
home_dir = os.environ.get('HOME', '/tmp')


def get_list(url, arch):
    content = str(requests.get(url).content)
    return re.findall(r'libc6_(2\.[0-9][0-9]-[0-9]ubuntu[0-9\.]*_{}).deb'.format(arch), content)


common_list = get_list(common_url, 'amd64')
common_list += get_list(common_url, 'i386')

with open(home_dir + '/.list', 'w') as f:
    for l in sorted(set(common_list)):
        f.write(l + '\n')

print('[+] Common list has been save to "list"')

old_list = get_list(old_url, 'amd64')
old_list += get_list(old_url, 'i386')

with open(home_dir+'/.old_list', 'w') as f:
    for l in sorted(set(old_list)):
        f.write(l + '\n')

print('[+] Old-release list has been save to "old_list"')
