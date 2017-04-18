# Apache Json logging module
This module logging reqeust data(include post-body data) to json format.
<br>And support dynamic load module

Basically Apache is support access.log and can modify log format to json.
<br>I just want to understand how Apache work.
<br>This module is not perfect because it was written for learning purposes.

This module tested on Apache 2.2, 2.4 version.

## Output data in log file>

```
{
  "Request":"POST /wordpress/wp-login.php HTTP/1.1",
  "Content-Type":"text/html",
  "Request-date":"Fri Nov 04 09:55:52 2016",
  "Post-body":"log=scott&pwd=******&wp-submit=%EB%A1%9C%EA%B7%B8%EC%9D%B8&redirect_to=http%3A%2F%2F192.168.10.140%2Fwordpress%2Fwp-admin%2Fprofile.php&testcookie=1",
  "Host":"192.168.10.140",
  "Upgrade-Insecure-Requests":"1",
  "Connection":"keep-alive",
  "Remote-addr":"192.168.10.1",
  "Referer":"http://192.168.10.140/wordpress/wp-login.php?redirect_to=http%3A%2F%2F192.168.10.140%2Fwordpress%2Fwp-admin%2Fprofile.php&reauth=1",
  "Cache-Control":"max-age=0",
  "Accept":"text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
  "Content-Length":"148",
  "Cookie":"wp-settings-1=editor%3Dhtml%26libraryContent%3Dbrowse; wp-settings-time-1=1478061389; wordpress_test_cookie=WP+Cookie+check",
  "Origin":"http://192.168.10.140",
  "Method":"POST",
  "User-Agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/53.0.2785.143 Safari/537.36",
  "Accept-Encoding":"gzip, deflate",
  "Accept-Language":"ko-KR,ko;q=0.8,en-US;q=0.6,en;q=0.4",
  "Server":"Apache",
  "Uri":"/wordpress/wp-login.php",
  "Status":200
}

```

# Installation>
## Dependency
For using this module, you should be require jansson library(i use 2.7.1 version)<br>

**[Ubuntu]**

```
# sudo apt-get update
# sudo apt-get install libjansson-dev
```

**[CentOS]**

```
# yum -y install epel-release
# yum -y install jansson-devel
```

## Build

```
# apxs -i -a -c mod_json_module.c -ljansson
```

## Apply module
Apache have a different service name, directory about CentOS and Ubuntu.
<br>You may have automatically generated a configuration file from a previous build.
<br>You can also enter data into an automatically generated file or delete and rename an existing file.

**[Ubuntu]**

1. Create jsonlog module config.
  ```
  # cat > /etc/apache2/conf-enabled/apajson.conf
  mp_secure pwd password passwd secure
  mp_log /var/log/apajon/apachejson.log

  # cat > /etc/apache2/mods-enabled/apajson.load
  LoadModule mod_json_module   /usr/lib/apache2/modules/mod_json_module.so
  ```

2. Create log directory and change permission.

  ```
  # mkdir /var/log/apajson
  # chown www-data:www-data /var/log/apajson
  ```

3. restart or reload service

  ```
  # service apache2 restart
  ```

**[CentOS 7]**

1. Create jsonlog module config.
  ```
  # cat > /etc/httpd/conf.d/apajson.conf
  mp_secure pwd password passwd secure
  mp_log /var/log/apajon/apachejson.log

  # cat > /etc/httpd/conf.modules.d/00-apajson.conf
  LoadModule mod_json_module   /usr/lib64/httpd/modules/mod_json_module.so
  ```

2. Change secure context (if selinux enable.)

  ```
  # chcon -u system_u /etc/httpd/conf.d/apajson.conf
  # chcon -u system_u /etc/httpd/conf.modules.d/00-apajson.conf
  # restorecon /etc/httpd/conf.d/apajson.conf
  # restorecon //etc/httpd/conf.modules.d/00-apajson.conf
  ```

3. Create log directory and change permission.

  ```
  # mkdir /var/log/apajson
  # chown apache:apache /var/log/apajson
  ```

4. restart or reload service

  ```
  # service httpd restart
  ```

**[CentOS 5, 6]**

1. Create jsonlog module config.
  ```
  # cat > /etc/httpd/conf.d/apajson.conf
  LoadModule mod_json_module   /usr/lib64/httpd/modules/mod_json_module.so

  mp_secure pwd password passwd secure
  mp_log /var/log/apajon/apachejson.log
  ```

2. Change secure context (if selinux enable.)

  ```
  # chcon -u system_u /etc/httpd/conf.d/apajson.conf
  # restorecon /etc/httpd/conf.d/apasjon.conf
  ```

3. Create log directory and change permission.

  ```
  # mkdir /var/log/apajson
  # chown apache:apache /var/log/apajson
  ```

4. restart or reload service

  ```
  # service httpd restart
  ```
