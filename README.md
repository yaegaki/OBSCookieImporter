# OBSCookieImporter
Import OBS browser cookies from Chrome.

## Requirements
* Python 3

```sh
$ pip install cryptography
```

## Usage

```sh
# Import .youtube.com cookies(default)
$ python main.py

# Import .nicovideo.jp cookies
$ python main.py --host .nicovideo.jp

# Import cookies from another path
$ python main.py --source path/to/source/cookie --dest path/to/dest/cookie
```

## Reference

* [taizan-hokuto/chrome_cookie](https://github.com/taizan-hokuto/chrome_cookie)
