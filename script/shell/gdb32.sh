adb shell "su -c 'pkill -9 gx32 '"
adb shell "su -c 'pkill -9 gx64 '"
adb shell "su -c '/data/local/tmp/gx32 :1234 --attach #pid'"