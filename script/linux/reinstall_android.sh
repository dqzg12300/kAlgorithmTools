adb push ../exec/frida-server-12.8.20-android-arm /data/local/tmp/fs12x8x32
adb push ../exec/frida-server-12.8.20-android-arm64 /data/local/tmp/fs12x8x64
adb push ../exec/linux/android_server64 /data/local/tmp/ida7x64
adb push ../exec/linux/android_server /data/local/tmp/ida7x32
adb push ../exec/linux/gdbserver64 /data/local/tmp/gx64
adb push ../exec/linux/gdbserver /data/local/tmp/gx32
adb shell "su -c 'chmod 0777 /data/local/tmp/fs12x8x32'"
adb shell "su -c 'chmod 0777 /data/local/tmp/fs12x8x64'"
adb shell "su -c 'chmod 0777 /data/local/tmp/ida7x64'"
adb shell "su -c 'chmod 0777 /data/local/tmp/ida7x32'"
adb shell "su -c 'chmod 0777 /data/local/tmp/gx64'"
adb shell "su -c 'chmod 0777 /data/local/tmp/gx32'"
pause