#adb push ../exec/frida-server-12.8.20-android-arm /data/local/tmp/fs12x8x32
#adb push ../exec/frida-server-12.8.20-android-arm64 /data/local/tmp/fs12x8x64
#adb push ../exec/android_server64 /data/local/tmp/ida7x64
#adb push ../exec/android_server /data/local/tmp/ida7x32
#adb push ../exec/gdbserver64 /data/local/tmp/gx64
#adb push ../exec/gdbserver /data/local/tmp/gx32
#adb shell "su -c 'chmod 0777 /data/local/tmp/fs12x8x32'"
#adb shell "su -c 'chmod 0777 /data/local/tmp/fs12x8x64'"
#adb shell "su -c 'chmod 0777 /data/local/tmp/ida7x64'"
#adb shell "su -c 'chmod 0777 /data/local/tmp/ida7x32'"
#adb shell "su -c 'chmod 0777 /data/local/tmp/gx64'"
#adb shell "su -c 'chmod 0777 /data/local/tmp/gx32'"

#!/bin/sh

osascript <<END

tell application "Terminal"

    do script "adb push /Users/achen/git_src/kAlgorithmTools//exec/frida-server-12.8.20-android-arm /data/local/tmp/fs12x8x32;adb push /Users/achen/git_src/kAlgorithmTools//exec/frida-server-12.8.20-android-arm64 /data/local/tmp/fs12x8x64;adb push /Users/achen/git_src/kAlgorithmTools//exec/android_server64 /data/local/tmp/ida7x64;adb push /Users/achen/git_src/kAlgorithmTools//exec/android_server /data/local/tmp/ida7x32;adb push /Users/achen/git_src/kAlgorithmTools//exec/gdbserver64 /data/local/tmp/gx64;adb push /Users/achen/git_src/kAlgorithmTools//exec/gdbserver /data/local/tmp/gx32;adb shell \"su -c 'chmod 0777 /data/local/tmp/*'\""


end tell

END
