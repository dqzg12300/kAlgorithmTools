#!/bin/sh

osascript <<END

tell application "Terminal"

    do script "adb shell \"su -c 'pkill -9 gx32 '\"; adb shell \"su -c 'pkill -9 gx64 '\"  ;adb shell \"su -c '/data/local/tmp/gx64 :1234 --attach 26456'\""

end tell

END
