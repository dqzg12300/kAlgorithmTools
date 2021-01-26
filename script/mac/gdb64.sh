#!/bin/sh

osascript <<END

tell application "Terminal"

    do script "adb shell \"su -c 'pkill -9 gx32 '\"; adb shell \"su -c 'pkill -9 gx64 '\"  ; adb forward tcp:1234 tcp:1234 ; adb shell \"su -c '/data/local/tmp/gx64 :1234 --attach #pid'\""

end tell

END
