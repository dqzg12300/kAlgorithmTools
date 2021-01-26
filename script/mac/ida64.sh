#!/bin/sh

osascript <<END

tell application "Terminal"

    do script "adb shell \"su -c 'pkill -9 ida7 '\"; adb forward tcp:5678 tcp:5678 ;adb shell \"su -c '/data/local/tmp/ida7x64 -p5678'\""

end tell

END
