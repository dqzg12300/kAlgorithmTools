
#!/bin/sh

osascript <<END

tell application "Terminal"

    do script "adb shell \"su -c 'pkill -9 fs12x8 '\"; adb forward tcp:27042 tcp:27042 ;adb forward tcp:27043 tcp:27043 ; adb shell \"su -c '/data/local/tmp/fs12x8x64'\""

end tell

END
