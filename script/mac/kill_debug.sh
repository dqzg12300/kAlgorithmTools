
#!/bin/sh

osascript <<END

tell application "Terminal"

    do script "adb shell \"su -c 'pkill -9 ida7 '\" ; adb shell \"su -c 'pkill -9 frida '\" ; adb shell \"su -c 'pkill -9 gx32 '\";  adb shell \"su -c 'pkill -9 gx64 '\""

end tell

END