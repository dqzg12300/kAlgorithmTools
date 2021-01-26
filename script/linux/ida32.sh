adb shell "su -c 'pkill -9 ida7 '"
adb forward tcp:5678 tcp:5678
adb shell "su -c '/data/local/tmp/ida7x32 -p5678'"