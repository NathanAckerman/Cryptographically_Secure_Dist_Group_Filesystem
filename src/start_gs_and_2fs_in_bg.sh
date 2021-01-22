killall java
rm nohup.out
rm *.bin
echo "admin" | nohup java RunGroupServer &
nohup java RunFileServer &
nohup java RunFileServer &
