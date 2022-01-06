添加WiFi驱动的绝对路径：

export WDRV_DIR= wifi的绝对路径
export HOST_PLAT=pc                    (新环境需要在platform.mak中添加)

make clean
make

// 驱动加载
insmod ZT9101xV20.ko fw=./fw/fw-9101-r2004.bin

// 驱动卸载
rmmod ZT9101xV20