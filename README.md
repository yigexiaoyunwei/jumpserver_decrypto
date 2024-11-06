# jumpserver_decrypto

jumpserver解密secret代码

## 🚀attention🚀

对jumpserver的数据库做解密,使用前记得修改config.py里面的配置文件。

解密失败请先查看config.py里面的SECRET_KEY是否正确。

SECRET_KEY在/opt/jumpserver/config/config.txt文件中。

要求最低使用python3.8版本。

## **🐍**python3.9 install**🐍**

一站式python3.9安装

```
bash <(curl -sSL https://linuxmirrors.cn/main.sh)
yum update -y
yum install -y openssl-devel sqlite-devel libffi-devel gcc wget
yum install -y freetype-devel xz-devel
wget https://www.python.org/ftp/python/3.9.12/Python-3.9.12.tar.xz
tar -xf Python-3.9.12.tar.xz
cd Python-3.9.12/
./configure --prefix=/usr/local/python39 --enable-shared
make && make install
ln -sf /usr/local/python39/bin/python3 /usr/bin/python3
ln -sf /usr/local/python39/bin/pip3 /usr/bin/pip3
ln -sf /usr/local/python39/lib/libpython3.9.so.1.0 /usr/lib64/libpython3.9.so.1.0
```

## **✨**Getting started**✨**

将导出的jumpserver sql文件导入到数据库，修改config文件中的相关配置，直接运行main即可

```
pip3 install -r requirements.txt 
python3 main.py
```
