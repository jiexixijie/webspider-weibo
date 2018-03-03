#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Time    : 2018/2/27 16:41
# @Author  : jiexixijie
# @File    : webspider_weibo_login.py
import requests
import base64
import json
import re
# import Crypto.PublicKey.RSA as RSA
import binascii
import rsa as rsa
from bs4 import BeautifulSoup
from lxml import etree

class Loginweibo():
    def __init__(self,usename="233",password="233"):
        self.usname=usename
        self.password=password
        self.cookies=None


    def get_su(self):  #获取base64加密后用户名
        name="15951929358"
        a=base64.b64encode(name.encode(encoding="utf-8")).decode()
        return a

    def get_dict_data(self):
        headers={
            "User-Agent": "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:41.0) Gecko/20100101 Firefox/41.0"
        }
        su=self.get_su()
        url="https://login.sina.com.cn/sso/prelogin.php?entry=weibo&callback=sinaSSOController.preloginCallBack&" \
            "su="\
            +su+\
            "&rsakt=mod&checkpin=1&client=ssologin.js(v1.4.19)&_=1519724524255"
        S=requests.session()
        response=S.get(url,headers=headers)
        self.cookies=S.cookies
        #调用正则表达式获取pubkey
        pattern=re.compile("\{.*\}")
        data_josn=pattern.search(response.text).group(0)
        dict_data=json.loads(data_josn)
        return dict_data

    def get_sp(self):
        dict_data=self.get_dict_data()
        #16进制
        pubkey=dict_data["pubkey"]
        n=int(pubkey,16)
        servertime=dict_data["servertime"]
        nonce=dict_data["nonce"]
        password=self.password
        password=str(servertime)+"\t"+str(nonce)+"\n"+str(password)
        #16进制,ssologin.js
        e=int('10001',16)
        key = rsa.PublicKey(int(pubkey,16),65537)
        password=rsa.encrypt(password.encode("utf-8"),key)
        # k=(n,e)
        # key=RSA.construct(k)
        # password=key.encrypt(password.encode("utf-8"),key)[0]
        sp=binascii.b2a_hex(password)
        return sp

    def get_postdata(self):
        data=self.get_dict_data()
        servertime=data["servertime"]
        nonce=data["nonce"]
        rsakv=data["rsakv"]
        post_data = {
            'entry': 'weibo',
            'gateway': '1',
            'from': '',
            'savestate': '7',
            'qrcode_flag': 'false',
            'useticket': '1',
            "pagerefer": "http://passport.weibo.com/visitor/visitor?entry=miniblog&a=enter&url=http%3A%2F%2Fweibo.com%2F&domain=.weibo.com&ua=php-sso_sdk_client-0.6.14",
            'vsnf': '1',
            'su': self.get_su(),
            'service': 'miniblog',
            'servertime': servertime,
            'nonce': nonce,
            'pwencode': 'rsa2',
            'rsakv': rsakv,
            'sp': self.get_sp(),
            'sr': '1920 * 1080',
            'ncoding': 'UTF - 8',
            'prelt': '912',
            'url': "http://weibo.com/ajaxlogin.php?framelogin=1&callback=parent.sinaSSOController.feedBackUrlCallBack",
            'returntype': 'META'
        }
        return post_data

    def Login(self):
        try:
            url="https://login.sina.com.cn/sso/login.php?client=ssologin.js(v1.4.19)"
            postdata=self.get_postdata()
            print("预登录成功")
            headers = {
                "User-Agent": "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:41.0) Gecko/20100101 Firefox/41.0"
            }
            S=requests.session()
            S.cookies=self.cookies
            response=S.post(url,headers=headers,data=postdata)

            ##跳过了手机验证码
            print("正在跳转-1")
            soup=BeautifulSoup(response.text,"lxml")
            text=soup.find_all("script")[0].string
            pattern=re.compile(r"replace\((.*)\)")
            #获得跳转url-1
            jump_url_1=pattern.search(text).group(1)[1:-1]
            #获得跳转url-2
            print("正在跳转-2")
            response=S.get(url=jump_url_1,headers=headers)
            jump_url_2=pattern.search(response.text).group(1)[1:-4]
            response=S.get(url=jump_url_2,headers=headers)
            #获得跳转url-3
            pattern2=re.compile(r'"userdomain":"(.*?)"')
            domain=pattern2.search(response.text).group(1)
            print("获取domain")
            jump_url_3="http://weibo.com/"+domain
            response=S.get(url=jump_url_3,headers=headers)
            #获取账号
            print("登录成功")

            html=response.text
            pattern=re.compile(r"CONFIG\['nick'\]=(.*);")
            usename=pattern.search(html).group(1)
            pattern=re.compile(r"CONFIG\['uid'\]=(.*);")
            uid=pattern.search(html).group(1)
            print("usename:",usename,"\tuid:",uid)

        except:
            print("登录失败")



if __name__=="__main__":
    username=input("username:")
    password=input("password:")
    my=Loginweibo(username,password)
    my.Login()
