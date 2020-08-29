import requests
import os, sys
import bs4
import os
import time
import json
import urllib.request
import base64
import hmac
import hashlib
import binascii
import json
from bs4 import BeautifulSoup
from termcolor import colored
from Crypto import Random
from Crypto.Cipher import AES

def main_menu():
        os.system("clear")
        print(colored("""  ____  _____ ____  _                      ____    ___   """, "white"))
        print(colored(""" |  _ \|  ___|  _ \| |__   ___  _ __   ___|___ \  / _ \  """, "white"))
        print(colored(""" | | | | |_  | |_) | '_ \ / _ \| '_ \ / _ \ __) || | | | """, "white"))
        print(colored(""" | |_| |  _| |  __/| | | | (_) | | | |  __// __/ | |_| | """, "white"))
        print(colored(""" |____/|_|   |_|   |_| |_|\___/|_| |_|\___|_____(_)___/  """, "white"))
        print(colored("""                                                         """, "white"))
        print(colored(" > Добро пожаловать в DFphone v2.0", 'white'))
        print(colored("    > Разработчик - @batyarimskiy1", "red"))
        print("\n")
        print(colored("        [1] - Поиск AVITO", "white"))
        print(colored("         Поиск обьявлений на AVITO", "white"))
        print("")
        print(colored("        [2] - Поиск GETCONTACT", 'white'))
        print(colored("         Поиск в базе GETCONTACT", "white"))
        print("")
        print(colored("        [3] - Поиск STANDART", 'white'))
        print(colored("         Поиск стандартных данных", "white"))
        print("")
        print(colored("        [4] - Поиск TELEGRAM", 'white'))
        print(colored("         Поиск аккаунта TELEGRAM\n    (в разработке)", "red"))
        print("")
        print('\n')

        action = input(colored("Выберите пункт поиска: ", 'red'))
        if action == "1":
                os.system("clear")
                pars_avito()
        elif action == "2":
                os.system("clear")
                pars_getcontact()
        elif action == "3":
                os.system("clear")
                pars_simcard()
        elif action == "4":
                os.system("clear")
                pass
        elif action == "5":
                os.system("clear")
                pass
        else:
                os.system("clear")
                main_menu()




AES_KEY = 'e62efa9ff5ebbc08701f636fcb5842d8760e28cc51e991f7ca45c574ec0ab15c'
TOKEN = 'gWFDtf18f16d9c97c01a58948fee3c6201094e93d6d3f102177c5778052'

key = b'2Wq7)qkX~cp7)H|n_tc&o+:G_USN3/-uIi~>M+c ;Oq]E{t9)RC_5|lhAA_Qq%_4'


class AESCipher(object):

    def __init__(self, AES_KEY):
        self.bs = AES.block_size
        self.AES_KEY = binascii.unhexlify(AES_KEY)

    def encrypt(self, raw):
        raw = self._pad(raw)
        cipher = AES.new(self.AES_KEY, AES.MODE_ECB)
        return base64.b64encode(cipher.encrypt(raw.encode()))

    def decrypt(self, enc):
        enc = base64.b64decode(enc)
        cipher = AES.new(self.AES_KEY, AES.MODE_ECB)
        return self._unpad(cipher.decrypt(enc)).decode('utf-8')

    def _pad(self, s):
        return s + (self.bs - len(s) % self.bs) * chr(self.bs - len(s) % self.bs)

    @staticmethod
    def _unpad(s):
        return s[:-ord(s[len(s)-1:])]


aes = AESCipher(AES_KEY)

def sendPost(url, data, sig, ts):

    headers = {'X-App-Version': '4.9.1',
        'X-Token':TOKEN,
        'X-Os': 'android 5.0',
        'X-Client-Device-Id': '14130e29cebe9c39',
        'Content-Type': 'application/json; charset=utf-8',
        'Accept-Encoding': 'deflate',
        'X-Req-Timestamp': ts,
        'X-Req-Signature': sig,
        'X-Encrypted': '1'}
    r = requests.post(url, data=data, headers=headers, verify=True)
    return json.loads(aes.decrypt(r.json()['data']))

def getByPhone(phone):

    ts = str(int(time.time()))

    req = f'"countryCode":"RU","source":"search","token":"{TOKEN}","phoneNumber":"{phone}"'
    req = '{'+req+'}'
    string = str(ts)+'-'+req

    sig = base64.b64encode(hmac.new(key, string.encode(), hashlib.sha256).digest()).decode()
    crypt_data = aes.encrypt(req)

    return sendPost('https://pbssrv-centralevents.com/v2.5/search',
                    b'{"data":"'+crypt_data+b'"}', sig, ts)

def getByPhoneTags(phone):

    ts = str(int(time.time()))

    req = f'"countryCode":"RU","source":"details","token":"{TOKEN}","phoneNumber":"{phone}"'
    req = '{'+req+'}'

    string = str(ts)+'-'+req
    sig = base64.b64encode(hmac.new(key, string.encode(), hashlib.sha256).digest()).decode()
    crypt_data = aes.encrypt(req)

    return sendPost('https://pbssrv-centralevents.com/v2.5/number-detail',
                    b'{"data":"'+crypt_data+b'"}', sig, ts)



##Получаем GETCONTACT
def pars_getcontact():

        print(colored("""   ____      _         ____            _             _    """, "white"))
        print(colored("""  / ___| ___| |_      / ___|___  _ __ | |_ __ _  ___| |_  """, "white"))
        print(colored(""" | |  _ / _ \ __|____| |   / _ \| '_ \| __/ _` |/ __| __| """, "white"))
        print(colored(""" | |_| |  __/ ||_____| |__| (_) | | | | || (_| | (__| |_  """, "white"))
        print(colored("""  \____|\___|\__|     \____\___/|_| |_|\__\__,_|\___|\__| """, "white"))
        print(colored("""                                                          """, "white"))
        phone = input(colored("Номер с '+' : ", 'white'))

        if '+' not in phone:
                phone = '+'+phone

        print(colored('\n========GETCONTACT========', 'blue'))
        finfo = getByPhone(phone)

        try:
                if finfo['result']['profile']['displayName']:
                        print(colored(finfo['result']['profile']['displayName'], 'green'))
                        print(colored('Имен найдено: '+str(finfo['result']['profile']['tagCount']), 'yellow'))

                        try:
                                print('\n'.join([i['tag'] for i in getByPhoneTags(phone)['result']['tags']]))
                        except KeyError:
                                if finfo['result']['profile']['tagCount'] > 0:
                                        print('Имя найдено, но для просморта нужен премиум')
                                        print('Телеграм - @BatyaRimskiy1')
                                else:
                                        pass
                else:
                        print('Не найдено!')
        except:
                print('Не найдено!')


def pars_avito():

        print(colored("""     _        _ _         """, "white"))
        print(colored("""    / \__   _(_) |_ ___   """, "white"))
        print(colored("""   / _ \ \ / / | __/ _ \  """, "white"))
        print(colored("""  / ___ \ V /| | || (_) | """, "white"))
        print(colored(""" /_/   \_\_/ |_|\__\___/  """, "white"))
        print(colored("""                          """, "white"))
        phone = input(colored("Номер с '+' : ", 'white'))
        os.system("clear")

        page = requests.get('https://mirror.bullshit.agency/search_by_phone/'+phone)
        soup = BeautifulSoup(page.text, 'html.parser')

        print(colored("========PARSER AVITO=======", 'white'))
        print("\n")

        #tag html search and class = name
        classsell=soup.find(class_='media-heading')
        namesell= soup.find_all('h4')

        #for tag = name
        for classsell in namesell:
                print(colored("Название обьявления: ", 'green'), classsell.text)

        #tag html search and class = adresat
        classtext = soup.find(class_='text-muted')
        nametext = soup.find_all('span')

        #for tag = adresat
        for classtext in nametext:
                print(colored("Найден адрес и дата\n", 'green'), classtext.text)

def pars_simcard():
        print(colored("""  ____ ___ __  __        ____              _  """, "white"))
        print(colored(""" / ___|_ _|  \/  |      / ___|__ _ _ __ __| | """, "white"))
        print(colored(""" \___ \| || |\/| |_____| |   / _` | '__/ _` | """, "white"))
        print(colored("""  ___) | || |  | |_____| |__| (_| | | | (_| | """, "white"))
        print(colored(""" |____/___|_|  |_|      \____\__,_|_|  \__,_| """, "white"))
        print(colored("""                                              """, "white"))
        phone = input(colored("Номер c '+': ", 'white'))
        try:
                getInfo = "https://htmlweb.ru/geo/api.php?json&telcod=" + str(phone)
                try:
                        infoPhone = urllib.request.urlopen( getInfo )
                except:
                        print( "\nТелефон не найден\n" )
                infoPhone = json.load( infoPhone )
                print( u"Страна:", infoPhone["country"]["name"] )
                print( u"Регион:", infoPhone["region"]["name"] )
                print( u"Округ:", infoPhone["region"]["okrug"] )
                print( u"Оператор:", infoPhone["0"]["oper"] )
                print( u"Часть света:", infoPhone["country"]["location"] )
        except:
                print(colored("Не найдено!", "red"))
main_menu()
