# play game https://viettel.vn/vtgame/index.html

import pytesseract, cv2
import numpy as np
from requests import Session
from time import sleep
try:
    import Image, ImageOps, ImageEnhance
except ImportError:
    from PIL import Image, ImageOps, ImageEnhance

def solve_captcha(image):
    thresh = cv2.threshold(image, 150, 255, cv2.THRESH_BINARY_INV)[1]
    kernel = cv2.getStructuringElement(cv2.MORPH_RECT, (5,5))
    opening = cv2.morphologyEx(thresh, cv2.MORPH_OPEN, kernel)
    result = 255 - opening
    captcha = pytesseract.image_to_string(result, config='--psm 10 --oem 3 -c tessedit_char_whitelist=0123456789')
    return captcha

def create_opencv_image_from_bytearray(data, cv2_img_flag=0):
    img_array = np.asarray(bytearray(data), dtype=np.uint8)
    return cv2.imdecode(img_array, cv2_img_flag)

header = {
	'Host' : 'viettel.vn',
	'User-Agent' : 'Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0',
	'Accept' : 'application/json, text/javascript, */*; q=0.01',
	'Accept-Language' : 'en-US,en;q=0.5',
	'Accept-Encoding' : 'gzip, deflate, br',
	'DNT' : '1',
	'Connection' : 'keep-alive',
}

def login(num):
    ses = Session()
    js = ses.get("https://viettel.vn/api/get_captcha", headers=header).json()
    data = ses.get(js['data']['url'], headers=header).content
    img = create_opencv_image_from_bytearray(data)
    captcha = solve_captcha(img)
    ses.get("https://viettel.vn/api/get_otp_captcha?telephone={}&captcha={}&sid={}".format(num, captcha, js['data']['sid']), headers=header)
    otp = input("Enter OTP for {}: ".format(num))
    ses.headers["Cookie"] = "apimyvt_session="+ses.cookies.get("apimyvt_session", domain="viettel.vn") #did not check whether need or not
    res = ses.post("https://viettel.vn/api/send_otp", data={'telephone':num,'otp':otp}).json()
    tok = res['data']['token']
    return (ses, tok)

def play(ses, tok):
    try:
        res = ses.get("https://viettel.vn/api/get_play_turn?token={}".format(tok)).json()
        print(res)
        if(res['data']['playing_turn'] > 0):
            res = ses.post("https://viettel.vn/api/minus_turns", data={'token':tok,'service':'MYVIETTEL'}).json()
            print(ses.post("https://viettel.vn/api/catch_pig", data={"token":tok, 'key':res['data']['key']}).json())
    except Exception as ex:
        print(ex)

numbers = ['092xxxxxxx', '038xxxxxxx', '033xxxxxx']
sessions = []

for number in numbers:
    sessions.append(login(number))

while True:
    for ses, tok in sessions:
        play(ses, tok)
    sleep(60) #don't know when session timeout because of idle, so i leave it 60 seconds
