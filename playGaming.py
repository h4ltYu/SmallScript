# play game https://viettel.vn/vtgame/index.html

import pytesseract, cv2, time
import numpy as np
from requests import Session

try:
    import Image, ImageOps, ImageEnhance, imread
except ImportError:
    from PIL import Image, ImageOps, ImageEnhance

def solve_captcha(image):
    thresh = cv2.threshold(image, 150, 255, cv2.THRESH_BINARY_INV)[1]
    kernel = cv2.getStructuringElement(cv2.MORPH_RECT, (5,5))
    opening = cv2.morphologyEx(thresh, cv2.MORPH_OPEN, kernel)
    result = 255 - opening
    cv2.imshow('thresh', thresh)
    cv2.imshow('opening', opening)
    cv2.imshow('result', result)
    text = pytesseract.image_to_string(result, config='--psm 10 --oem 3 -c tessedit_char_whitelist=0123456789')
    return text

def create_opencv_image_from_bytearray(data, cv2_img_flag=0):
    img_array = np.asarray(bytearray(data), dtype=np.uint8)
    return cv2.imdecode(img_array, cv2_img_flag)

def login(number):
    ses = Session()
    res = ses.get('https://viettel.vn/api/get_captcha')
    js = res.json()
    data = ses.get(js['data']['url']).content
    image = create_opencv_image_from_bytearray(data)
    captcha = solve_captcha(image)
    ses.get('https://viettel.vn/api/get_otp_captcha?telephone={}&captcha={}&sid={}'.format(number, captcha, js['data']['sid']), headers=header)
    otp = input('Enter OTP: ')
    token = ses.post('https://viettel.vn/api/send_otp', data={'telephone':number,'otp':otp}).json()['data']['token']
    return (ses, token)

def play(ses, token):
    res = ses.get('https://viettel.vn/api/get_play_turn?token={}'.format(token)).json()
    if(res['data']['playing_turn'] > 0):
        res = ses.post('https://viettel.vn/api/minus_turns', data={'token':token,'service':'MYVIETTEL'}).json()
        print(ses.post('https://viettel.vn/api/catch_pig', data={"token":token, 'key':res['data']['key']}).json())

numbers = ['09xxxxxxxx', '03xxxxxxxx']
sessions = []

for number in numbers:
    sessions.append(login(number))

while True:
    for ses in sessions:
        play(ses[0], ses[1])
    time.sleep(300)
