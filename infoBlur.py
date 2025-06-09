import cv2
import re

def blur_sensitive_info(image_path, ocr_json, patterns):
    img = cv2.imread(image_path)

    for item in ocr_json:
        text = item.get('inferText', '')
        for pattern in patterns:
            if re.fullmatch(pattern, text):
                vertices = item['boundingPoly']['vertices']
                x_coords = [v['x'] for v in vertices]
                y_coords = [v['y'] for v in vertices]
                x, y = int(min(x_coords)), int(min(y_coords))
                w = int(max(x_coords) - x)
                h = int(max(y_coords) - y)

                roi = img[y:y+h, x:x+w]
                blurred = cv2.GaussianBlur(roi, (25, 25), 0)
                img[y:y+h, x:x+w] = blurred

    # 저장할 파일 경로 결정
    blurred_path = image_path.replace('.png', '_blurred.png')
    cv2.imwrite(blurred_path, img)
    print(f"[🖼️] 블러 처리 완료: {blurred_path}")