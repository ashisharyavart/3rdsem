from PIL import Image, ImageDraw
import os

def create_icons():
    os.makedirs('assets/icons', exist_ok=True)
    size = (128, 128)
    img = Image.new('RGBA', size, (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)

    # Outer shield border
    shield_poly = [
        (64, 10),
        (114, 25),
        (104, 85),
        (64, 120),
        (24, 85),
        (14, 25)
    ]
    draw.polygon(shield_poly, fill=(14, 165, 233, 255), outline=(56, 189, 248, 255))

    # Inner shield fill
    inner_poly = [
        (64, 22),
        (102, 34),
        (94, 80),
        (64, 110),
        (34, 80),
        (26, 34)
    ]
    draw.polygon(inner_poly, fill=(15, 23, 42, 255))

    # Checkmark / Guardian symbol
    draw.line([(45, 62), (58, 76), (85, 48)], fill=(56, 189, 248, 255), width=7)

    img.save('assets/icons/shield.png')
    img.resize((32, 32), Image.Resampling.LANCZOS).save('assets/icons/shield_32.png')
    img.resize((16, 16), Image.Resampling.LANCZOS).save('assets/icons/shield_16.png')
    print("Icon generated successfully.")

if __name__ == "__main__":
    create_icons()

