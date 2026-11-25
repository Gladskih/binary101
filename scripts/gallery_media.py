from subprocess import run

from reportlab.lib.colors import HexColor, white
from reportlab.pdfgen.canvas import Canvas


def build_pdf(output):
    canvas = Canvas(str(output), pagesize=(432, 240), invariant=True)
    canvas.setTitle("Hello, world!")
    canvas.setAuthor("Binary101")
    canvas.setFillColor(HexColor("#172138"))
    canvas.rect(0, 0, 432, 240, fill=1, stroke=0)
    canvas.setFillColor(HexColor("#B5C9EB"))
    canvas.setFont("Helvetica-Bold", 11)
    canvas.drawString(32, 190, "BINARY101")
    canvas.setFillColor(white)
    canvas.setFont("Helvetica-Bold", 33)
    canvas.drawString(32, 133, "Hello, world!")
    canvas.setFont("Helvetica", 12)
    canvas.drawString(32, 103, "A one-page PDF for the example gallery.")
    for index, color in enumerate(("#65C8DA", "#8998F6", "#FCC190")):
        canvas.setFillColor(HexColor(color))
        canvas.rect(32 + index * 126, 32, 116, 21, fill=1, stroke=0)
    canvas.showPage()
    canvas.save()


def build_media(output):
    # FFmpeg's testsrc2 gives each encoder the same generated color pattern.
    # https://ffmpeg.org/ffmpeg-filters.html#testsrc_002c-testsrc2
    source = ["ffmpeg", "-hide_banner", "-loglevel", "error", "-y", "-f", "lavfi",
              "-i", "testsrc2=size=320x180:rate=12"]
    run([*source, "-frames:v", "1", "-pix_fmt", "rgb24", output / "test-pattern.png"], check=True)
    run([*source, "-frames:v", "1", "-q:v", "3", output / "test-pattern.jpg"], check=True)
    run([*source, "-filter_complex_threads", "1", "-filter_complex",
         "fps=8,trim=duration=2,split[frames][colors];[colors]palettegen[palette];"
         "[frames][palette]paletteuse", "-loop", "0", output / "test-pattern.gif"], check=True)
    run([*source, "-f", "lavfi", "-i", "sine=frequency=440:sample_rate=48000", "-t", "2",
         "-c:v", "libvpx", "-crf", "32", "-b:v", "0", "-g", "12", "-c:a", "libopus",
         "-metadata", "title=Binary101 test pattern", output / "test-pattern.webm"], check=True)
    build_pdf(output / "hello.pdf")
