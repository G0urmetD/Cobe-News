"""Feed text going out (mail, chat, push, webhook, forwarding): control and direction characters neutralised – the one
place that decides, used by app/notify.py (Story, the renderers' one-line helpers), app/forward.py (the forwarded
story and the comment), app/webpush.py and app/weekly.py (through notify.one_line).

A story title is somebody else's text. The Unicode direction controls (U+202A–202E embeddings and overrides, U+2066–2069
isolates, U+200E/200F and U+061C marks) let it show "‮gnp.exe" as "exe.png" or move a link's label away from where it
seems to be; other control characters (C0 except line feed and tab, DEL, C1) break mail headers, terminals and parsers.
Direction characters go (a story needs none to be read), other controls become a blank – line feed and tab stay (a
summary's lines; the one-line helpers fold them themselves)."""

import re

_DIRECTION = re.compile("[\u061c\u200e\u200f\u202a-\u202e\u2066-\u2069]")
_CONTROL = re.compile("[\x00-\x08\x0b-\x1f\x7f-\x9f\u2028\u2029]")


def neutral(text: str, control: str = " ") -> str:
    """The text without direction characters, its other control characters (but \\n and \\t) as a blank – a carriage
    return as the line break it stands for. `control=""`: those dropped instead (the forwarding comment, as before)."""
    if not text:
        return ""
    text = str(text).replace("\r\n", "\n").replace("\r", "\n")
    return _CONTROL.sub(control, _DIRECTION.sub("", text))
