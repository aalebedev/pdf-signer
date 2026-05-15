import os

from django.http import JsonResponse, HttpResponse
from django.conf import settings
from django.views.decorators.csrf import csrf_exempt


files_dir = os.path.join(settings.BASE_DIR, 'files')
ui_dir = os.path.join(settings.BASE_DIR, 'ui')

def get_path(filename):
    return os.path.join(files_dir, filename)

def get_path_prepared(filename):
    base_name, ext = os.path.splitext(filename)
    return os.path.join(files_dir, f'{base_name}_prepared{ext}')

def get_path_signed(filename):
    base_name, ext = os.path.splitext(filename)
    return os.path.join(files_dir, f'{base_name}_signed{ext}')


def ui(request):
    path = os.path.join(ui_dir, 'index.html')

    with open(path, 'r') as f:
        content = f.read()

    return HttpResponse(content, content_type='text/html')


def files(request):
    return JsonResponse({
        'files': os.listdir(files_dir),
    })


def get_signature_name(f):
    from pyhanko.pdf_utils.reader import PdfFileReader

    reader = PdfFileReader(f)
    signatures = [sig.field_name for sig in reader.embedded_signatures]

    if not signatures:
        return 1, 'Signature1'

    if signatures == ['Signature1']:
        return 2, 'Signature2'

    raise Exception(f'invalid signatures {signatures}')


@csrf_exempt
def prepare(request):
    from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
    from pyhanko.sign.fields import SigFieldSpec, SigSeedSubFilter
    from pyhanko.sign.signers import cms_embedder, pdf_byterange
    from pyhanko import stamp

    from io import BytesIO
    import re
    import datetime
    import json

    if request.method != 'POST':
        raise Exception('unexpected method')

    data = json.loads(request.body)
    filename = data['file']

    with open(get_path(filename), 'rb') as f:
        number, name = get_signature_name(f)
        f.seek(0)

        w = IncrementalPdfFileWriter(f)

        padding = {1: 0, 2: 300}[number]

        field_spec = SigFieldSpec(
            sig_field_name=name,
            box=(padding + 100, 100, padding + 300, 200),
            on_page=0,
        )

        emb = cms_embedder.PdfCMSEmbedder(field_spec)
        coroutine = emb.write_cms(name, w)

        next(coroutine)
        sig_obj = pdf_byterange.SignatureObject(
            name='test',
            bytes_reserved=16000,
        )

        style = stamp.TextStampStyle()

        coroutine.send(
            cms_embedder.SigObjSetup(
                sig_placeholder=sig_obj,
                appearance_setup=cms_embedder.SigAppearanceSetup(
                    style=style,
                    timestamp=datetime.datetime.now(),
                    text_params={},
                    name=None,
                ),
            )
        )

        prepared_digest, output = coroutine.send(
            cms_embedder.SigIOSetup(md_algorithm='sha256', output=BytesIO())
        )

    content = output.getvalue()

    with open(get_path_prepared(filename), 'wb') as f:
        f.write(content)

    reserved_start, reserved_end = prepared_digest.reserved_region_start, prepared_digest.reserved_region_end
    print('prepared_digest', [reserved_start, reserved_end])

    matches = re.compile(rb"/ByteRange\s*\[\s*(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s*\]").findall(content)
    for match in matches:
        byte_range = [int(item) for item in match]
        print('byte_range', byte_range)

    digest_hex = get_hash(content, reserved_start, reserved_end)

    return JsonResponse({
        'hash': digest_hex.upper(),
        'start': reserved_start,
        'end': reserved_end,
    })


def get_hash(content, reserved_start, reserved_end):
    from gostcrypto import gosthash
    hasher = gosthash.new('streebog256')
    hasher.update(content[:reserved_start] + content[reserved_end:])
    return hasher.hexdigest()


@csrf_exempt
def sign(request):
    import json
    import base64

    if request.method != 'POST':
        raise Exception('unexpected method')

    data = json.loads(request.body)

    signature_base64 = data['signature']
    start = data['start']
    end = data['end']
    filename = data['file']

    cms_der = base64.b64decode(signature_base64)

    # PDF требует hex-string в /Contents
    cms_hex = cms_der.hex().upper().encode('ascii')

    path_prepared = get_path_prepared(filename)
    with open(path_prepared, 'rb') as f:
        pdf_data = f.read()

    reserved_size = end - start
    assert reserved_size > len(cms_hex)

    padded_signature = b"<" + cms_hex.ljust(reserved_size - 2, b"0") + b">"
    assert len(padded_signature) == reserved_size
    signed_pdf_data = pdf_data[:start] + padded_signature + pdf_data[end:]

    with open(get_path_signed(filename), 'wb') as f:
        f.write(signed_pdf_data)

    os.remove(path_prepared)

    return JsonResponse({})
