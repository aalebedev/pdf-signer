import os

from django.http import JsonResponse, HttpResponse
from django.conf import settings
from django.views.decorators.csrf import csrf_exempt


files_dir = os.path.join(settings.BASE_DIR, 'files')
ui_dir = os.path.join(settings.BASE_DIR, 'ui')

original_path = os.path.join(files_dir, 'test.pdf')
prepared_path = os.path.join(files_dir, 'test_prepared.pdf')
signed_path = os.path.join(files_dir, 'test_signed.pdf')


def ui(request):
    path = os.path.join(ui_dir, 'index.html')

    with open(path, 'r') as f:
        content = f.read()

    return HttpResponse(content, content_type='text/html')


def prepare(request):
    from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
    from pyhanko.sign.fields import SigFieldSpec, SigSeedSubFilter
    from pyhanko.sign.signers import cms_embedder, pdf_byterange
    from pyhanko import stamp

    from io import BytesIO
    import re
    import datetime

    with open(original_path, 'rb') as f:
        name = 'Signature1'

        w = IncrementalPdfFileWriter(f)

        field_spec = SigFieldSpec(
            sig_field_name=name,
            box=(100, 100, 300, 200),
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

    with open(prepared_path, 'wb') as f:
        f.write(content)

    reserved_start, reserved_end = prepared_digest.reserved_region_start, prepared_digest.reserved_region_end
    print('prepared_digest', [reserved_start, reserved_end])

    match = re.compile(rb"/ByteRange\s*\[\s*(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s*\]").search(content)
    byte_range = [int(part) for part in match.groups()]
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

    cms_der = base64.b64decode(signature_base64)

    # PDF требует hex-string в /Contents
    cms_hex = cms_der.hex().upper().encode('ascii')

    with open(prepared_path, 'rb') as f:
        pdf_data = f.read()

    reserved_size = end - start
    assert reserved_size > len(cms_hex)

    padded_signature = b"<" + cms_hex.ljust(reserved_size - 2, b"0") + b">"
    assert len(padded_signature) == reserved_size
    signed_pdf_data = pdf_data[:start] + padded_signature + pdf_data[end:]

    with open(signed_path, 'wb') as f:
        f.write(signed_pdf_data)

    return JsonResponse({})
