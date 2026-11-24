"""Blink local visual workspace. Launch with: streamlit run app.py."""
import hashlib
from pathlib import Path

from PIL import Image
import streamlit as st

from blink_visual import analyze_pixels, difference_overlay, heatmap
from blink_visual.workspace import decode_upload, demo_pair, png_bytes, report_bytes, split_image, preview_image

st.set_page_config(page_title='Blink. | See what changed.',
                   page_icon=str(Path(__file__).resolve().parent / 'assets' / 'icon.png'),
                   layout='wide')
st.markdown('''<style>
.block-container {max-width: 1440px; padding-top: 4.75rem; padding-bottom: 2rem;}
.blink-header {display:flex; align-items:center; gap:14px; margin-bottom:0; min-height:58px;}
.blink-header svg {display:block; width:48px; height:48px; flex-shrink:0;}
.blink-brand {font-size: 2.75rem; font-weight: 850; letter-spacing: -0.065em; line-height: 1.1;}
.blink-brand span {color: #c6f65c;}
.blink-kicker {font-size: .72rem; letter-spacing: .13em; color: #a3a7a9; font-weight: 600;}
[data-testid="stMetric"] {border:1px solid #353535; background:#1b1b1b; border-radius:10px; padding:10px 14px;}
[data-testid="stMetricValue"] {font-variant-numeric:tabular-nums;}
</style>''', unsafe_allow_html=True)
brand, source_panel = st.columns([2, 1], gap='large')
with brand:
    st.markdown('''<div class="blink-header">
<svg viewBox="0 0 64 64" aria-hidden="true"><path d="M3 32 Q32 -5 61 32 Q32 69 3 32Z" fill="none" stroke="#f4f4f2" stroke-width="3"/><circle cx="32" cy="32" r="12" fill="#c6f65c"/><path d="M32 4V60" stroke="#141414" stroke-width="3"/></svg>
<div><div class="blink-kicker">VISUAL COMPARISON / LOCAL WORKSPACE</div><div class="blink-brand">blink<span>.</span></div></div></div>''', unsafe_allow_html=True)
    st.caption('See what changed. Compare two images, inspect differences and export evidence.')
with source_panel:
    source = st.radio('Image source', ['Built-in demo', 'Your images'], horizontal=True)
    if source == 'Built-in demo':
        st.caption('Synthetic dashboard · 960 × 540 · No personal data')
if source == 'Built-in demo':
    before, after = demo_pair()
    pair_key = 'demo'
else:
    left, right = st.columns(2)
    with left:
        first = st.file_uploader('01 / Original image', type=['png','jpg','jpeg'], key='before')
    with right:
        second = st.file_uploader('02 / Modified image', type=['png','jpg','jpeg'], key='after')
    if first is None or second is None:
        st.session_state.pop('analysis_cache', None)
        st.info('Choose two equal-sized, opaque RGB or grayscale PNG/JPEG images to begin.')
        st.stop()
    try:
        a, b = first.getvalue(), second.getvalue()
        before, after = decode_upload(a), decode_upload(b)
        pair_key = (hashlib.sha256(a).hexdigest(), hashlib.sha256(b).hexdigest())
    except (ValueError, OSError, Image.DecompressionBombError) as exc:
        st.session_state.pop('analysis_cache', None)
        st.error(f'Could not open image: {exc}')
        st.stop()
if before.shape != after.shape:
    st.session_state.pop('analysis_cache', None)
    st.error(f'Image dimensions must match. Original: {before.shape[1]} × {before.shape[0]}; modified: {after.shape[1]} × {after.shape[0]}. Blink never resizes inputs.')
    st.stop()

controls, canvas = st.columns([1, 3], gap='large')
with controls:
    st.subheader('Controls')
    threshold = st.slider('Difference threshold', 0, 255, 15, help='A pixel changes when its largest RGB channel difference exceeds this value.')
    min_area = st.number_input('Minimum region pixels', min_value=1, max_value=10000, value=1, step=1, help='Filters the region list only, not the overall changed-pixel count.')
    show_boxes = st.checkbox('Show region bounds', value=True)
    st.caption('Lower threshold = higher sensitivity. SSIM and heatmaps are independent of the threshold.')
    st.caption('Minimum region size filters the region list, not pixel statistics.')
    st.divider()
    st.caption('ENGINE / NumPy · SciPy · scikit-image')
    st.caption('Images are decoded in this local process. No external image uploads.')

def show_preview(image):
    # Limit the display width only; never resize scientific evidence.
    preview = preview_image(image)
    st.image(preview, width=min(preview.width, 800))


key = (pair_key, threshold, min_area)
cached = st.session_state.get('analysis_cache')
if cached is None or cached[0] != key:
    result = analyze_pixels(before, after, threshold=threshold, min_region_pixels=min_area)
    st.session_state['analysis_cache'] = (key, result)
else:
    result = cached[1]
p = result.pixels
with canvas:
    st.subheader('Comparison')
    a, b, c = st.columns(3)
    a.metric('Changed pixels', f'{p.changed_percentage:.3f}%')
    b.metric('SSIM', 'N/A' if result.ssim is None else f'{result.ssim:.4f}')
    c.metric('Regions', result.total_regions)
    st.caption(f'{p.width} × {p.height} px  ·  {p.changed_pixels:,} / {p.total_pixels:,} changed  ·  Threshold {threshold}')
    overlay = difference_overlay(after, result, boxes=show_boxes)
    heat = heatmap(result)
    mode = st.radio('Comparison mode', ['Difference', 'Split', 'Blink', 'Heatmap', 'Side by side'], horizontal=True)
    if mode == 'Difference':
        show_preview(overlay)
        st.caption('Pink = threshold-exceeding pixels. Outlines show qualifying region bounds.')
    elif mode == 'Split':
        position = st.slider('Split position', 0, 100, 50)
        show_preview(split_image(before, after, position))
        st.caption('Original on the left · Modified on the right')
    elif mode == 'Blink':
        original = st.toggle('Show original (switch to compare)', value=False)
        show_preview(before if original else after)
        st.caption('Showing original' if original else 'Showing modified')
    elif mode == 'Heatmap':
        show_preview(heat)
        st.caption('Black = zero difference · Bright pink = maximum channel difference (255).')
    else:
        l, r = st.columns(2)
        l.image(preview_image(before), caption='Original', width='content')
        r.image(preview_image(after), caption='Modified', width='content')
    st.subheader('Export evidence')
    x, y, z = st.columns(3)
    x.download_button('Overlay PNG', png_bytes(overlay), 'blink-overlay.png', 'image/png', width='stretch')
    y.download_button('Heatmap PNG', png_bytes(heat), 'blink-heatmap.png', 'image/png', width='stretch')
    z.download_button('JSON report', report_bytes(result), 'blink-report.json', 'application/json', width='stretch')
    with st.expander(f'Detected regions ({result.total_regions})', expanded=False):
        if result.regions:
            rows = [{'Region': i, 'X': r.x, 'Y': r.y, 'Width': r.width, 'Height': r.height, 'Changed pixels': r.changed_pixels} for i, r in enumerate(result.regions, 1)]
            st.dataframe(rows, hide_index=True, width='stretch')
            st.caption(f'Showing {len(rows)} of {result.total_regions} qualifying regions (largest first; maximum 100). Coordinates start at the upper-left.')
        else:
            st.caption('No regions meet the current threshold and minimum region size.')
