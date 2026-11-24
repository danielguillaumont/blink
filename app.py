"""Blink local visual workspace. Launch with: streamlit run app.py."""
import hashlib

from PIL import Image
import streamlit as st

from blink_visual import analyze_pixels, difference_overlay, heatmap
from blink_visual.workspace import decode_upload, demo_pair, png_bytes, report_bytes, split_image

st.set_page_config(page_title='Blink. | See what changed.', page_icon='👁', layout='wide')
st.markdown('''<style>
.block-container {max-width: 1280px; padding-top: 2.5rem; padding-bottom: 3rem;}
.blink-brand {font-size: 3.25rem; font-weight: 850; letter-spacing: -0.07em; line-height: 1.05;}
.blink-brand span {color: #c6f65c;}
.blink-kicker {font-size: .75rem; letter-spacing: .17em; color: #a3a7a9; font-weight: 600;}
</style><div class="blink-kicker">VISUAL COMPARISON / LOCAL WORKSPACE</div>
<div class="blink-brand">blink<span>.</span></div>''', unsafe_allow_html=True)
st.caption('See what changed. Compare two images, inspect differences and export evidence.')

source = st.radio('Image source', ['Built-in demo', 'Your images'], horizontal=True)
if source == 'Built-in demo':
    before, after = demo_pair()
    pair_key = 'demo'
    st.caption('DEMO / Synthetic dashboard · 960 × 540 · No personal data')
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
    st.divider()
    st.caption('ENGINE / NumPy · SciPy · scikit-image')
    st.caption('Images are decoded in this local process. No external image uploads.')

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
    mode = st.radio('Comparison mode', ['Difference', 'Split', 'Blink', 'Heatmap', 'Side by side'], horizontal=True)
    if mode == 'Difference':
        st.image(difference_overlay(after, result, boxes=show_boxes), width='stretch')
        st.caption('Pink = threshold-exceeding pixels. Outlines show qualifying region bounds.')
    elif mode == 'Split':
        position = st.slider('Split position', 0, 100, 50)
        st.image(split_image(before, after, position), width='stretch')
        st.caption('Original on the left · Modified on the right')
    elif mode == 'Blink':
        original = st.toggle('Show original (switch to compare)', value=False)
        st.image(before if original else after, width='stretch')
        st.caption('Showing original' if original else 'Showing modified')
    elif mode == 'Heatmap':
        st.image(heatmap(result), width='stretch')
        st.caption('Black = zero difference · Bright pink = maximum channel difference (255).')
    else:
        l, r = st.columns(2)
        l.image(before, caption='Original', width='stretch')
        r.image(after, caption='Modified', width='stretch')
    st.divider()
    st.subheader('Detected regions')
    if result.regions:
        rows = [{'Region': i, 'X': r.x, 'Y': r.y, 'Width': r.width, 'Height': r.height, 'Changed pixels': r.changed_pixels} for i, r in enumerate(result.regions, 1)]
        st.dataframe(rows, hide_index=True, width='stretch')
        st.caption(f'Showing {len(rows)} of {result.total_regions} qualifying regions (largest first; maximum 100). Coordinates start at the upper-left.')
    else:
        st.info('No regions meet the current threshold and minimum region size.')
    st.subheader('Export evidence')
    x, y, z = st.columns(3)
    x.download_button('Overlay PNG', png_bytes(difference_overlay(after, result, boxes=show_boxes)), 'blink-overlay.png', 'image/png')
    y.download_button('Heatmap PNG', png_bytes(heatmap(result)), 'blink-heatmap.png', 'image/png')
    z.download_button('JSON report', report_bytes(result), 'blink-report.json', 'application/json')
