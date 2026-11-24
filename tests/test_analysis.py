import json
import numpy as np
import pytest
from PIL import Image
from blink_visual import analyze, analyze_pixels, difference_overlay, heatmap


def sample():
    a = np.zeros((12, 16, 3), dtype=np.uint8)
    b = a.copy()
    b[1:3, 2:5] = 100
    b[7:9, 9:11] = 255
    return a, b


def test_regions():
    a,b = sample()
    r = analyze_pixels(a,b)
    assert r.pixels.changed_pixels == 10
    assert r.total_regions == 2
    assert [x.to_dict() for x in r.regions] == [dict(x=2,y=1,width=3,height=2,changed_pixels=6),dict(x=9,y=7,width=2,height=2,changed_pixels=4)]


def test_diagonal_connectivity():
    a = np.zeros((3,3,3),dtype=np.uint8); b=a.copy()
    b[0,0]=b[1,1]=255
    assert analyze_pixels(a,b).total_regions == 1


def test_filter_independent():
    a,b=sample(); r=analyze_pixels(a,b,min_region_pixels=5)
    assert r.total_regions == 1 and r.pixels.changed_pixels == 10


def test_threshold_independent_ssim():
    a,b=sample(); r=analyze_pixels(a,b); s=analyze_pixels(a,b,threshold=255)
    assert s.ssim == r.ssim and s.total_regions == 0 and s.pixels.changed_pixels == 0


@pytest.mark.parametrize('size',[3,4,5,6,7,12])
def test_identical_ssim(size):
    a=np.zeros((size,size,3),dtype=np.uint8)
    r=analyze_pixels(a,a)
    assert r.ssim == pytest.approx(1) and r.regions == ()


@pytest.mark.parametrize('shape',[(1,1,3),(2,5,3),(5,2,3)])
def test_tiny(shape):
    a=np.zeros(shape,dtype=np.uint8)
    assert analyze_pixels(a,a).ssim is None


@pytest.mark.parametrize('value',[0,-1,True,1.5,'2'])
def test_bad_region_filter(value):
    a,b=sample()
    with pytest.raises(ValueError,match='min_region_pixels'):
        analyze_pixels(a,b,min_region_pixels=value)


def test_cap():
    a=np.zeros((40,40,3),dtype=np.uint8); b=a.copy(); b[::3,::3]=255
    r=analyze_pixels(a,b)
    assert r.total_regions == 196 and len(r.regions)==100 and r.pixels.changed_pixels == 196
    assert (r.regions[0].x,r.regions[0].y)==(0,0)


def test_render():
    a,b=sample(); original=b.copy(); r=analyze_pixels(a,b)
    overlay=np.asarray(difference_overlay(b,r,boxes=False)); heat=np.asarray(heatmap(r))
    assert np.array_equal(b,original)
    assert np.array_equal(overlay[0,0],b[0,0])
    assert tuple(heat[7,9])==(255,82,123)
    assert tuple(heat[0,0])==(0,0,0)
    assert tuple(np.asarray(difference_overlay(b,r))[1,2])==(255,82,123)


def test_heatmap_independent_threshold():
    a,b=sample()
    assert np.array_equal(np.asarray(heatmap(analyze_pixels(a,b))),np.asarray(heatmap(analyze_pixels(a,b,threshold=255))))


def test_bad_overlay():
    a,b=sample()
    with pytest.raises(ValueError):
        difference_overlay(b[:2],analyze_pixels(a,b))


def test_file_and_json(tmp_path):
    a,b=sample(); x=tmp_path/'a.png'; y=tmp_path/'b.png'
    Image.fromarray(a).save(x); Image.fromarray(b).save(y)
    report=json.loads(json.dumps(analyze(x,y).to_dict(),allow_nan=False))
    assert report['changed_pixels']==10 and report['reported_regions']==2
    assert str(tmp_path) not in json.dumps(report)
