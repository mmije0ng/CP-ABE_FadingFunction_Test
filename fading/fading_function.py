import hashlib
import time
import math

def fading_function(attr_base: str, t0: float, delta: float) -> str:
    """
    attr_base: 기본 속성 이름 (예: "subscription_active")
    t0: 기준 시각 (epoch time)
    delta: 갱신 주기 (초 단위)
    """
    current_time = time.time()
    time_slot = math.floor((current_time - t0) / delta)
    fading_input = f"{attr_base}_{time_slot}"
    return hashlib.sha256(fading_input.encode()).hexdigest()

def is_fading_attr_changed(attr_base: str, t0: float, delta: float, old_attr: str) -> bool:
    """
    현재 시간 기준으로 다시 계산한 속성이 이전 속성과 다른지 확인
    """
    new_attr = fading_function(attr_base, t0, delta)
    return new_attr != old_attr
