#[inline(never)]
fn leaf(value: usize) -> usize {
    value.wrapping_mul(3).wrapping_add(1)
}

#[inline(never)]
fn frame(seed: usize) -> usize {
    let mut values = [0u64; 1024];
    for (index, value) in values.iter_mut().enumerate() {
        unsafe { std::ptr::write_volatile(value, seed.wrapping_add(index) as u64) };
    }
    std::hint::black_box(values[seed & 1023]) as usize ^ leaf(seed)
}

fn main() {
    std::hint::black_box(frame(std::env::args().len()));
}
