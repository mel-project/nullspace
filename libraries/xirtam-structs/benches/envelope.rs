use bytes::Bytes;
use criterion::{Criterion, Throughput, black_box, criterion_group, criterion_main};
use xirtam_structs::envelope::{EnvelopePublic, EnvelopeSecret};
use xirtam_crypt::dh::DhSecret;

fn envelope_benchmarks(c: &mut Criterion) {
    let sender_long_term = DhSecret::random();
    let receiver_long_term = DhSecret::random();
    let receiver_short_term = DhSecret::random();
    let envelope_public = EnvelopePublic {
        long_term: receiver_long_term.public_key(),
        short_term: receiver_short_term.public_key(),
    };
    let envelope_secret = EnvelopeSecret {
        long_term: receiver_long_term,
        short_term: receiver_short_term,
    };
    let plaintext = Bytes::from_static(b"benchmark envelope test payload");

    let mut group = c.benchmark_group("envelope");
    group.throughput(Throughput::Elements(1));
    group.bench_function("seal", |b| {
        b.iter(|| {
            let sealed = envelope_public
                .seal_to(plaintext.clone(), &sender_long_term)
                .expect("seal");
            black_box(sealed);
        });
    });

    let sealed = envelope_public
        .seal_to(plaintext.clone(), &sender_long_term)
        .expect("seal");
    let sender_public = sender_long_term.public_key();
    group.bench_function("open", |b| {
        b.iter(|| {
            let opened = envelope_secret
                .open_from(sealed.clone(), &sender_public)
                .expect("open");
            black_box(opened);
        });
    });
    group.finish();
}

criterion_group!(benches, envelope_benchmarks);
criterion_main!(benches);
