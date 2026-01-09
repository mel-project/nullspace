use bytes::Bytes;
use criterion::{Criterion, Throughput, black_box, criterion_group, criterion_main};
use xirtam_crypt::dh::DhSecret;
use xirtam_structs::certificate::{CertificateChain, DeviceSecret};
use xirtam_structs::envelope::{envelope_decrypt, envelope_encrypt};
use xirtam_structs::handle::Handle;
use xirtam_structs::msg_content::MessageContent;
use xirtam_structs::timestamp::Timestamp;

fn envelope_benchmarks(c: &mut Criterion) {
    let receiver_secret = DhSecret::random();
    let receiver_public = receiver_secret.public_key();
    let plaintext = Bytes::from_static(b"benchmark envelope test payload");

    let mut group = c.benchmark_group("envelope");
    group.throughput(Throughput::Elements(1));
    group.bench_function("seal", |b| {
        b.iter(|| {
            let sealed = envelope_encrypt(&receiver_public, plaintext.as_ref());
            black_box(sealed);
        });
    });

    let sealed = envelope_encrypt(&receiver_public, plaintext.as_ref());
    group.bench_function("open", |b| {
        b.iter(|| {
            let opened = envelope_decrypt(&receiver_secret, sealed.as_ref()).expect("open");
            black_box(opened);
        });
    });
    group.finish();
}

fn dm_benchmarks(c: &mut Criterion) {
    let sender_secret = DeviceSecret {
        sign_sk: xirtam_crypt::signing::SigningSecret::random(),
        long_sk: DhSecret::random(),
    };
    let sender_cert = sender_secret.self_signed(Timestamp(u64::MAX), true);
    let sender_chain = CertificateChain(vec![sender_cert]);
    let sender_handle = Handle::parse("@sender01").expect("sender handle");

    let content = MessageContent {
        mime: smol_str::SmolStr::new("text/plain"),
        body: Bytes::from_static(b"benchmark dm payload"),
    };

    let recipient_one_secret = DeviceSecret {
        sign_sk: xirtam_crypt::signing::SigningSecret::random(),
        long_sk: DhSecret::random(),
    };
    let recipient_one_temp = DhSecret::random();
    let recipients_one = vec![(
        recipient_one_secret.public(),
        recipient_one_temp.public_key(),
    )];

    let mut recipients_ten = Vec::with_capacity(10);
    for _ in 0..10 {
        let secret = DeviceSecret {
            sign_sk: xirtam_crypt::signing::SigningSecret::random(),
            long_sk: DhSecret::random(),
        };
        let temp = DhSecret::random();
        recipients_ten.push((secret.public(), temp.public_key()));
    }

    let mut group = c.benchmark_group("dm_encrypt");
    group.throughput(Throughput::Elements(1));
    group.bench_function("encrypt_1_device", |b| {
        b.iter(|| {
            let encrypted = content
                .encrypt(
                    sender_handle.clone(),
                    sender_chain.clone(),
                    &sender_secret,
                    recipients_one.iter().cloned(),
                )
                .expect("encrypt");
            black_box(encrypted);
        });
    });
    group.bench_function("encrypt_10_devices", |b| {
        b.iter(|| {
            let encrypted = content
                .encrypt(
                    sender_handle.clone(),
                    sender_chain.clone(),
                    &sender_secret,
                    recipients_ten.iter().cloned(),
                )
                .expect("encrypt");
            black_box(encrypted);
        });
    });
    group.finish();
}

criterion_group!(benches, envelope_benchmarks, dm_benchmarks);
criterion_main!(benches);
