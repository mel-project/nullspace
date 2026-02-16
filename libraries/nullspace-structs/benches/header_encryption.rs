use bytes::Bytes;
use criterion::{Criterion, Throughput, black_box, criterion_group, criterion_main};
use nullspace_crypt::dh::DhSecret;
use nullspace_structs::Blob;
use nullspace_structs::certificate::DeviceSecret;
use nullspace_structs::e2ee::{DeviceSigned, HeaderEncrypted};
use nullspace_structs::event::Event;
use nullspace_structs::timestamp::NanoTimestamp;
use nullspace_structs::username::UserName;

fn dm_benchmarks(c: &mut Criterion) {
    let sender_secret = DeviceSecret::random();
    let sender_device_pk = sender_secret.public().signing_public();
    let sender_username = UserName::parse("@sender01").expect("sender username");
    let recipient = UserName::parse("@rcpt01").expect("recipient username");

    let content = Event {
        recipient: recipient.into(),
        sent_at: NanoTimestamp(0),
        mime: smol_str::SmolStr::new("text/plain"),
        body: Bytes::from_static(b"benchmark dm payload"),
    };
    let message = Blob {
        kind: Blob::V1_MESSAGE_CONTENT.into(),
        inner: Bytes::from(bcs::to_bytes(&content).expect("content")),
    };

    let recipient_one_medium = DhSecret::random();
    let recipients_one = vec![recipient_one_medium.public_key()];

    let mut recipients_ten = Vec::with_capacity(10);
    for _ in 0..10 {
        let medium = DhSecret::random();
        recipients_ten.push(medium.public_key());
    }

    let mut group = c.benchmark_group("dm_encrypt");
    group.throughput(Throughput::Elements(1));
    group.bench_function("encrypt_1_device", |b| {
        b.iter(|| {
            let signed = DeviceSigned::sign_blob(
                &message,
                sender_username.clone(),
                sender_device_pk,
                &sender_secret,
            )
            .expect("sign");
            let signed_bytes = bcs::to_bytes(&signed).expect("encode signed");
            let encrypted =
                HeaderEncrypted::encrypt_bytes(&signed_bytes, recipients_one.iter().cloned())
                    .expect("encrypt");
            black_box(encrypted);
        });
    });
    group.bench_function("encrypt_10_devices", |b| {
        b.iter(|| {
            let signed = DeviceSigned::sign_blob(
                &message,
                sender_username.clone(),
                sender_device_pk,
                &sender_secret,
            )
            .expect("sign");
            let signed_bytes = bcs::to_bytes(&signed).expect("encode signed");
            let encrypted =
                HeaderEncrypted::encrypt_bytes(&signed_bytes, recipients_ten.iter().cloned())
                    .expect("encrypt");
            black_box(encrypted);
        });
    });
    group.finish();
}

criterion_group!(benches, dm_benchmarks);
criterion_main!(benches);
