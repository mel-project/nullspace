use bytes::Bytes;
use criterion::{Criterion, Throughput, black_box, criterion_group, criterion_main};
use xirtam_crypt::dh::DhSecret;
use xirtam_structs::Blob;
use xirtam_structs::certificate::{CertificateChain, DeviceSecret};
use xirtam_structs::envelope::Envelope;
use xirtam_structs::username::UserName;
use xirtam_structs::msg_content::MessageContent;
use xirtam_structs::timestamp::{NanoTimestamp, Timestamp};

fn dm_benchmarks(c: &mut Criterion) {
    let sender_secret = DeviceSecret::random();
    let sender_cert = sender_secret.self_signed(Timestamp(u64::MAX), true);
    let sender_chain = CertificateChain {
        ancestors: Vec::new(),
        this: sender_cert,
    };
    let sender_username = UserName::parse("@sender01").expect("sender username");
    let recipient = UserName::parse("@rcpt01").expect("recipient username");

    let content = MessageContent {
        recipient,
        sent_at: NanoTimestamp(0),
        mime: smol_str::SmolStr::new("text/plain"),
        body: Bytes::from_static(b"benchmark dm payload"),
    };
    let message = Blob {
        kind: Blob::V1_MESSAGE_CONTENT.into(),
        inner: Bytes::from(bcs::to_bytes(&content).expect("content")),
    };

    let recipient_one_secret = DeviceSecret::random();
    let recipient_one_medium = DhSecret::random();
    let recipients_one = vec![(
        recipient_one_secret.public(),
        recipient_one_medium.public_key(),
    )];

    let mut recipients_ten = Vec::with_capacity(10);
    for _ in 0..10 {
        let secret = DeviceSecret::random();
        let medium = DhSecret::random();
        recipients_ten.push((secret.public(), medium.public_key()));
    }

    let mut group = c.benchmark_group("dm_encrypt");
    group.throughput(Throughput::Elements(1));
    group.bench_function("encrypt_1_device", |b| {
        b.iter(|| {
            let encrypted = Envelope::encrypt_message(
                &message,
                sender_username.clone(),
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
            let encrypted = Envelope::encrypt_message(
                &message,
                sender_username.clone(),
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

criterion_group!(benches, dm_benchmarks);
criterion_main!(benches);
