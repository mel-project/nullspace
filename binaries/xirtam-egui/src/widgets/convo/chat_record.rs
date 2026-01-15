use bytes::Bytes;
use xirtam_client::internal::{DmMessage, GroupMessage};
use xirtam_structs::handle::Handle;
use xirtam_structs::timestamp::NanoTimestamp;

pub(super) trait ChatRecord {
    fn id(&self) -> i64;
    fn received_at(&self) -> Option<NanoTimestamp>;
    fn sender(&self) -> &Handle;
    fn mime(&self) -> &smol_str::SmolStr;
    fn body(&self) -> &Bytes;
}

impl ChatRecord for DmMessage {
    fn id(&self) -> i64 {
        self.id
    }

    fn received_at(&self) -> Option<NanoTimestamp> {
        self.received_at
    }

    fn sender(&self) -> &Handle {
        &self.sender
    }

    fn mime(&self) -> &smol_str::SmolStr {
        &self.mime
    }

    fn body(&self) -> &Bytes {
        &self.body
    }
}

impl ChatRecord for GroupMessage {
    fn id(&self) -> i64 {
        self.id
    }

    fn received_at(&self) -> Option<NanoTimestamp> {
        self.received_at
    }

    fn sender(&self) -> &Handle {
        &self.sender
    }

    fn mime(&self) -> &smol_str::SmolStr {
        &self.mime
    }

    fn body(&self) -> &Bytes {
        &self.body
    }
}
