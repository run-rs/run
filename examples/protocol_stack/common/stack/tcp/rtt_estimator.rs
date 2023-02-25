#[derive(Debug, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct RttEstimator {
  rtt: u32,
  deviation: u32,
  timestamp: Option<(smoltcp::time::Instant, super::seq_number::TcpSeqNumber)>,
  max_seq_sent: Option<super::seq_number::TcpSeqNumber>,
  rto_count: u8,
}

impl Default for RttEstimator {
  fn default() -> Self {
    Self {
      rtt: super::constant::RTTE_INITIAL_RTT,
      deviation: super::constant::RTTE_INITIAL_DEV,
      timestamp: None,
      max_seq_sent: None,
      rto_count: 0,
    }
  }
}

impl RttEstimator {
  pub(crate) fn retransmission_timeout(&self) -> smoltcp::time::Duration {
    let margin = super::constant::RTTE_MIN_MARGIN.max(self.deviation * 4);
    let ms = (self.rtt + margin)
      .max(super::constant::RTTE_MIN_RTO)
      .min(super::constant::RTTE_MAX_RTO);
    smoltcp::time::Duration::from_millis(ms as u64)
  }

  pub(crate) fn sample(&mut self, new_rtt: u32) {
    self.rtt = (self.rtt * 7 + new_rtt + 7) / 8;
    let diff = (self.rtt as i32 - new_rtt as i32).abs() as u32;
    self.deviation = (self.deviation * 3 + diff + 3) / 4;
    self.rto_count = 0;
    let rto = self.retransmission_timeout().millis();
    log::log!(
      log::Level::Trace,
      "rtte: sample={:?} rtt={:?} dev={:?} rto={:?}",
      new_rtt,
      self.rtt,
      self.deviation,
      rto
    );
  }

  pub(crate) fn on_send(
    &mut self,
    ts: smoltcp::time::Instant,
    seq: super::seq_number::TcpSeqNumber,
  ) {
    if self
      .max_seq_sent
      .map(|max_seq_sent| seq > max_seq_sent)
      .unwrap_or(true)
    {
      self.max_seq_sent = Some(seq);
      if self.timestamp.is_none() {
        self.timestamp = Some((ts, seq));
        log::log!(log::Level::Trace, "rtte: sampling at seq={:?}", seq);
      }
    }
  }

  pub(crate) fn on_ack(
    &mut self,
    ts: smoltcp::time::Instant,
    seq: super::seq_number::TcpSeqNumber,
  ) {
    if let Some((sent_ts, sent_seq)) = self.timestamp {
      if seq >= sent_seq {
        self.sample((ts - sent_ts).millis() as u32);
        self.timestamp = None;
      }
    }
  }

  pub(crate) fn on_retransmit(&mut self) {
    if self.timestamp.is_some() {
      log::log!(log::Level::Trace, "rtte: abort sampling due to retransmit");
    }
    self.timestamp = None;
    self.rto_count = self.rto_count.saturating_add(1);
    if self.rto_count >= 3 {
      self.rto_count = 0;
      self.rtt = super::constant::RTTE_MAX_RTO.min(self.rtt * 2);
      let rto = self.retransmission_timeout().millis();
      log::log!(
        log::Level::Trace,
        "rtte: too many retransmissions,increasing: \
         rtt={:?} dev={:?} rto={:?}",
        self.rtt,
        self.deviation,
        rto
      );
    }
  }
}
