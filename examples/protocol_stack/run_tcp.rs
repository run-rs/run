mod common;

use clap::Parser;

#[derive(Parser)]
struct Flags {
  #[clap(long = "rx_buf_size",default_value_t = 8192)]
  pub rx_buffer:u32,
  #[clap(long = "tx_buf_size",default_value_t = 8192)]
  pub tx_buffer:u32,
  #[clap(long = "bind", required = true)]
  pub bind:String,
  #[clap(long = "connect")]
  pub connect:Option<String>,
  #[clap(long = "mac",required = true)]
  pub mac:String
}

fn server_start(args:&Flags) {
  /* let mut stack = TcpStack::new();
  let (ipv4,port) = parser_addr(&args.bind).unwrap();
  let mut socket = stack.create_socket();
  socket.bind(ipv4,port);
  socket.listen();

  let device = DpdkDeviceHelper::build(0).unwrap();
  let mut iface = Interface::new(device,stack);

  let run = Arc::new(std::sync::atomic::AtomicBool::new(true));
  let run_clone = run.clone();

  let total_sent_bytes = Arc::new(std::sync::atomic::AtomicU64::new(0));
  let total_sent_bytes_clone = total_sent_bytes.clone();
  
  let jh = std::thread::spawn(move || {
    let mut old_total_sent_bytes = 0;
    let mut stats_total_secs = 20;
    //wait for connecting
    std::thread::sleep(std::time::Duration::from_secs(1));

    while stats_total_secs > 0 {
      std::thread::sleep(std::time::Duration::from_secs(1));
      println!(
        "bytes per sec: {}",
        (total_sent_bytes_clone.load(std::sync::atomic::Ordering::Relaxed) - 
          old_total_sent_bytes) as f64 * 8.0 / 1000000000.0
      );
      old_total_sent_bytes = total_sent_bytes_clone.load(std::sync::atomic::Ordering::Relaxed);
      stats_total_secs -= 1;
    }
    run_clone.store(false,std::sync::atomic::Ordering::Relaxed);
  });

  while run.load(std::sync::atomic::Ordering::Relaxed) {
    iface.poll();

    if socket.can_send() {
      let sent_bytes = socket.send();
      total_sent_bytes.fetch_add(sent_bytes,std::sync::atomic::Ordering::Relaxed);
    }
  }

  jh.join(); */
}

fn client_start(args:&Flags) {
  /* let mut stack = TcpStack::new();
  let (ipv4,port) = parser_addr(&args.bind).unwrap();
  let mut socket = stack.create_socket();
  socket.bind(ipv4,port);
  let (ipv4,port) = parser_addr(args.connect.as_ref().unwrap()).unwrap();
  socket.connect(ipv4,port);

  let device = DpdkDeviceHelper::build(0).unwrap();
  let mut iface = Interface::new(device,stack);

  let run = Arc::new(std::sync::atomic::AtomicBool::new(true));
  let run_clone = run.clone();

  let total_recv_bytes = Arc::new(std::sync::atomic::AtomicU64::new(0));
  let total_recv_bytes_clone = total_recv_bytes.clone();
  
  let jh = std::thread::spawn(move || {
    let mut old_total_sent_bytes = 0;
    let mut stats_total_secs = 20;
    //wait for connecting
    std::thread::sleep(std::time::Duration::from_secs(1));

    while stats_total_secs > 0 {
      std::thread::sleep(std::time::Duration::from_secs(1));
      println!(
        "bytes per sec: {}",
        (total_recv_bytes_clone.load(std::sync::atomic::Ordering::Relaxed) - 
          old_total_sent_bytes) as f64 * 8.0 / 1000000000.0
      );
      old_total_sent_bytes = total_recv_bytes_clone.load(std::sync::atomic::Ordering::Relaxed);
      stats_total_secs -= 1;
    }
    run_clone.store(false,std::sync::atomic::Ordering::Relaxed);
  });

  while run.load(std::sync::atomic::Ordering::Relaxed) {
    iface.poll();

    if socket.can_recv() {
      let sent_bytes = socket.recv();
      total_recv_bytes.fetch_add(sent_bytes,std::sync::atomic::Ordering::Relaxed);
    }
  }

  jh.join(); */
}

fn main() {
  let args = Flags::parse();
  if args.connect.is_none() {
    server_start(&args);
  } else {
    client_start(&args);
  }
}