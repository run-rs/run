use run_packet::ipv4::Ipv4Addr;

pub fn parser_addr(addr:&String) ->Result<(Ipv4Addr,u16),()> {
    let s:Vec<&str>= addr.split(":").into_iter().collect();
    if s.len() != 2 {
      return Err(());
    }
    
    let ipv4_s:Vec<&str> = s[0].split(".").into_iter().collect();
    
    if ipv4_s.len() != 4 {
      return Err(());
    }
  
    let mut ipv4_a:[u8;4] = [0;4];
    for i in 0..4 {
      ipv4_a[i] = u8::from_str_radix(ipv4_s[i], 10).map_err(|e| ())?;
    }
    let ipv4 = Ipv4Addr::from_bytes(&ipv4_a[..]);
    let port = u16::from_str_radix(s[1],10).map_err(|e| ())?;
    return Ok((ipv4,port));
}