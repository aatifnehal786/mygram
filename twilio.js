const iceServers =  [
  {
    
    urls: 'stun:global.stun.twilio.com:3478'
  },
  {
    credential: 'qnkvVZvs1MIS8Gj8Hmbv5aZDUUahcdClkMjGpKn+XeQ=',
   
    urls: 'turn:global.turn.twilio.com:3478?transport=udp',
    username: '0a195baad521a7d98525a0843d727f13c63fb986e67047c4fc78d162825ee374'
  },
  {
    credential: 'qnkvVZvs1MIS8Gj8Hmbv5aZDUUahcdClkMjGpKn+XeQ=',
    
    urls: 'turn:global.turn.twilio.com:3478?transport=tcp',
    username: '0a195baad521a7d98525a0843d727f13c63fb986e67047c4fc78d162825ee374'
  },
  {
    credential: 'qnkvVZvs1MIS8Gj8Hmbv5aZDUUahcdClkMjGpKn+XeQ=',
    
    urls: 'turn:global.turn.twilio.com:443?transport=tcp',
    username: '0a195baad521a7d98525a0843d727f13c63fb986e67047c4fc78d162825ee374'
  }
]