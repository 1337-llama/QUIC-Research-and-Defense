##! Lab tuning for quic-hunting.zeek: short runs and a known-good "CDN".

redef QUICHunt::long_threshold = 3 min;
redef QUICHunt::approved_nets += { 172.28.0.20/32 };
