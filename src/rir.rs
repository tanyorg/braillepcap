// Map the first IPv4 octet to the corresponding Regional Internet Registry (RIR)
pub fn get_iana_rir(octet1: u8) -> &'static str {
    match octet1 {
        0 => "Local",
        10 => "Private",
        127 => "Loopback",
        224..=239 => "Multicast",
        240..=255 => "Reserved",
        1 | 14 | 27 | 36 | 39 | 42 | 43 | 49 | 58..=61 
        | 101 | 103 | 106 | 110..=126 | 133 | 150 | 153 | 163 
        | 171 | 175 | 180 | 182 | 183 | 202 | 203 | 210 | 211 
        | 218..=223 => "APNIC",
        2 | 5 | 25 | 31 | 37 | 46 | 51 | 53 | 57 | 62 
        | 77..=95 | 109 | 141 | 145 | 151 | 176 | 178 | 185 
        | 188 | 193..=195 | 212 | 213 | 217 => "RIPE NCC",
        41 | 102 | 105 | 154 | 196 | 197 => "AFRINIC",
        177 | 179 | 181 | 186 | 187 | 189..=191 | 200 | 201 => "LACNIC",
        _ => "ARIN",
    }
}
