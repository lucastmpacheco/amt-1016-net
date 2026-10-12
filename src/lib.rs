//! Protocolo ISECNet V1 da central Intelbras AMT 1016 NET.
//!
//! Framing e checksum CONFIRMADOS em 9/9 frames reais capturados (2026-10-12,
//! proxy TCP na LAN <-> central). Formato de comando V1 e offsets
//! de status derivados do projeto aberto bobaoapae/guardian-api-intelbras
//! (ver ../referencias/isecnet_protocol.py) e da captura.
//!
//! Frame V1 de comando: [size][0xE9][!][senha ascii][comando...][!][chk]
//!   size = len(comando) + len(senha) + 3        (0xE9, '!', '!')
//!   chk  = 0xFF XOR (XOR de todos os bytes anteriores)   <- confirmado
//! Resposta: [size][dados...][chk], mesmo checksum.

/// Checksum ISECNet: 0xFF XOR (XOR de todos os bytes). Confirmado nos frames reais.
pub fn checksum(bytes: &[u8]) -> u8 {
    bytes.iter().fold(0u8, |a, &b| a ^ b) ^ 0xFF
}

// --- constantes do protocolo V1 ---
pub const ISEC_PROGRAM: u8 = 0xE9;
pub const DELIM: u8 = 0x21; // '!'

pub const GET_PARTIAL_STATUS: u8 = 0x5A;
pub const GET_COMPLETE_STATUS: u8 = 0x53;
pub const ACTIVATE: u8 = 0x41; // 'A' (armar)
pub const DEACTIVATE: u8 = 0x44; // 'D' (desarmar)
pub const SIREN_OFF: u8 = 0x4F; // 'O'
pub const PANIC: u8 = 0x45; // 'E'
pub const PGM: u8 = 0x47; // 'G'
pub const STAY: u8 = 0x50; // 'P' (modo parcial/stay)

/// Codificacao da senha no frame V1.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Enc { Ascii, Digitos, Bcd }

/// Codifica a senha conforme `enc`:
/// - Ascii:   '2'->0x32 ... (1 byte por digito)
/// - Digitos: '2'->0x02 ... (1 byte por digito, valor 0-9)
/// - Bcd:     "2425" -> 0x24 0x25 (2 digitos por byte; impar completa com 0)
pub fn encode_senha(senha: &str, enc: Enc) -> Vec<u8> {
    let ds: Vec<u8> = senha.bytes().filter(|b| b.is_ascii_digit()).map(|b| b - b'0').collect();
    match enc {
        Enc::Ascii => ds.iter().map(|d| d + b'0').collect(),
        Enc::Digitos => ds,
        Enc::Bcd => ds.chunks(2).map(|c| (c[0] << 4) | *c.get(1).unwrap_or(&0)).collect(),
    }
}

/// Monta um comando V1 pronto pra enviar, com a senha ja codificada em bytes.
pub fn build_v1(command: &[u8], pwd: &[u8]) -> Vec<u8> {
    let size = command.len() + pwd.len() + 3;
    let mut p = Vec::with_capacity(size + 2);
    p.push(size as u8);
    p.push(ISEC_PROGRAM);
    p.push(DELIM);
    p.extend_from_slice(pwd);
    p.extend_from_slice(command);
    p.push(DELIM);
    let c = checksum(&p);
    p.push(c);
    p
}

// --- builders de comando (payload interno; use com build_v1) ---
pub fn cmd_status() -> Vec<u8> { vec![GET_PARTIAL_STATUS] }
pub fn cmd_status_completo() -> Vec<u8> { vec![GET_COMPLETE_STATUS] }

/// Armar. `particao`: None = todas; Some(0..=3) = A..D. `stay` = modo parcial.
pub fn cmd_arm(particao: Option<u8>, stay: bool) -> Vec<u8> {
    let mut c = vec![ACTIVATE];
    if let Some(p) = particao { c.push(ACTIVATE + p); } // A..D = 0x41+idx
    if stay { c.push(STAY); }
    c
}
/// Desarmar. `particao`: None = todas; Some(0..=3) = A..D.
pub fn cmd_disarm(particao: Option<u8>) -> Vec<u8> {
    let mut c = vec![DEACTIVATE];
    if let Some(p) = particao { c.push(ACTIVATE + p); }
    c
}
pub fn cmd_siren_off() -> Vec<u8> { vec![SIREN_OFF] }
pub fn cmd_panic(tipo: u8) -> Vec<u8> { vec![PANIC, tipo] }
pub fn cmd_pgm(index: u8, on: bool) -> Vec<u8> { vec![PGM, index, on as u8] }

/// Valida e extrai os dados de uma resposta V1 ([size][dados][chk]).
pub fn parse_response(resp: &[u8]) -> Result<Vec<u8>, String> {
    if resp.len() < 2 {
        return Err(format!("resposta curta: {} bytes", resp.len()));
    }
    let size = resp[0] as usize;
    if resp.len() < size + 2 {
        return Err(format!("esperado {} bytes, veio {}", size + 2, resp.len()));
    }
    let calc = checksum(&resp[..size + 1]);
    let got = resp[size + 1];
    if calc != got {
        return Err(format!("checksum invalido: calc {:02x} != recebido {:02x}", calc, got));
    }
    Ok(resp[1..size + 1].to_vec())
}

#[derive(Debug, Default)]
pub struct Status {
    pub model_code: u8,
    pub firmware: u8,
    pub multi_particao: bool,
    pub particao_bits: u8,
    pub armado: bool,
    pub bateria: u8,
    pub raw: Vec<u8>,
}

/// Decodifica o status parcial V1 (resposta ~46 bytes). Offsets do APK,
/// sobre `data` = parse_response(resp) (ja sem size/chk).
/// data[0]=0xE9 echo, data[1]=codigo (0x00 ok), data[19]=modelo, data[20]=firmware,
/// data[21]=multi-particao, data[22]=bits de particao armada, data[31]=bateria.
pub fn parse_status(data: &[u8]) -> Result<Status, String> {
    if data.len() < 40 {
        return Err(format!("status curto p/ parse parcial: {} bytes", data.len()));
    }
    let mut s = Status { raw: data.to_vec(), ..Default::default() };
    s.model_code = data[19];
    s.firmware = data[20];
    s.multi_particao = data[21] != 0;
    s.particao_bits = data[22];
    s.armado = data[22] != 0; // qualquer particao armada
    s.bateria = data[31];
    Ok(s)
}

// --- modo e7 (replay da sessao capturada: connect/auth/status) ---

#[derive(Debug, Default)]
pub struct StatusE7 {
    pub armado: bool,
    pub disparo_memoria: bool,
    pub ana1: u8,
    pub ana2: u8,
    pub raw: Vec<u8>,
}

/// Decodifica a resposta de status de 32B do protocolo e7 (o que o app usa).
/// armado: byte19 bit0x08 (ou byte6 != 0); disparo-na-memoria: byte14 bit0x40.
pub fn parse_status_e7(f: &[u8]) -> Result<StatusE7, String> {
    if f.len() < 24 || f.get(1) != Some(&0xE7) {
        return Err(format!("nao parece status e7 (len {})", f.len()));
    }
    Ok(StatusE7 {
        armado: (f[19] & 0x08) != 0 || f[6] != 0,
        disparo_memoria: (f[14] & 0x40) != 0,
        ana1: f[21],
        ana2: f[23],
        raw: f.to_vec(),
    })
}

/// Extrai os frames C>S (bytes) de um log do relay_log.py, em ordem.
pub fn frames_cs_do_log(texto: &str) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    for linha in texto.lines() {
        // formato: HH:MM:SS.mmm  C>S   LEN  hh hh ..  | ascii
        let Some(pos) = linha.find("C>S") else { continue };
        let resto = &linha[pos + 3..];
        let Some(barra) = resto.find('|') else { continue };
        let campo = &resto[..barra];
        let toks: Vec<&str> = campo.split_whitespace().collect();
        // toks[0] = LEN (decimal do relay); os seguintes = hex do frame
        let bytes: Vec<u8> = toks.iter().skip(1)
            .filter_map(|t| u8::from_str_radix(t, 16).ok())
            .collect();
        if bytes.len() >= 3 {
            out.push(bytes);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hx(s: &str) -> Vec<u8> {
        s.split_whitespace().map(|x| u8::from_str_radix(x, 16).unwrap()).collect()
    }

    // Frames reais capturados (sessao 0xe7). O checksum tem que bater em TODOS.
    const REAIS: &[&str] = &[
        "05 e7 01 17 86 71 fc",
        "05 e7 01 14 86 7b f5",
        "06 e7 02 19 10 d6 4b 88",
        "1e e7 1a 97 61 43 00 00 00 00 00 00 00 00 36 00 00 00 00 55 03 d0 03 cf 0c 2d 0c 0a 1a 8e c6 a0",
        "1e e7 1a 97 61 43 03 00 00 00 00 00 00 00 36 00 00 00 00 5d 03 d4 03 cc 0c 2d 0c 0a 1a fc dd c5",
        "14 e7 10 94 00 00 00 00 00 00 00 00 04 00 00 00 00 00 00 9e 71 63",
        "06 e7 02 99 00 d6 21 72",
    ];

    #[test]
    fn checksum_bate_nos_frames_reais() {
        for f in REAIS {
            let b = hx(f);
            let (body, chk) = b.split_at(b.len() - 1);
            assert_eq!(checksum(body), chk[0], "falhou no frame: {f}");
        }
    }

    #[test]
    fn build_v1_estrutura_e_size() {
        let pkt = build_v1(&cmd_status(), b"123456");
        assert_eq!(pkt[0] as usize, pkt.len() - 2, "size = total - 2");
        assert_eq!(pkt[1], ISEC_PROGRAM);
        assert_eq!(pkt[2], DELIM);
        assert_eq!(*pkt.last().unwrap(), checksum(&pkt[..pkt.len() - 1]));
    }

    #[test]
    fn round_trip_resposta() {
        // monta uma resposta sintetica valida e parseia de volta
        let data = [0xE9u8, 0x00, 1, 2, 3];
        let mut resp = vec![data.len() as u8];
        resp.extend_from_slice(&data);
        resp.push(checksum(&resp));
        assert_eq!(parse_response(&resp).unwrap(), data);
    }

    #[test]
    fn checksum_rejeita_corrompido() {
        let mut resp = vec![2u8, 0xE9, 0x00];
        resp.push(checksum(&resp));
        let n = resp.len();
        resp[n - 1] ^= 0xFF; // corrompe o checksum
        assert!(parse_response(&resp).is_err());
    }

    #[test]
    fn encoding_senha() {
        assert_eq!(encode_senha("123456", Enc::Ascii), b"123456".to_vec());
        assert_eq!(encode_senha("123456", Enc::Digitos), vec![1, 2, 3, 4, 5, 6]);
        assert_eq!(encode_senha("123456", Enc::Bcd), vec![0x12, 0x34, 0x56]);
    }

    #[test]
    fn arm_disarm_bytes() {
        assert_eq!(cmd_arm(None, false), vec![0x41]);
        assert_eq!(cmd_arm(Some(1), false), vec![0x41, 0x42]); // particao B
        assert_eq!(cmd_arm(None, true), vec![0x41, 0x50]); // stay
        assert_eq!(cmd_disarm(Some(3)), vec![0x44, 0x44]); // particao D
    }
}

// --- protocolo e7 (sessao local do AMT Remoto) — CRC decifrado do APK Amt2k ---
// Tabela e algoritmo extraidos de Amt2k.Protocol.DotnetStandard.Crc (dnfile/dncil).
static CRC_TBL: [u16; 257] = [
    0x0000, 0x0580, 0x0f80, 0x0a00, 0x1b80, 0x1e00, 0x1400, 0x1180, 0x3380, 0x3600, 0x3c00, 0x3980,
    0x2800, 0x2d80, 0x2780, 0x2200, 0x6380, 0x6600, 0x6c00, 0x6980, 0x7800, 0x7d80, 0x7780, 0x7200,
    0x5000, 0x5580, 0x5f80, 0x5a00, 0x4b80, 0x4e00, 0x4400, 0x4180, 0xc380, 0xc600, 0xcc00, 0xc980,
    0xd800, 0xdd80, 0xd780, 0xd200, 0xf000, 0xf580, 0xff80, 0xfa00, 0xeb80, 0xee00, 0xe400, 0xe180,
    0xa000, 0xa580, 0xaf80, 0xaa00, 0xbb80, 0xbe00, 0xb400, 0xb180, 0x9380, 0x9600, 0x9c00, 0x9980,
    0x8800, 0x8d80, 0x8780, 0x8200, 0x8381, 0x8601, 0x8c01, 0x8981, 0x9801, 0x9d81, 0x9781, 0x9201,
    0xb001, 0xb581, 0xbf81, 0xba01, 0xab81, 0xae01, 0xa401, 0xa181, 0xe001, 0xe581, 0xef81, 0xea01,
    0xfb81, 0xfe01, 0xf401, 0xf181, 0xd381, 0xd601, 0xdc01, 0xd981, 0xc801, 0xcd81, 0xc781, 0xc201,
    0x4001, 0x4581, 0x4f81, 0x4a01, 0x5b81, 0x5e01, 0x5401, 0x5181, 0x7381, 0x7601, 0x7c01, 0x7981,
    0x6801, 0x6d81, 0x6781, 0x6201, 0x2381, 0x2601, 0x2c01, 0x2981, 0x3801, 0x3d81, 0x3781, 0x3201,
    0x1001, 0x1581, 0x1f81, 0x1a01, 0x0b81, 0x0e01, 0x0401, 0x0181, 0x0383, 0x0603, 0x0c03, 0x0983,
    0x1803, 0x1d83, 0x1783, 0x1203, 0x3003, 0x3583, 0x3f83, 0x3a03, 0x2b83, 0x2e03, 0x2403, 0x2183,
    0x6003, 0x6583, 0x6f83, 0x6a03, 0x7b83, 0x7e03, 0x7403, 0x7183, 0x5383, 0x5603, 0x5c03, 0x5983,
    0x4803, 0x4d83, 0x4783, 0x4203, 0xc003, 0xc583, 0xcf83, 0xca03, 0xdb83, 0xde03, 0xd403, 0xd183,
    0xf383, 0xf603, 0xfc03, 0xf983, 0xe803, 0xed83, 0xe783, 0xe203, 0xa383, 0xa603, 0xac03, 0xa983,
    0xb803, 0xbd83, 0xb783, 0xb203, 0x9003, 0x9583, 0x9f83, 0x9a03, 0x8b83, 0x8e03, 0x8403, 0x8183,
    0x8002, 0x8582, 0x8f82, 0x8a02, 0x9b82, 0x9e02, 0x9402, 0x9182, 0xb382, 0xb602, 0xbc02, 0xb982,
    0xa802, 0xad82, 0xa782, 0xa202, 0xe382, 0xe602, 0xec02, 0xe982, 0xf802, 0xfd82, 0xf782, 0xf202,
    0xd002, 0xd582, 0xdf82, 0xda02, 0xcb82, 0xce02, 0xc402, 0xc182, 0x4382, 0x4602, 0x4c02, 0x4982,
    0x5802, 0x5d82, 0x5782, 0x5202, 0x7002, 0x7582, 0x7f82, 0x7a02, 0x6b82, 0x6e02, 0x6402, 0x6182,
    0x2002, 0x2582, 0x2f82, 0x2a02, 0x3b82, 0x3e02, 0x3402, 0x3182, 0x1382, 0x1602, 0x1c02, 0x1982,
    0x0802, 0x0d82, 0x0782, 0x0202, 0x0001,
];

/// CRC16 da familia AMT: reflexivo, init 0, tabela propria.  c = (c>>8) ^ tbl[(c^b)&0xff]
pub fn crc16_e7(data: &[u8]) -> u16 {
    let mut c: u16 = 0;
    for &b in data {
        c = (c >> 8) ^ CRC_TBL[((c as u8) ^ b) as usize];
    }
    c
}

/// Monta frame e7: [LEN][0xE7][tipo][dados][CRC16 LE][CHK=0xFF^XOR].
pub fn build_e7(tipo: u8, cmd: &[u8]) -> Vec<u8> {
    let mut payload = vec![tipo];
    payload.extend_from_slice(cmd);
    let c = crc16_e7(&payload);
    let mut body = vec![0xE7u8];
    body.extend_from_slice(&payload);
    body.push((c & 0xFF) as u8);
    body.push((c >> 8) as u8);
    let mut frame = vec![body.len() as u8];
    frame.extend_from_slice(&body);
    frame.push(checksum(&frame));
    frame
}

// comandos e7 — DADOS confirmados do codigo-fonte (Amt2k.Core)
/// Armar. particao: None/Some(0)=A ... Some(3)=D (indice).
pub fn e7_armar(particao: Option<u8>) -> Vec<u8> { build_e7(0x02, &[0x16, particao.unwrap_or(0)]) }
/// Desarmar / desabilitar alarme.
pub fn e7_desarmar() -> Vec<u8> { build_e7(0x02, &[0x19, 0x40]) }
/// Status (poll).
pub fn e7_status_poll() -> Vec<u8> { build_e7(0x01, &[0x17]) }

#[cfg(test)]
mod tests_e7 {
    use super::*;
    fn hx(s:&str)->Vec<u8>{ s.split_whitespace().map(|x|u8::from_str_radix(x,16).unwrap()).collect() }
    #[test]
    fn e7_reproduz_frames_reais() {
        // sintese tem que bater byte a byte com os frames capturados
        assert_eq!(e7_desarmar(),            hx("06 e7 02 19 40 d7 ab 39"));
        assert_eq!(e7_armar(Some(0)),        hx("06 e7 02 16 00 74 28 56"));
        assert_eq!(e7_status_poll(),         hx("05 e7 01 17 86 71 fc"));
        // CRC isolado
        assert_eq!(crc16_e7(&[0x02,0x19,0x40]), 0xabd7);
    }
}

// --- autenticacao e7 (identify) — decifrada do app (SendIdentify + GetPartsInBytes) ---

/// Converte a senha em bytes parseando 2 caracteres por vez como HEX
/// (equivalente ao GetPartsInBytes do app: ToByte(senha[i..i+2], base16)).
pub fn senha_em_bytes(senha: &str) -> Vec<u8> {
    let b = senha.as_bytes();
    (0..b.len()).step_by(2)
        .filter_map(|i| std::str::from_utf8(&b[i..(i+2).min(b.len())]).ok())
        .filter_map(|s| u8::from_str_radix(s, 16).ok())
        .collect()
}

/// Frame de autenticacao (identify): e7 TIPO=0x05, DADOS = [0x11] + senha_bytes + [0x34].
/// Sem replay, sem nonce — a auth e so a senha. Connect e `01 c4` / `01 c2` (sem segredo).
pub fn build_auth(senha: &str) -> Vec<u8> {
    let mut data = vec![0x11u8];
    data.extend_from_slice(&senha_em_bytes(senha));
    data.push(0x34);
    build_e7(0x05, &data)
}

#[cfg(test)]
mod tests_auth {
    use super::*;
    #[test]
    fn senha_em_bytes_hex() {
        // parsing hexadecimal de 2 em 2 (senhas dummy)
        assert_eq!(senha_em_bytes("123456"), vec![0x12, 0x34, 0x56]);
        assert_eq!(senha_em_bytes("0a1b2c"), vec![0x0a, 0x1b, 0x2c]);
    }
    #[test]
    fn auth_frame_bem_formado() {
        let f = build_auth("123456"); // dummy
        assert_eq!(f[1], 0xE7, "wrapper");
        assert_eq!(f[2], 0x05, "TIPO");
        assert_eq!(f[3], 0x11, "marcador inicial");
        assert_eq!(f[f.len()-4], 0x34, "marcador final (antes de CRC+CHK)");
        // auto-consistencia: CHK = 0xFF ^ XOR, e LEN = total-2
        assert_eq!(*f.last().unwrap(), checksum(&f[..f.len()-1]));
        assert_eq!(f[0] as usize, f.len()-2);
        // CRC recomputado bate com o do proprio frame
        let crc_lo=f[f.len()-3]; let crc_hi=f[f.len()-2];
        let c=crc16_e7(&f[2..f.len()-3]);
        assert_eq!((c & 0xFF) as u8, crc_lo);
        assert_eq!((c >> 8) as u8, crc_hi);
    }
}
